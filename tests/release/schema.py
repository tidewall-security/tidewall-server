"""What the live schema must look like for write attribution to be possible.

The release suite has to say where a value was written, not merely that its
bytes exist somewhere. Two different kinds of writer make that hard, and they
need different treatment:

**Additional-copy writers** put the *same* value in *more physical locations*.
Indexes are that class, and it is derivable: for each column, the table B-tree
plus every index covering it. `copy_map` computes it from the live schema, so
it is complete over indexes by construction rather than by enumeration.

**Different-target writers** put a value somewhere the statement never names.
A connection-level statement trace cannot attribute those, and their bodies
are arbitrary, so they are not derivable — they are *refused*. `invariant`
checks that none exists.

That list was not arrived at by reasoning. Each entry was found by building the
attribution argument, being shown a counterexample, and adding the class it
belonged to: triggers, then referential actions, then generated columns, then
indexes, then virtual tables. **Completeness is not claimed.** What is claimed
is that each part is asserted against the live schema and fails on drift, so a
sixth class arriving becomes a build failure rather than a silent hole.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

#: Every foreign key at head, as (table, column, parent, on_delete).
#:
#: All ten are pinned, not only the six that write. "Exactly the six" was
#: ambiguous about whether RESTRICT and NO ACTION were inside or outside the
#: set; they are inside the pin and outside the cascade map, because they
#: cannot copy a value anywhere.
REFERENTIAL_ACTIONS: frozenset[tuple[str, str, str, str]] = frozenset(
    {
        ("access_rules", "rule_set_id", "rule_sets", "CASCADE"),
        ("access_tokens", "device_id", "devices", "CASCADE"),
        ("interaction_contents", "interaction_id", "interactions", "CASCADE"),
        ("rule_sets", "policy_id", "policies", "CASCADE"),
        ("api_keys", "policy_id", "policies", "SET NULL"),
        ("devices", "reg_token_id", "registration_tokens", "SET NULL"),
        ("devices", "policy_id", "policies", "RESTRICT"),
        ("registration_tokens", "policy_id", "policies", "RESTRICT"),
        ("content_export_notes", "attempt_id", "content_export_attempts", "NO ACTION"),
        ("content_export_reconciliations", "attempt_id", "content_export_attempts", "NO ACTION"),
    }
)

#: The actions that actually write to a child when a parent row is deleted.
WRITING_ACTIONS = frozenset({"CASCADE", "SET NULL"})


@dataclass(frozen=True)
class InvariantViolation:
    kind: str
    detail: str


def _tables(conn: sqlite3.Connection) -> list[str]:
    return [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]


def referential_actions(conn: sqlite3.Connection) -> set[tuple[str, str, str, str]]:
    """Every foreign key, as (table, column, parent, on_delete)."""
    out: set[tuple[str, str, str, str]] = set()
    for table in _tables(conn):
        for fk in conn.execute(f"PRAGMA foreign_key_list('{table}')"):
            out.add((table, fk[3], fk[2], fk[6]))
    return out


def cascade_map(conn: sqlite3.Connection) -> dict[str, set[tuple[str, str, str]]]:
    """Parent table -> the (child, column, action) a DELETE on it writes.

    Only the writing actions. RESTRICT and NO ACTION refuse or do nothing, so
    they cannot carry a value into another table and have nothing to attribute.
    """
    out: dict[str, set[tuple[str, str, str]]] = {}
    for table, column, parent, action in referential_actions(conn):
        if action in WRITING_ACTIONS:
            out.setdefault(parent, set()).add((table, column, action))
    return out


def copy_map(conn: sqlite3.Connection) -> dict[tuple[str, str], set[str]]:
    """(table, column) -> every physical location holding that value.

    The table B-tree, plus every index whose columns include it. This is what
    makes an expected byte-occurrence count an oracle instead of a surprise:
    `policies.name` is unique, so its value exists twice in a closed database.
    """
    out: dict[tuple[str, str], set[str]] = {}
    for table in _tables(conn):
        columns = [r[1] for r in conn.execute(f"PRAGMA table_info('{table}')")]
        for column in columns:
            out[(table, column)] = {table}
        for index in conn.execute(f"PRAGMA index_list('{table}')"):
            name = index[1]
            for entry in conn.execute(f"PRAGMA index_xinfo('{name}')"):
                column = entry[2]
                if column and (table, column) in out:
                    out[(table, column)].add(name)
    return out


def invariant(conn: sqlite3.Connection) -> list[InvariantViolation]:
    """Every different-target writer this design refuses. Empty is passing."""
    violations: list[InvariantViolation] = []

    for kind in ("trigger", "view"):
        for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type=?", (kind,)):
            violations.append(InvariantViolation(kind, name))

    observed = referential_actions(conn)
    for extra in sorted(observed - REFERENTIAL_ACTIONS):
        violations.append(InvariantViolation("referential-action-added", str(extra)))
    for missing in sorted(REFERENTIAL_ACTIONS - observed):
        violations.append(InvariantViolation("referential-action-removed", str(missing)))

    for table in _tables(conn):
        # table_xinfo, not table_info: only the former can see generated columns
        # at all, and `hidden` is 2 for VIRTUAL and 3 for STORED.
        for column in conn.execute(f"PRAGMA table_xinfo('{table}')"):
            if column[6] in (2, 3):
                violations.append(InvariantViolation("generated-column", f"{table}.{column[1]}"))

    for row in conn.execute("PRAGMA table_list"):
        if row[2] in ("virtual", "shadow"):
            violations.append(InvariantViolation(row[2], row[1]))

    for name, sql in conn.execute("SELECT name, sql FROM sqlite_master WHERE type='index' AND sql IS NOT NULL"):
        # A partial index has a WHERE clause; an expression index reports its
        # slot as cid=-2 with a NULL name, so `copy_map` cannot link it back to
        # a source column. Both are refused rather than mis-attributed.
        if " where " in (sql or "").lower():
            violations.append(InvariantViolation("partial-index", name))
        # index_xinfo columns: (seqno, cid, name, desc, coll, key). Only KEY
        # columns describe the index's own content -- every index also carries
        # an implicit rowid entry with cid=-1 and a NULL name, so checking for
        # a NULL name flags all 41 of them. An expression is cid=-2 on a key
        # column.
        if any(e[5] == 1 and e[1] == -2 for e in conn.execute(f"PRAGMA index_xinfo('{name}')")):
            violations.append(InvariantViolation("expression-index", name))

    for table in _tables(conn):
        sql = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
        if sql and sql[0] and "without rowid" in sql[0].lower():
            # Stored AS the index B-tree, so the table/index distinction
            # `copy_map` relies on does not hold.
            violations.append(InvariantViolation("without-rowid", table))

    return violations
