"""What the live schema must look like for write attribution to be possible.

The release suite has to say where a value was written, not merely that its
bytes exist somewhere. Two different kinds of writer make that hard, and they
need different treatment:

**Additional-copy writers** put the *same* value in *more physical locations*.
Indexes are that class, and it is derivable: for each column, the table B-tree
plus every index covering it. `copy_map` inventories the live index slots
and resolves the receipt index predicate against the row being attributed.

**Different-target writers** put a value somewhere the statement never names.
A connection-level statement trace cannot attribute those, and their bodies
are arbitrary, so they are not derivable — they are *refused*. `invariant`
checks that none exists.

That list was not arrived at by reasoning. Each entry was found by building the
attribution argument, being shown a counterexample, and adding the class it
belonged to: triggers, then referential actions, then generated columns, then
indexes, then virtual tables. **Completeness is not claimed.** What is claimed is
that each part is asserted against the live schema and fails on drift -- and,
for the one dimension where an unknown value is detectable, that anything
outside the known-safe set is refused unexamined rather than ignored.
"""

from __future__ import annotations

import collections
import sqlite3
from dataclasses import dataclass
from itertools import groupby

# Keep child and parent columns paired and ordered within each constraint.
# Splitting a composite FK changes which rows may refer to one another even
# though the same column-to-column edges still appear in foreign_key_list.
ForeignKey = tuple[str, tuple[str, ...], str, tuple[str, ...], str, str]

REFERENTIAL_ACTIONS: frozenset[ForeignKey] = frozenset(
    {
        ("access_rules", ("rule_set_id",), "rule_sets", ("id",), "NO ACTION", "CASCADE"),
        # A device's refresh credential dies with the device. Leaving it would
        # keep a credential addressed to a device that no longer exists.
        ("device_refresh_tokens", ("device_id",), "devices", ("id",), "NO ACTION", "CASCADE"),
        # A vault dies with the policy that owns it. The vault holds the
        # placeholder-to-original mapping, and once its policy is gone no
        # credential can resolve that policy -- so the row would be unreachable
        # plaintext. CASCADE rather than RESTRICT so retention never becomes a
        # reason a policy cannot be deleted.
        ("vaults", ("policy_id",), "policies", ("id",), "NO ACTION", "CASCADE"),
        ("access_tokens", ("device_id",), "devices", ("id",), "NO ACTION", "CASCADE"),
        ("interaction_contents", ("interaction_id",), "interactions", ("id",), "NO ACTION", "CASCADE"),
        ("rule_sets", ("policy_id",), "policies", ("id",), "NO ACTION", "CASCADE"),
        # RESTRICT, matching devices and registration_tokens. It was SET NULL,
        # which made api_keys the only one of the three bound to a policy whose
        # guarantee was a service check rather than a constraint -- and an
        # unbound admin reads and deletes globally, so silently unbinding one
        # promotes a policy-scoped administrator to an organisation-wide one.
        ("api_keys", ("policy_id",), "policies", ("id",), "NO ACTION", "RESTRICT"),
        ("devices", ("reg_token_id",), "registration_tokens", ("id",), "NO ACTION", "SET NULL"),
        ("devices", ("policy_id",), "policies", ("id",), "NO ACTION", "RESTRICT"),
        ("registration_tokens", ("policy_id",), "policies", ("id",), "NO ACTION", "RESTRICT"),
        ("content_export_notes", ("attempt_id",), "content_export_attempts", ("attempt_id",), "NO ACTION", "NO ACTION"),
        (
            "content_export_reconciliations",
            ("attempt_id",),
            "content_export_attempts",
            ("attempt_id",),
            "NO ACTION",
            "NO ACTION",
        ),
        ("agent_sessions", ("device_id",), "devices", ("id",), "NO ACTION", "CASCADE"),
        ("agent_sessions", ("policy_id",), "policies", ("id",), "NO ACTION", "RESTRICT"),
        ("collector_progress", ("device_id",), "devices", ("id",), "NO ACTION", "CASCADE"),
        ("collector_progress", ("policy_id",), "policies", ("id",), "NO ACTION", "RESTRICT"),
        ("agent_observations", ("device_id",), "devices", ("id",), "NO ACTION", "CASCADE"),
        ("agent_observations", ("policy_id",), "policies", ("id",), "NO ACTION", "RESTRICT"),
        (
            "agent_observations",
            ("session_id", "device_id", "policy_id", "agent"),
            "agent_sessions",
            ("session_id", "device_id", "policy_id", "agent"),
            "NO ACTION",
            "NO ACTION",
        ),
        ("collector_outcomes", ("device_id",), "devices", ("id",), "NO ACTION", "CASCADE"),
        (
            "collector_outcomes",
            ("event_id", "device_id"),
            "agent_observations",
            ("event_id", "device_id"),
            "NO ACTION",
            "CASCADE",
        ),
    }
)

#: The actions that write to a child. ON UPDATE matters as much as ON DELETE:
#: an `ON UPDATE CASCADE` copies the parent's new value into the child, which
#: is a different-target write the statement never names. v1 read only
#: `on_delete` (fk[6]) and would have missed every one of them. All are
#: `NO ACTION` on update today, which is exactly why the omission was invisible.
WRITING_ACTIONS = frozenset({"CASCADE", "SET NULL"})


@dataclass(frozen=True)
class InvariantViolation:
    kind: str
    detail: str


def _tables(conn: sqlite3.Connection) -> list[str]:
    return [r[0] for r in conn.execute("SELECT name FROM main.sqlite_schema WHERE type='table'")]


def referential_actions(conn: sqlite3.Connection) -> collections.Counter[ForeignKey]:
    """Pin each complete foreign key, including multiplicity and column order."""
    out: collections.Counter[ForeignKey] = collections.Counter()
    for table in _tables(conn):
        # foreign_key_list is (id, seq, parent, from, to, on_update, on_delete, match).
        edges = sorted(conn.execute(f"PRAGMA main.foreign_key_list('{table}')"), key=lambda fk: (fk[0], fk[1]))
        for _, group in groupby(edges, key=lambda fk: fk[0]):
            rows = list(group)
            first = rows[0]
            columns = tuple(row[3] for row in rows)
            parent_columns = tuple(row[4] for row in rows)
            out[(table, columns, first[2], parent_columns, first[5], first[6])] += 1
    return out


def cascade_map(conn: sqlite3.Connection) -> dict[tuple[str, str], set[tuple[str, str, str]]]:
    """(parent table, parent column) -> the (child, column, event, action) writes it causes.

    Both events. RESTRICT and NO ACTION refuse or defer and never modify a
    child value, so they carry nothing and have nothing to attribute -- but
    that is an argument about those two ACTIONS, not about the DELETE event,
    and reading only `on_delete` would silently drop every ON UPDATE CASCADE.
    """
    out: dict[tuple[str, str], set[tuple[str, str, str]]] = {}
    for table, columns, parent, parent_columns, on_update, on_delete in referential_actions(conn):
        for event, action in (("UPDATE", on_update), ("DELETE", on_delete)):
            if action in WRITING_ACTIONS:
                # Keyed by (parent table, parent COLUMN): which value changing
                # causes the write is the fact attribution needs.
                for column, parent_column in zip(columns, parent_columns, strict=True):
                    out.setdefault((parent, parent_column), set()).add((table, column, event, action))
    return out


RECEIPT_INDEX = "uq_collector_successful_ordinal"
_RECEIPT_INDEX_SQL = (
    f"CREATE UNIQUE INDEX {RECEIPT_INDEX} ON collector_outcomes (device_id, ordinal) WHERE event_id IS NOT NULL"
)


class Unattributed(Exception):
    """A byte occurrence no declared path explains."""


def _partial_index_violations(conn: sqlite3.Connection) -> list[InvariantViolation]:
    violations = []
    tables = _tables(conn)
    if "collector_outcomes" in tables:
        ddl = conn.execute(
            "SELECT sql FROM main.sqlite_schema WHERE type='index' AND name=?", (RECEIPT_INDEX,)
        ).fetchone()
        if ddl is None or ddl[0] != _RECEIPT_INDEX_SQL:
            violations.append(InvariantViolation("receipt-index", RECEIPT_INDEX))

    for table in tables:
        for index in conn.execute(f"PRAGMA main.index_list('{table}')"):
            if index[4] and (table, index[1]) != ("collector_outcomes", RECEIPT_INDEX):
                violations.append(InvariantViolation("partial-index", index[1]))
    return violations


@dataclass
class CopyMap:
    conn: sqlite3.Connection
    slots: dict[tuple[str, str], collections.Counter[str]]

    def locations(self, path: tuple[str, str], *, rowid: int | None = None) -> collections.Counter[str]:
        """Resolve all physical copies of a cell, including the conditional receipt index."""
        if path not in self.slots:
            raise Unattributed(f"no copy map entry for {path[0]}.{path[1]}")
        slots = self.slots[path]
        if path[0] != "collector_outcomes" or RECEIPT_INDEX not in slots:
            return slots
        if rowid is None:
            raise Unattributed(f"{path[0]}.{path[1]} requires a rowid to resolve its partial index")
        row = self.conn.execute(
            "SELECT event_id IS NOT NULL FROM main.collector_outcomes WHERE rowid = ?", (rowid,)
        ).fetchone()
        if row is None:
            raise Unattributed(f"no live collector_outcomes row for rowid {rowid}")
        if row[0]:
            return slots
        locations = slots.copy()
        del locations[RECEIPT_INDEX]
        return locations


def copy_map(conn: sqlite3.Connection) -> CopyMap:
    """Inventory all index slots; resolve conditional membership for each live cell."""
    violations = _partial_index_violations(conn)
    if violations:
        raise Unattributed(f"cannot attribute copies on a schema with unsupported indexes: {violations}")
    out: dict[tuple[str, str], collections.Counter[str]] = {}
    for table in _tables(conn):
        info = list(conn.execute(f"PRAGMA main.table_info('{table}')"))
        for column in (r[1] for r in info):
            out[(table, column)] = collections.Counter({table: 1})

        # An INTEGER PRIMARY KEY IS the rowid, and every index on a rowid table
        # carries the rowid as its `cid=-1, name=NULL` auxiliary entry. So that
        # column's value physically exists in every index on the table, and a
        # map built only from NAMED key columns reports one location for a
        # value that has five. Measured on `interactions.id`: five secondary
        # indexes, all invisible to the named-column pass.
        # A rowid alias is a SINGLE-column INTEGER PRIMARY KEY. `table_info.pk`
        # is the ordinal within the key, so in `PRIMARY KEY(a, b)` the column
        # `a` also reports pk == 1 and is NOT an alias -- treating it as one
        # put its value in indexes that never carry it and double-counted the
        # composite autoindex, on a schema the invariant permits.
        key_columns = [r for r in info if r[5] > 0]
        # A genuine rowid alias is identified STRUCTURALLY: SQLite creates no
        # pk-origin autoindex for one, because the rowid B-tree already is the
        # key. Every non-alias primary key has one -- DESC, composite, TEXT.
        #
        # The previous rule matched DDL tokens, and a legal SQL comment between
        # `INTEGER` and `PRIMARY KEY DESC` evaded it, so a non-alias column was
        # counted into indexes that never carry it. Asking SQLite what it built
        # needs no lexical guessing at all.
        has_pk_autoindex = any(index[3] == "pk" for index in conn.execute(f"PRAGMA main.index_list('{table}')"))
        rowid_alias = (
            key_columns[0][1]
            if len(key_columns) == 1 and (key_columns[0][2] or "").upper() == "INTEGER" and not has_pk_autoindex
            else None
        )
        if rowid_alias is not None:
            for index in conn.execute(f"PRAGMA main.index_list('{table}')"):
                out[(table, rowid_alias)][index[1]] += 1

        for index in conn.execute(f"PRAGMA main.index_list('{table}')"):
            name = index[1]
            for entry in conn.execute(f"PRAGMA main.index_xinfo('{name}')"):
                column = entry[2]
                # Counter, not a set: `CREATE INDEX i ON t(c, c)` gives c two
                # key slots in one index, so the value exists twice there. A
                # set of B-tree names collapses that to one and cannot be an
                # occurrence-count oracle.
                # `column is not None`, not truthiness: SQLite permits a
                # quoted empty-string column name and an ordinary index on it,
                # and `""` is falsy -- so the index copy was dropped and the
                # canonical count expected one physical copy where the
                # permitted schema has two.
                if entry[5] == 1 and column is not None and (table, column) in out:
                    out[(table, column)][name] += 1
    return CopyMap(conn, out)


def invariant(conn: sqlite3.Connection) -> list[InvariantViolation]:
    """Every different-target writer this design refuses. Empty is passing."""
    violations: list[InvariantViolation] = []

    # Both schemas. A TEMP trigger is connection-local and invisible to
    # sqlite_master, but it can be attached to a main-schema table and write
    # another main-schema table -- a different-target writer while the
    # invariant reported nothing.
    for source, prefix in (("main.sqlite_schema", ""), ("temp.sqlite_schema", "temp-")):
        for kind in ("trigger", "view"):
            for (name,) in conn.execute(f"SELECT name FROM {source} WHERE type=?", (kind,)):
                violations.append(InvariantViolation(f"{prefix}{kind}", name))

    observed = referential_actions(conn)
    expected = collections.Counter(REFERENTIAL_ACTIONS)
    for entry, count in sorted(observed.items()):
        if count != expected.get(entry, 0):
            violations.append(InvariantViolation("referential-action-added", f"{entry} x{count}"))
    for entry in sorted(expected):
        if entry not in observed:
            violations.append(InvariantViolation("referential-action-removed", str(entry)))

    for table in _tables(conn):
        # table_xinfo, not table_info: only the former can see generated columns
        # at all, and `hidden` is 2 for VIRTUAL and 3 for STORED.
        for column in conn.execute(f"PRAGMA main.table_xinfo('{table}')"):
            if column[6] in (2, 3):
                violations.append(InvariantViolation("generated-column", f"{table}.{column[1]}"))

    # ALLOWLISTED, not blocklisted. Refusing only the `virtual` and `shadow`
    # values known today meant a SQLite version introducing a sixth object type
    # would pass silently -- while the module's own docstring claimed a new
    # class becomes a build failure. That claim is now implemented rather than
    # asserted: anything outside the known-safe set is refused unexamined.
    known_safe = {"table", "view"}
    for row in conn.execute("PRAGMA table_list"):
        if row[2] in ("virtual", "shadow"):
            violations.append(InvariantViolation(row[2], row[1]))
        elif row[2] not in known_safe:
            violations.append(InvariantViolation("unknown-object-type", f"{row[2]}:{row[1]}"))

    # The structural partial flag catches every conditional index. Only the
    # exact DDL whose predicate CopyMap.locations resolves is supported.
    violations.extend(_partial_index_violations(conn))

    for name, _sql in conn.execute("SELECT name, sql FROM main.sqlite_schema WHERE type='index' AND sql IS NOT NULL"):
        # index_xinfo columns: (seqno, cid, name, desc, coll, key). Only KEY
        # columns describe the index's own content -- every index also carries
        # an implicit rowid entry with cid=-1 and a NULL name, so checking for
        # a NULL name flags all 41 of them. An expression is cid=-2 on a key
        # column.
        if any(e[5] == 1 and e[1] == -2 for e in conn.execute(f"PRAGMA main.index_xinfo('{name}')")):
            violations.append(InvariantViolation("expression-index", name))

    # table_list columns: (schema, name, type, ncol, wr, strict). `wr` is the
    # structural WITHOUT ROWID flag. Substring matching was both too permissive
    # -- `WITHOUT\nROWID` is legal and evaded it -- and too strict, flagging an
    # ordinary table with a column named "without rowid". Such a table is
    # stored AS its index B-tree, so the table/index distinction `copy_map`
    # relies on does not hold.
    for row in conn.execute("PRAGMA table_list"):
        if row[4] and row[2] == "table":
            violations.append(InvariantViolation("without-rowid", row[1]))

    return violations
