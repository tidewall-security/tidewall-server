"""Whole-store before/after delta, and declared-versus-produced equality.

This is the oracle for DECLARATION STALENESS, not for what was persisted.
It answers "does the set of objects this exercise actually produced match the
set it declared it would produce", in both directions:

  * produced but not declared -- a write nobody wrote down, which is the
    surface a value-scan is never pointed at;
  * declared but not produced -- a declaration that has outlived its code, so
    a later assertion about it is checking a table nobody writes any more.

Both directions fail. Only checking one of them was how a stale declaration
survived: the exercise stopped producing the row, the declaration stayed, and
every downstream count over it read zero and agreed with itself.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field

# A single cell, addressed the way an occurrence path addresses it.
Cell = tuple[str, int, str]  # (table, rowid, column)


def _live_tables(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute(
        "SELECT name FROM pragma_table_list " "WHERE schema = 'main' AND type = 'table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    return sorted(r[0] for r in rows)


def _columns(conn: sqlite3.Connection, table: str) -> list[str]:
    # xinfo, not table_info: table_info hides generated columns, and a value
    # written into one is still a value on disk.
    rows = conn.execute("SELECT name, hidden FROM pragma_table_xinfo(?)", (table,)).fetchall()
    return [name for name, hidden in rows if hidden in (0, 2, 3)]


@dataclass(frozen=True)
class Snapshot:
    """Every cell of every live table, addressed by (table, rowid, column)."""

    cells: dict[Cell, object]

    @classmethod
    def take(cls, conn: sqlite3.Connection) -> Snapshot:
        cells: dict[Cell, object] = {}
        for table in _live_tables(conn):
            columns = _columns(conn, table)
            if not columns:
                continue
            # rowid is the stable address. The invariant already refuses
            # WITHOUT ROWID tables, so every live table has one.
            selected = ", ".join(f'"{c}"' for c in columns)
            for row in conn.execute(f'SELECT rowid, {selected} FROM "{table}"'):
                rowid = row[0]
                for column, value in zip(columns, row[1:], strict=True):
                    cells[(table, rowid, column)] = value
        return cls(cells=cells)


@dataclass(frozen=True)
class Delta:
    """What changed between two snapshots, as concrete occurrence paths."""

    added: dict[Cell, object] = field(default_factory=dict)
    removed: dict[Cell, object] = field(default_factory=dict)
    changed: dict[Cell, tuple[object, object]] = field(default_factory=dict)

    @property
    def produced(self) -> set[Cell]:
        """Cells this exercise wrote: new cells and cells whose value moved."""
        return set(self.added) | set(self.changed)

    def __bool__(self) -> bool:
        return bool(self.added or self.removed or self.changed)


def delta(before: Snapshot, after: Snapshot) -> Delta:
    added = {c: v for c, v in after.cells.items() if c not in before.cells}
    removed = {c: v for c, v in before.cells.items() if c not in after.cells}
    changed = {c: (before.cells[c], v) for c, v in after.cells.items() if c in before.cells and before.cells[c] != v}
    return Delta(added=added, removed=removed, changed=changed)


@dataclass(frozen=True)
class Mismatch:
    """One direction of a declared-versus-produced disagreement."""

    direction: str  # "produced-not-declared" | "declared-not-produced"
    cell: Cell

    def __str__(self) -> str:
        table, rowid, column = self.cell
        return f"{self.direction}: {table}.{column} (rowid {rowid})"


def compare(produced: set[Cell], declared: set[Cell]) -> list[Mismatch]:
    """Set equality, reported per direction.

    Returns an empty list only when the two sets are equal. A caller that
    checks `not compare(...)` is checking both directions by construction --
    there is no argument order that silences one of them.
    """
    out = [Mismatch("produced-not-declared", c) for c in sorted(produced - declared)]
    out += [Mismatch("declared-not-produced", c) for c in sorted(declared - produced)]
    return out
