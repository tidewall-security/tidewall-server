"""From a byte occurrence to a concrete occurrence path.

BYTE SCANNING PROVES PHYSICAL PRESENCE, NOT OCCURRENCE PATH. A match at some
offset in a database file says the bytes are on disk; it does not say which
column put them there, and the matrix in `occurrences.py` resolves rules by
path, not by offset. The two are joined here, and the join is explicit about
where it is inferring rather than observing.

The join has three sources, in decreasing strength:

  1. the live cell delta -- an OBSERVED path, read back from the store;
  2. the copy map -- for an observed live cell, the set of physical locations
     (table B-tree plus each index) that necessarily also hold the value, so
     an expected count is derivable rather than a surprise;
  3. the cascade map -- a write a value's change CAUSES in a child row, which
     no statement names and no live cell of the parent records.

Anything a byte scan finds which none of the three explains is UNATTRIBUTED,
and that is a failure, not a residue. An occurrence nobody can name is
exactly the occurrence no rule was applied to.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from tests.release.schema import cascade_map, copy_map
from tests.release.store import Cell, Delta


@dataclass(frozen=True)
class Attribution:
    """One physical occurrence, joined to the path that explains it."""

    path: tuple[str, str]  # (table, column)
    location: str  # the B-tree holding it: table name or index name
    basis: str  # "observed" | "copy" | "cascade"
    rowid: int | None = None

    def __str__(self) -> str:
        table, column = self.path
        where = f" in {self.location}" if self.location != table else ""
        return f"{table}.{column}{where} ({self.basis})"


class Unattributed(Exception):
    """A byte occurrence no declared path explains."""


def expected_locations(conn: sqlite3.Connection, path: tuple[str, str]) -> dict[str, int]:
    """Every physical location holding `path`'s value, with its copy count.

    This is what makes an expected byte count an oracle. A unique column's
    value exists twice in a closed database -- once in the table B-tree and
    once in the index -- and a check expecting one occurrence fails on a
    correct system.
    """
    copies = copy_map(conn)
    if path not in copies:
        raise Unattributed(f"no copy map entry for {path[0]}.{path[1]}")
    return dict(copies[path])


def attribute(conn: sqlite3.Connection, delta: Delta) -> list[Attribution]:
    """Every occurrence the exercise's OBSERVED writes account for.

    Observed cells first, then their necessary physical copies, then the child
    writes their change causes.
    """
    copies = copy_map(conn)
    cascades = cascade_map(conn)
    out: list[Attribution] = []

    for cell in sorted(delta.produced):
        table, rowid, column = cell
        path = (table, column)
        out.append(Attribution(path=path, location=table, basis="observed", rowid=rowid))

        for location, count in sorted(copies.get(path, {}).items()):
            if location == table:
                continue  # already recorded as the observed table occurrence
            for _ in range(count):
                out.append(Attribution(path=path, location=location, basis="copy", rowid=rowid))

        for child_table, child_column, _event, _action in sorted(cascades.get(path, set())):
            out.append(Attribution(path=(child_table, child_column), location=child_table, basis="cascade"))

    return out


def unexplained(physical: dict[str, int], attributions: list[Attribution]) -> dict[str, int]:
    """Physical occurrences per location that no attribution accounts for.

    `physical` is a location -> count mapping from an actual byte scan of the
    live image. The result is what is left over: for each location, how many
    occurrences exceed what the attributions predict. A non-empty result means
    the value is somewhere no declared path put it.
    """
    predicted: dict[str, int] = {}
    for a in attributions:
        predicted[a.location] = predicted.get(a.location, 0) + 1

    leftover = {}
    for location, count in physical.items():
        excess = count - predicted.get(location, 0)
        if excess > 0:
            leftover[location] = excess
    return leftover


def cells_holding(conn: sqlite3.Connection, value: str) -> set[Cell]:
    """Read back the live cells that actually hold `value`.

    This is the OBSERVED source. It is a logical read, so it sees only the
    live image -- never a WAL frame, a freelist page or a freeblock. Those are
    the corpus's job; conflating the two is how a historical occurrence gets
    attributed to a live path that no longer holds it.
    """
    from tests.release.store import Snapshot

    found = set()
    for cell, stored in Snapshot.take(conn).cells.items():
        if stored is None:
            continue
        if isinstance(stored, bytes | bytearray | memoryview):
            if value.encode() in bytes(stored):
                found.add(cell)
        elif value in str(stored):
            found.add(cell)
    return found
