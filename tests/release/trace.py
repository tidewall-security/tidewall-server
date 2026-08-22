"""Statement tracing, and the forbidden-column read that does not trust it.

A statement trace IS NOT A VALUE LEDGER, and cannot be made into one here:

  * `set_trace_callback` expands bound parameters, so a value passed as a
    parameter does appear -- which is what makes the trace look sufficient;
  * a value the SQL computes (`INSERT ... SELECT upper(v)`, `UPDATE ... SET
    v = other.v`, a trigger, a default) reaches disk without ever appearing
    in any statement text;
  * CPython's sqlite3 exposes no `set_update_hook` and no
    `set_preupdate_hook` -- `ENABLE_PREUPDATE_HOOK` is 0 -- so there is no
    row-level callback to close the gap with.

So the trace is kept for attribution (which statement was running), and the
actual assertion is a READ of the forbidden columns at every statement
boundary. The read sees the row whatever computed it.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field


class UnreadableForbiddenColumn(Exception):
    """A declared forbidden column could not be read.

    This is an error, not a skip. A check that cannot run has not passed.
    """


def _holds(value: object, watched: str) -> bool:
    """Whether a stored value contains the watched text, WHATEVER ITS TYPE.

    A secret stored as a BLOB is a secret on disk. Comparing only `str` values
    meant `INSERT INTO audit(v) VALUES (CAST(? AS BLOB))` passed the check.
    """
    if isinstance(value, str):
        return watched in value
    if isinstance(value, bytes | bytearray | memoryview):
        return watched.encode() in bytes(value)
    return watched in str(value)


@dataclass
class Statement:
    """One traced statement, with the value-visibility caveat attached."""

    sql: str
    index: int

    def mentions(self, value: str) -> bool:
        """Whether the value appears in the statement TEXT.

        False does not mean the statement did not write the value. See the
        module docstring; this is exactly the case the boundary read exists
        for.
        """
        return value in self.sql


@dataclass
class ForbiddenRead:
    """A forbidden column found holding a watched value."""

    table: str
    column: str
    rowid: int
    after_statement: str

    def __str__(self) -> str:
        return f"{self.table}.{self.column} (rowid {self.rowid}) after: {self.after_statement}"


@dataclass
class TracedConnection:
    """A connection whose statements are recorded and whose forbidden columns
    are read after every statement.

    `forbidden` is a set of (table, column). The watched values are byte or
    text values that must never come to rest in one of them.
    """

    conn: sqlite3.Connection
    forbidden: frozenset[tuple[str, str]]
    watched: tuple[str, ...]
    statements: list[Statement] = field(default_factory=list)
    violations: list[ForbiddenRead] = field(default_factory=list)
    _read: set[tuple[str, str]] = field(default_factory=set)

    def __post_init__(self) -> None:
        self.conn.set_trace_callback(self._record)

    def _record(self, sql: str) -> None:
        self.statements.append(Statement(sql=sql, index=len(self.statements)))

    def execute(self, sql: str, parameters: tuple = ()) -> sqlite3.Cursor:
        cur = self.conn.execute(sql, parameters)
        self._sweep(sql)
        return cur

    def executemany(self, sql: str, seq) -> sqlite3.Cursor:
        cur = self.conn.executemany(sql, seq)
        self._sweep(sql)
        return cur

    def commit(self) -> None:
        self.conn.commit()
        self._sweep("COMMIT")

    def _sweep(self, after: str) -> None:
        """Read every forbidden column. This is the statement boundary."""
        for table, column in sorted(self.forbidden):
            if not self._table_exists(table):
                # A boundary before the schema is created has nothing to read.
                # Tolerated here, refused by `verify_every_pair_was_read`.
                continue
            if column not in self._columns_of(table):
                # Fail closed on a BROKEN DECLARATION.
                #
                # This cannot be caught by letting the SELECT fail. SQLite
                # falls back to treating a double-quoted unknown identifier as
                # a STRING LITERAL, so `SELECT "vv" FROM audit` does not error
                # -- it returns the constant 'vv' for every row, and the sweep
                # reads that happily and finds nothing, forever. A misspelled
                # forbidden column was therefore a check that silently never
                # ran and passed for the entire run.
                raise UnreadableForbiddenColumn(
                    f"forbidden column {table}.{column} does not exist " f"(columns: {sorted(self._columns_of(table))})"
                )
            rows = self.conn.execute(f'SELECT rowid, "{column}" FROM "{table}"').fetchall()
            self._read.add((table, column))
            for rowid, value in rows:
                if value is None:
                    continue
                for watched in self.watched:
                    if _holds(value, watched):
                        self.violations.append(
                            ForbiddenRead(
                                table=table,
                                column=column,
                                rowid=rowid,
                                after_statement=after,
                            )
                        )

    def _columns_of(self, table: str) -> set[str]:
        return {r[0] for r in self.conn.execute("SELECT name FROM pragma_table_xinfo(?)", (table,))}

    def _table_exists(self, table: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM pragma_table_list WHERE schema = 'main' AND name = ?",
            (table,),
        ).fetchone()
        return row is not None

    def verify_every_pair_was_read(self) -> None:
        """Refuse a declared pair that was never successfully read.

        A forbidden column naming a table that is never created is not a pass;
        it is a declaration with nothing behind it.
        """
        never = sorted(set(self.forbidden) - self._read)
        if never:
            raise UnreadableForbiddenColumn(
                "declared forbidden columns were never read: " + ", ".join(f"{t}.{c}" for t, c in never)
            )

    def trace_mentions(self, value: str) -> list[Statement]:
        """Statements whose TEXT contains the value. Attribution, not proof."""
        return [s for s in self.statements if s.mentions(value)]
