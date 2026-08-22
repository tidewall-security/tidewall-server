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
            try:
                rows = self.conn.execute(f'SELECT rowid, "{column}" FROM "{table}"').fetchall()
            except sqlite3.OperationalError:
                # The table does not exist yet. A boundary before the schema
                # is created has nothing to read, which is not a pass for any
                # later boundary -- each one reads independently.
                continue
            for rowid, value in rows:
                if value is None:
                    continue
                text = value if isinstance(value, str) else str(value)
                for watched in self.watched:
                    if watched in text:
                        self.violations.append(
                            ForbiddenRead(
                                table=table,
                                column=column,
                                rowid=rowid,
                                after_statement=after,
                            )
                        )

    def trace_mentions(self, value: str) -> list[Statement]:
        """Statements whose TEXT contains the value. Attribution, not proof."""
        return [s for s in self.statements if s.mentions(value)]
