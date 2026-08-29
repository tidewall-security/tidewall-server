"""Declared object sets for every non-database boundary.

The store delta gives produced-versus-declared equality for rows and columns.
Every other boundary needs the same treatment, and successive drafts kept
losing one: v2 covered only rows and columns; v3 added HTTP, transport, logs
and artifacts and omitted the browser entirely; v4 listed four of the browser
surfaces and dropped page state, which the design names separately.

So the boundaries are enumerated ONCE, here, and `REQUIRED_BOUNDARIES` is
asserted against the registry. A boundary that is never declared is not
absent from the system -- it is absent from the check, which is worse.

Each boundary independently declares its object set and is compared for SET
EQUALITY, both directions, exactly as the store delta is.
"""

from __future__ import annotations

from dataclasses import dataclass, field

#: Every boundary that must have a declared object set. Naming one here and
#: never registering it fails; registering one not named here fails too.
REQUIRED_BOUNDARIES: frozenset[str] = frozenset(
    {
        "http",  # exchange identities and counts
        "transport",  # outbound call identities and counts
        "logs",  # log-record identities and counts
        "artifacts",  # artifact paths and byte counts
        "dom",  # DOM nodes
        "page-state",  # page/browser state -- named separately by the design
        "storage",  # storage entries
        "console",  # console events
        "browser-network",  # browser-initiated network requests
    }
)


class BoundaryError(Exception):
    """A boundary's declared set does not match what it produced."""


class MissingBoundary(Exception):
    """A required boundary was never registered, or an unknown one was."""


@dataclass(frozen=True)
class Mismatch:
    boundary: str
    direction: str  # "produced-not-declared" | "declared-not-produced"
    identity: str

    def __str__(self) -> str:
        return f"{self.boundary}: {self.direction}: {self.identity}"


@dataclass
class Boundary:
    """One boundary's declared and produced object sets, plus its own counter.

    Identities and COUNTS are both carried. Two HTTP exchanges with the same
    identity are two exchanges; a set alone reports one and cannot support
    Step 7's per-boundary counters.
    """

    name: str
    declared: dict[str, int] = field(default_factory=dict)
    produced: dict[str, int] = field(default_factory=dict)

    def declare(self, identity: str, count: int = 1) -> None:
        self.declared[identity] = self.declared.get(identity, 0) + count

    def record(self, identity: str, count: int = 1) -> None:
        self.produced[identity] = self.produced.get(identity, 0) + count

    def mismatches(self) -> list[Mismatch]:
        out = []
        for identity in sorted(set(self.produced) - set(self.declared)):
            out.append(Mismatch(self.name, "produced-not-declared", identity))
        for identity in sorted(set(self.declared) - set(self.produced)):
            out.append(Mismatch(self.name, "declared-not-produced", identity))
        for identity in sorted(set(self.declared) & set(self.produced)):
            if self.declared[identity] != self.produced[identity]:
                out.append(
                    Mismatch(
                        self.name,
                        "count-mismatch",
                        f"{identity} declared {self.declared[identity]}, " f"produced {self.produced[identity]}",
                    )
                )
        return out


@dataclass
class BoundarySet:
    """The registry. Refuses to be checked while a required boundary is absent."""

    boundaries: dict[str, Boundary] = field(default_factory=dict)

    def register(self, name: str) -> Boundary:
        if name not in REQUIRED_BOUNDARIES:
            raise MissingBoundary(
                f"{name!r} is not a declared boundary; add it to "
                f"REQUIRED_BOUNDARIES with a reason or correct the name"
            )
        boundary = self.boundaries.setdefault(name, Boundary(name))
        return boundary

    def verify_complete(self) -> None:
        absent = sorted(REQUIRED_BOUNDARIES - set(self.boundaries))
        if absent:
            raise MissingBoundary("boundaries required but never registered: " + ", ".join(absent))

    def check(self) -> None:
        """Every required boundary present, and every one of them in agreement."""
        self.verify_complete()
        problems: list[Mismatch] = []
        for name in sorted(self.boundaries):
            problems.extend(self.boundaries[name].mismatches())
        if problems:
            raise BoundaryError("; ".join(str(p) for p in problems))


def http_exchange_identity(method: str, path: str, status: int, headers: dict[str, str], body: bytes) -> str:
    """AN HTTP EXCHANGE IS STATUS + EVERY HEADER + BODY BYTES.

    A body-derived identity omits `Content-Disposition`, which is where
    `policy.name` currently appears -- and such an inventory passes its own
    controls while never looking at the header the value is in.
    """
    header_part = ";".join(f"{k.lower()}={v}" for k, v in sorted(headers.items()))
    return f"{method.upper()} {path} -> {status} [{header_part}] ({len(body)}B)"
