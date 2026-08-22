"""Observed failure signatures, in the same six fields the manifest uses.

The gate used to read the manifest as a BOOLEAN: non-empty means red. That
cannot establish that the observed failures are the expected ones. It cannot
notice that a baseline failure stopped happening, and it cannot reject a NOVEL
security failure -- a brand-new leak lands in a run that was already red and
changes nothing the gate looks at.

So every security failure emits its six-field signature, the run writes them
out, and the gate compares MULTISETS: observed == expected, or the gate is red
and says which side each difference is on.

A HARNESS ERROR EMITS NO SIGNATURE. It is not a manifestable failure and must
never reconcile against one.
"""

from __future__ import annotations

import json
import os
import pathlib
from dataclasses import asdict, dataclass

FIELDS = (
    "case_id",
    "property",
    "collector",
    "surface_path",
    "representation",
    "occurrence_rule",
)


@dataclass(frozen=True)
class Signature:
    case_id: str
    property: str
    collector: str
    surface_path: str
    representation: str
    occurrence_rule: str

    def as_tuple(self) -> tuple:
        return tuple(getattr(self, f) for f in FIELDS)


#: Marker that ties a JUnit failure to the signature that caused it.
#:
#: Accounting a failure by NODE ID alone excused any failure a
#: signature-emitting test happened to produce -- including an unrelated one. A
#: mutation could make such a test fail for a different reason and still be
#: accepted. The failure message now carries its own signature, so the link is
#: established rather than assumed.
FAILURE_MARKER = "RELEASE-GATE-SIGNATURE"


class ExpectedSecurityFailure(AssertionError):
    """A security failure that carries the signature it emitted."""

    def __init__(self, signature: Signature, detail: str) -> None:
        self.signature = signature
        super().__init__(f"{FAILURE_MARKER}={encode(signature)} :: {detail}")


def encode(signature: Signature) -> str:
    """A canonical, single-line encoding for embedding in a failure message."""
    return "|".join(getattr(signature, f) for f in FIELDS)


def signatures_in(message: str) -> set[str]:
    """Every encoded signature a JUnit failure message carries."""
    found = set()
    for part in message.split(FAILURE_MARKER + "=")[1:]:
        found.add(part.split(" :: ")[0].strip())
    return found


class Recorder:
    """Collects signatures for one run."""

    def __init__(self) -> None:
        self._signatures: list[Signature] = []
        self._nodeids: set[str] = set()
        self._by_node: dict[str, set[str]] = {}

    def record_and_fail(self, signature: Signature, detail: str) -> None:
        """Record the signature and fail WITH it, so the two are tied."""
        self.record(signature)
        raise ExpectedSecurityFailure(signature, detail)

    def record(self, signature: Signature) -> None:
        self._signatures.append(signature)
        # The emitting test's node id, so a consumer can tell an ACCOUNTED
        # failure (one that produced a signature) from an unrelated assertion
        # failure. Without it every unrecognised failure looked like noise the
        # mutation runner could ignore.
        current = os.environ.get("PYTEST_CURRENT_TEST", "")
        if current:
            node = current.split(" ")[0]
            self._nodeids.add(node)
            self._by_node.setdefault(node, set()).add(encode(signature))

    @property
    def signatures(self) -> list[Signature]:
        return list(self._signatures)

    @property
    def nodeids(self) -> set[str]:
        """Tests that emitted at least one signature."""
        return set(self._nodeids)

    def dump(self, path: pathlib.Path) -> None:
        path.write_text(
            json.dumps(
                {
                    "signatures": [asdict(s) for s in self._signatures],
                    "nodeids": sorted(self._nodeids),
                    "by_node": {k: sorted(v) for k, v in sorted(self._by_node.items())},
                },
                indent=2,
                sort_keys=True,
            )
        )

    def clear(self) -> None:
        self._signatures.clear()
        self._nodeids.clear()
        self._by_node.clear()


#: One recorder per run, written out by tests/release/conftest.py.
RECORDER = Recorder()


def load(path: pathlib.Path) -> list[Signature]:
    if not path.exists():
        return []
    return [Signature(**row) for row in _rows(path)]


def _rows(path: pathlib.Path) -> list[dict]:
    """Tolerates the older bare-list format as well as the current object."""
    data = json.loads(path.read_text())
    return data["signatures"] if isinstance(data, dict) else data


def signatures_by_node(path: pathlib.Path) -> dict[str, set[str]]:
    """Which encoded signatures each test emitted."""
    if not path.exists():
        return {}
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        return {}
    return {k: set(v) for k, v in data.get("by_node", {}).items()}


def accounted_nodeids(path: pathlib.Path) -> set[str]:
    """Tests that emitted a signature, so their failure is ACCOUNTED FOR."""
    if not path.exists():
        return set()
    data = json.loads(path.read_text())
    return set(data.get("nodeids", [])) if isinstance(data, dict) else set()
