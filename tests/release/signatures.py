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


class Recorder:
    """Collects signatures for one run."""

    def __init__(self) -> None:
        self._signatures: list[Signature] = []
        self._nodeids: set[str] = set()

    def record(self, signature: Signature) -> None:
        self._signatures.append(signature)
        # The emitting test's node id, so a consumer can tell an ACCOUNTED
        # failure (one that produced a signature) from an unrelated assertion
        # failure. Without it every unrecognised failure looked like noise the
        # mutation runner could ignore.
        current = os.environ.get("PYTEST_CURRENT_TEST", "")
        if current:
            self._nodeids.add(current.split(" ")[0])

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
                },
                indent=2,
                sort_keys=True,
            )
        )

    def clear(self) -> None:
        self._signatures.clear()
        self._nodeids.clear()


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


def accounted_nodeids(path: pathlib.Path) -> set[str]:
    """Tests that emitted a signature, so their failure is ACCOUNTED FOR."""
    if not path.exists():
        return set()
    data = json.loads(path.read_text())
    return set(data.get("nodeids", [])) if isinstance(data, dict) else set()
