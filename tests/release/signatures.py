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

    def record(self, signature: Signature) -> None:
        self._signatures.append(signature)

    @property
    def signatures(self) -> list[Signature]:
        return list(self._signatures)

    def dump(self, path: pathlib.Path) -> None:
        path.write_text(json.dumps([asdict(s) for s in self._signatures], indent=2, sort_keys=True))

    def clear(self) -> None:
        self._signatures.clear()


#: One recorder per run, written out by tests/release/conftest.py.
RECORDER = Recorder()


def load(path: pathlib.Path) -> list[Signature]:
    if not path.exists():
        return []
    return [Signature(**row) for row in json.loads(path.read_text())]
