"""Total traversal, per-path plants, and the controls that make them mean something.

TRAVERSAL emits a CONCRETE PATH for every leaf of every captured object. Not a
serialisation of the object -- a path, because the occurrence matrix resolves
rules by path, and a sweep that only knows "the value is somewhere in this
exchange" has nothing to resolve against.

A PLANT alone proves nothing. Planting a canary and finding it is satisfied by
a sweep that searches the whole serialised blob and never traverses at all. So
every plant is paired with two controls:

  * PATH REMOVAL -- remove the value from that path and the finding must
    disappear. This is what distinguishes "the traversal reached this path"
    from "the bytes were somewhere in the object".
  * COLLECTOR AND REPRESENTATION -- design §7. Disable one collector and only
    its findings disappear; plant in one representation family and it is still
    found. A single plain-text plant does not prove the \\uXXXX decoder runs.

Every control goes through THE IDENTICAL TOP-LEVEL SWEEP, the same collector
registry and the same security-failure conversion. A control with its own
harness measures the harness.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from tests.release.representations import FAMILIES, Representation


@dataclass(frozen=True)
class Leaf:
    """One traversed location, addressed the way a rule addresses it."""

    path: str
    value: object

    def __str__(self) -> str:
        return self.path


def traverse(obj: object, prefix: str = "") -> Iterator[Leaf]:
    """Every leaf of a nested structure, with its concrete path.

    Total: dicts, lists, and scalars. A container that yields only its own
    repr hides the paths inside it, and a rule can only be applied to a path
    that was emitted.
    """
    if isinstance(obj, dict):
        for key in sorted(obj, key=str):
            child = f"{prefix}.{key}" if prefix else str(key)
            yield from traverse(obj[key], child)
    elif isinstance(obj, list | tuple):
        for i, item in enumerate(obj):
            yield from traverse(item, f"{prefix}[{i}]")
    else:
        yield Leaf(path=prefix, value=obj)


def set_at(obj: object, path: str, value: object) -> None:
    """Write `value` at a traversed path. Used to plant and to remove."""
    parent, key = _resolve_parent(obj, path)
    if isinstance(parent, dict):
        parent[key] = value
    else:
        parent[int(key)] = value


def delete_at(obj: object, path: str) -> None:
    """Remove a traversed path entirely. This is the path-removal control."""
    parent, key = _resolve_parent(obj, path)
    if isinstance(parent, dict):
        del parent[key]
    else:
        del parent[int(key)]


def _resolve_parent(obj: object, path: str) -> tuple[object, str]:
    parts = _split(path)
    cursor = obj
    for part in parts[:-1]:
        cursor = cursor[int(part)] if isinstance(cursor, list) else cursor[part]
    return cursor, parts[-1]


def _split(path: str) -> list[str]:
    out: list[str] = []
    buf = ""
    for ch in path:
        if ch == ".":
            if buf:
                out.append(buf)
            buf = ""
        elif ch == "[":
            if buf:
                out.append(buf)
            buf = ""
        elif ch == "]":
            out.append(buf)
            buf = ""
        else:
            buf += ch
    if buf:
        out.append(buf)
    return out


@dataclass(frozen=True)
class Finding:
    """One occurrence, attributed to the collector and path that found it."""

    collector: str
    path: str
    family: str

    def __str__(self) -> str:
        return f"{self.collector}:{self.path} ({self.family})"


class SecurityFailure(Exception):
    """A finding converted into a build failure. The single conversion point."""


#: The collector registry. Every sweep -- real or control -- iterates THIS.
Collector = Callable[[object], Iterator[Leaf]]
_REGISTRY: dict[str, Collector] = {}


def collector(name: str) -> Callable[[Collector], Collector]:
    def register(fn: Collector) -> Collector:
        _REGISTRY[name] = fn
        return fn

    return register


@collector("structure")
def _structure(obj: object) -> Iterator[Leaf]:
    """Leaves as traversed."""
    yield from traverse(obj)


@collector("serialised")
def _serialised(obj: object) -> Iterator[Leaf]:
    """The object as it goes on the wire.

    Distinct from `structure`: a value that survives JSON encoding in an
    escaped form is present here and absent there.
    """
    yield Leaf(path="<serialised>", value=json.dumps(obj, ensure_ascii=True))


@dataclass
class Sweep:
    """The one top-level sweep. Controls disable collectors; they do not fork.

    `disabled` names collectors to skip. The traversal, the matching and the
    conversion are otherwise byte-identical to a real run, because a control
    that takes a different route measures a different thing.
    """

    disabled: frozenset[str] = field(default_factory=frozenset)
    families: tuple[Representation, ...] = FAMILIES

    def findings(self, obj: object, secret: str) -> list[Finding]:
        out: list[Finding] = []
        for name in sorted(_REGISTRY):
            if name in self.disabled:
                continue
            for leaf in _REGISTRY[name](obj):
                raw = leaf.value if isinstance(leaf.value, bytes) else str(leaf.value).encode()
                for family in self.families:
                    if family.encode(secret) in raw:
                        out.append(Finding(collector=name, path=leaf.path, family=family.name))
        return out

    def check(self, obj: object, secret: str) -> None:
        """The single security-failure conversion."""
        found = self.findings(obj, secret)
        if found:
            raise SecurityFailure(
                f"{len(found)} occurrence(s) of the canary: " + "; ".join(str(f) for f in sorted(found, key=str))
            )


def registered_collectors() -> frozenset[str]:
    return frozenset(_REGISTRY)
