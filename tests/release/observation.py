"""Observe which marked components a case ACTUALLY reaches.

Task 2 declares which component each case exercises and CANNOT VERIFY IT.
Confirming that a case reaches a component requires running it and watching,
so every Task 2 oracle compares one declaration with another. A review
demonstrated the gap by changing a case from
`malicious_prompt/generic_injection_ml` to `topic/topics_pipeline` with all
twenty tests still green.

This is the first mechanism that can tell the difference. It records the lines
that executed and maps them back to the marked region each marker introduces.

A MARKER MARKS THE CODE THAT FOLLOWS IT. `# release:component x/y` on line N
is about the statement beginning at the next line, so the marked region is
that statement's full AST extent -- `lineno` to `end_lineno`. Treating the
marker line itself as the region observes nothing, because a comment never
executes; treating "any line after N" as the region observes every marker in
the file once anything below the first one runs.
"""

from __future__ import annotations

import ast
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from tests.release.inventory import APP, Component, scan_source


class NoRegion(Exception):
    """A marker introduces no statement, so nothing can ever observe it."""


@dataclass(frozen=True)
class Region:
    """The lines a marker is about."""

    identity: str
    source: str
    start: int
    end: int

    def contains(self, line: int) -> bool:
        return self.start <= line <= self.end


def _statement_regions(path: Path) -> list[tuple[int, int]]:
    """Every statement's (lineno, end_lineno), innermost last."""
    tree = ast.parse(path.read_text())
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.stmt) and node.end_lineno is not None:
            out.append((node.lineno, node.end_lineno))
    return sorted(out)


def _branch_bodies(path: Path) -> dict[int, tuple[int, int]]:
    """For each branching statement, the extent of the branch it GUARDS.

    A marker above `if cond:` is credited whenever the CHECK runs, whatever
    branch is taken -- so `scanner_engine/applicability_skip` was reported by
    every scan, including single-detector runs where nothing was ever skipped.
    Nineteen of the source's markers had this shape, and every component
    observation made through them was "the check ran", not "this happened".

    Each of those markers describes what happens WHEN THE CONDITION HOLDS, so
    the marked region is the guarded body, not the test.
    """
    tree = ast.parse(path.read_text())
    out: dict[int, tuple[int, int]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.If | ast.While | ast.For | ast.AsyncFor) and node.body:
            first, last = node.body[0], node.body[-1]
            if last.end_lineno is not None:
                out[node.lineno] = (first.lineno, last.end_lineno)
    return out


def region_for(component: Component, root: Path = APP) -> Region:
    """The AST extent of the statement the marker introduces."""
    path = root.parent / component.source
    # `>=`, not `>`. The grammar accepts a TRAILING marker -- a comment token
    # on the same line as a statement -- and `>` skipped that statement to mark
    # the next one. For a marker on its own line the two are identical, because
    # no statement begins on a comment line.
    candidates = [r for r in _statement_regions(path) if r[0] >= component.line]
    if not candidates:
        raise NoRegion(f"{component.identity} at {component.source}:{component.line} " "introduces no statement")
    # The statement STARTING SOONEST after the marker. Sorting by (start, end)
    # and taking the first also picks the outermost when several begin on the
    # same line, which is the region the marker is about.
    start, end = min(candidates)

    # If that statement is a branch, narrow to the body it guards.
    bodies = _branch_bodies(path)
    if start in bodies:
        start, end = bodies[start]

    return Region(identity=component.identity, source=component.source, start=start, end=end)


def all_regions(root: Path = APP) -> dict[str, Region]:
    return {c.identity: region_for(c, root) for c in scan_source(root)}


@dataclass
class Observation:
    """Lines that executed, per file."""

    lines: dict[str, set[int]] = field(default_factory=dict)

    def record(self, filename: str, lineno: int) -> None:
        self.lines.setdefault(filename, set()).add(lineno)

    def components(self, regions: dict[str, Region], root: Path = APP) -> set[str]:
        """Which marked components these executed lines reached."""
        found = set()
        for identity, region in regions.items():
            target = str((root.parent / region.source).resolve())
            for line in self.lines.get(target, ()):
                if region.contains(line):
                    found.add(identity)
                    break
        return found


@contextmanager
def observing(root: Path = APP) -> Iterator[Observation]:
    """Record executed lines under `root` for the duration of the block.

    Only files under `root` are recorded: tracing everything makes the result
    dominated by library frames and slow enough that nobody runs it.
    """
    observation = Observation()
    prefix = str(root.resolve())

    def trace(frame, event, arg):
        filename = frame.f_code.co_filename
        if not filename.startswith(prefix):
            return None
        observation.record(filename, frame.f_lineno)
        return trace_lines

    def trace_lines(frame, event, arg):
        if event == "line":
            observation.record(frame.f_code.co_filename, frame.f_lineno)
        return trace_lines

    previous = sys.gettrace()
    sys.settrace(trace)
    threading.settrace(trace)
    try:
        yield observation
    finally:
        sys.settrace(previous)
        threading.settrace(previous)


class ComponentMismatch(Exception):
    """A case's declared component is not the one it was observed to reach."""


def verify_declared_component(case_id: str, declared: str, observed: set[str]) -> None:
    """Reject a case whose declared component is not the one it reaches."""
    if declared not in observed:
        raise ComponentMismatch(
            f"{case_id}: declares {declared!r}, observed "
            f"{sorted(observed) if observed else 'no marked component at all'}"
        )
