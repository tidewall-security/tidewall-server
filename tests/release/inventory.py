"""The component and sub-path inventory, generated from markers in the source.

A parser that *infers* which syntactic forms constitute a component cannot be
trusted here. The domain spans `ScannerEngine`'s control flow, detector-specific
string-keyed status maps, the eighteen detect-secrets plugin classes, and
ordinary `if`/`raise` branches in destination validation. Nothing syntactic
unites those, so a parser would recognise only the forms its author happened to
remember — and would then pass its own drift test, because the manifest was
written from the same memory.

So the contract is a **registry, not inference**: every component and sub-path
is declared at its definition site by a marker comment, and this module only
collects them. The grammar is one rule:

    # release:component <component>/<sub-path>  -- <why this path differs>

A marker is a comment, so it cannot change runtime behaviour, and it sits on
the line whose branch it names, so it moves with the code it describes.

**What this does and does not buy.** It cannot discover a component nobody
marked — that is the residual, and it is why the manifest comparison is only
one of the two oracles. What it does buy is that adding a marked path without
adding it to the manifest fails the build, and deleting a MARKER without
deleting its manifest entry fails too.

Deleting the marked *thing* is a weaker guarantee than deleting its marker. The
eighteen secrets plugins are declared by a block of comments above the plugin
list rather than bound to their individual entries, so removing a plugin while
leaving its marker changes nothing here. Comments cannot bind to the construct
they name; the honest statement is that this registry tracks DECLARATIONS, and
a declaration going stale relative to the code beside it is what Task 5's
observation exists to catch.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
APP = REPO / "app"
GENERATED = Path(__file__).resolve().parent / "inventory.generated.toml"

#: The one rule. Everything after `--` is the reason, kept for a reader and
#: excluded from the identity, so rewording a rationale is not schema drift.
_MARKER = re.compile(
    r"^#\s*release:component\s+(?P<component>[a-z0-9_.]+)/(?P<sub_path>[a-z0-9_.]+)\s+--\s+(?P<why>\S.*)$"
)


@dataclass(frozen=True, order=True)
class Component:
    component: str
    sub_path: str
    source: str
    line: int
    why: str = ""

    @property
    def identity(self) -> str:
        return f"{self.component}/{self.sub_path}"


def _display(path: Path) -> str:
    """Repo-relative where possible, so the artifact is stable across machines."""
    try:
        return str(path.relative_to(REPO))
    except ValueError:
        return str(path)


def scan_source(root: Path = APP) -> list[Component]:
    """Every marked component under *root*, in a stable order."""
    found: list[Component] = []
    for path in sorted(root.rglob("*.py")):
        for token in _comment_tokens(path):
            match = _MARKER.match(token.string.strip())
            if match:
                found.append(
                    Component(
                        component=match.group("component"),
                        sub_path=match.group("sub_path"),
                        source=_display(path),
                        line=token.start[0],
                        why=match.group("why").strip(),
                    )
                )

    # A duplicate identity would render two artifact rows and collapse to one
    # in any set comparison, so two definition sites could claim the same
    # component and no oracle would notice.
    seen: dict[str, Component] = {}
    for entry in found:
        if entry.identity in seen:
            first = seen[entry.identity]
            raise DuplicateComponent(
                f"{entry.identity} is declared twice: " f"{first.source}:{first.line} and {entry.source}:{entry.line}"
            )
        seen[entry.identity] = entry
    return sorted(found)


class DuplicateComponent(Exception):
    """Two definition sites claim the same component identity."""


def _comment_tokens(path: Path):
    """Real Python COMMENT tokens, not any line containing the text.

    A regex over raw lines accepted the marker inside a string literal --
    `x = "# release:component string_literal/not_a_comment -- ..."` registered
    a component with no declaration comment anywhere. Tokenizing means only an
    actual comment can declare one.
    """
    import tokenize

    try:
        with path.open("rb") as handle:
            for token in tokenize.tokenize(handle.readline):
                if token.type == tokenize.COMMENT:
                    yield token
    except (tokenize.TokenError, SyntaxError) as exc:  # pragma: no cover
        raise ValueError(f"{path} could not be tokenized: {exc}") from exc


def render(components: list[Component]) -> str:
    """The checked-in artifact, deterministic and diffable.

    Line numbers are deliberately absent: they change when unrelated code moves,
    and a diff every time anything shifts trains a reviewer to ignore this file.
    """
    lines = [
        "# GENERATED by tests/release/inventory.py -- do not edit by hand.",
        "# Regenerate with: uv run python -m tests.release.inventory",
        "#",
        "# Every component and sub-path declared by a `# release:component`",
        "# marker in app/. CI fails if this file and the source disagree.",
        "",
    ]
    for entry in components:
        lines += [
            "[[component]]",
            f'identity = "{entry.identity}"',
            f'source = "{entry.source}"',
        ]
        if entry.why:
            lines.append(f'why = "{entry.why}"')
        lines.append("")
    return "\n".join(lines)


def load_generated() -> set[str]:
    """The identities recorded in the checked-in artifact."""
    if not GENERATED.exists():
        return set()
    data = tomllib.loads(GENERATED.read_text())
    return {entry["identity"] for entry in data.get("component", [])}


if __name__ == "__main__":  # pragma: no cover - a developer entry point
    GENERATED.write_text(render(scan_source()))
    print(f"wrote {GENERATED.relative_to(REPO)}")
