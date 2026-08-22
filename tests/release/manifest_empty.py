"""The standalone manifest-emptiness assertion.

Task 6 step 5 wants a release workflow whose publish job `needs: release-gate`
AND asserts the manifest is empty. WHAT THIS PROJECT PUBLISHES IS A DEFERRED
OWNER DECISION -- PyPI or GHCR changes the trigger, the artifact, the
credentials, the permissions and the publish command, and whether the gate
becomes a reusable workflow is part of the same choice.

So the half that does not depend on it lands now, as a required step of its
own, and the claim that FAILURES BLOCK RELEASE IS NOT MADE. A workflow that
asserts emptiness is not a workflow that gates publication; saying otherwise
would be the one thing this whole programme is built to stop.
"""

from __future__ import annotations

import pathlib
import sys
import tomllib

MANIFEST = pathlib.Path(__file__).resolve().parent / "expected_failures.toml"

#: Recorded here so a reader does not have to infer it from an absence.
BLOCKED_ON_OWNER = (
    "publish topology (PyPI vs GHCR, and whether the gate becomes a reusable "
    "workflow) is a deferred owner decision; until it is made, this project "
    "does NOT claim that release-gate failures block release"
)


def manifest_records(path: pathlib.Path | None = None) -> list[dict]:
    path = MANIFEST if path is None else path
    if not path.exists():
        return []
    return list(tomllib.loads(path.read_text()).get("expected_failure", []))


def main(argv: list[str]) -> int:
    path = pathlib.Path(argv[1]) if len(argv) > 1 else MANIFEST
    records = manifest_records(path)
    if records:
        print(f"MANIFEST NOT EMPTY: {len(records)} expected-failure record(s)")
        print(f"NOTE: {BLOCKED_ON_OWNER}")
        return 1
    print("MANIFEST EMPTY")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
