"""The standalone manifest-emptiness assertion.

Task 6 step 5 wants a release workflow whose publish job `needs: release-gate`
AND asserts the manifest is empty. Both now exist: the publish topology was
answered on 2026-08-23 -- PyPI, via Trusted Publishing.

This module remains a REQUIRED STEP OF ITS OWN in CI, separate from the
release workflow, because the two answer different questions. CI asks whether
the manifest is empty on every commit; the release workflow asks it again at
the moment of publication. A gate that passed elsewhere is evidence about
elsewhere.
"""

from __future__ import annotations

import pathlib
import sys
import tomllib

MANIFEST = pathlib.Path(__file__).resolve().parent / "expected_failures.toml"

#: Answered on 2026-08-23. Retained rather than deleted so the record of what
#: was deferred, and when it stopped being deferred, survives in the source.
PUBLISH_TOPOLOGY = (
    "PyPI via Trusted Publishing (OIDC), triggered by a v* tag. The publish "
    "job needs: release-gate and re-asserts manifest emptiness in its own "
    "steps, so release-gate failures DO block release."
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
        print(f"NOTE: {PUBLISH_TOPOLOGY}")
        return 1
    print("MANIFEST EMPTY")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
