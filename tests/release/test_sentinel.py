"""The release gate does not exist yet, and says so.

This fails unconditionally, on purpose, and is removed in Task 6 step 4 when
the real `release-gate` job exists.

The reason it lands first, before any policy or manifest artifact: without it,
the tasks that build the gate's data (the schema invariant, the execution
manifest, the occurrence matrix) would sit on a green tree while the repository
appears to have a release gate it does not have. A partially-built gate that
reports success is the exact failure this whole step exists to remove, and it
would be introduced by the process of removing it.

Removing this test is a deliberate step in an accepted plan, not a cleanup.
"""

import pytest

#: What is still missing, checked off as each task lands. The gate is not
#: complete until this is empty AND the real job decides the build.
#:
#: Tasks 1-3 are removed as they land. Leaving a completed task listed here is
#: not harmless: the branch would claim the task is done while the checked-in
#: hard-fail diagnostic said it was not, and one of those two would be wrong
#: with nothing to say which.
STILL_MISSING = (
    "witnesses and the mandatory surfaces (Task 5)",
    "the two canary suites, expected-failure manifest, release-gate job (Task 6)",
)


def test_the_release_gate_is_not_complete():
    pytest.fail(
        "release gate incomplete: "
        + "; ".join(STILL_MISSING)
        + ". This sentinel is removed in Task 6 step 4, when the release-gate "
        "job exists and decides the build."
    )
