"""What `make demo` prints must exist and must work.

This file is the whole reason issue #1 was possible: the demo menu named three
scripts that were not there, a variable the agent has never heard of, and a
scheme the agent refuses. Nothing read it, because it is `echo` inside a
Makefile and no test looks at those.

Every assertion here is about the TEXT the demo prints, checked against the
sibling repository it tells the reader to `cd` into.
"""

from __future__ import annotations

import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
MAKEFILE = REPO / "Makefile"
OTEL = REPO.parent / "tidewall-otel" / "python"

#: The demo spans two repositories, and the server's own CI checks out one.
#: Skipped rather than deleted: it runs locally, and in the contract job, which
#: checks out the sibling for exactly this.
needs_otel = pytest.mark.skipif(not OTEL.is_dir(), reason=f"the tidewall-otel sibling is not checked out at {OTEL}")


@pytest.fixture(scope="module")
def demo_text() -> str:
    text = MAKEFILE.read_text()
    start = text.index("demo: demo-stop")
    end = text.index("\ndemo-stop:")
    return text[start:end]


def test_the_demo_target_was_actually_found(demo_text):
    """Without this the file passes vacuously if the Makefile is restructured."""
    assert len(demo_text) > 2000, len(demo_text)
    assert "Tidewall Demo Environment Ready" in demo_text


def _printed_scripts(demo_text: str) -> list[str]:
    """Every `examples/...py` the menu tells the reader to run."""
    return sorted(set(re.findall(r"(examples/[\w/]+\.py)", demo_text)))


@needs_otel
def test_every_script_the_demo_prints_exists(demo_text):
    """The defect this file exists for.

    `demo_openai_wrapper.py` and `demo_direct_sdk.py` were printed for months
    and were never in the repository, on main or on any branch.
    """
    printed = _printed_scripts(demo_text)
    assert printed, "the menu names no scripts at all; the pattern is wrong"

    missing = [s for s in printed if not (OTEL / s).is_file()]

    assert not missing, f"the demo tells the reader to run scripts that do not exist: {missing}"


@needs_otel
def test_every_tidewall_variable_the_demo_sets_is_one_the_agent_reads(demo_text):
    """`TIDEWALL_BASE_URL_TEMPLATE` was printed and is not a variable.

    It was AIDR heritage. Setting it did nothing, and because it is not on the
    removed-variable list it was silently ignored rather than refused -- so the
    reader got a missing-configuration error naming a DIFFERENT variable.
    """
    config = (OTEL / "src" / "tidewall_otel" / "_config.py").read_text()
    real = set(re.findall(r'["\'](TIDEWALL_[A-Z_]+)["\']', config))
    assert len(real) > 5, f"only {len(real)} variables found; the config scan is wrong"

    printed = set(re.findall(r"(TIDEWALL_[A-Z_]+)=", demo_text))
    assert printed, "the menu sets no TIDEWALL_ variables; the pattern is wrong"

    invented = sorted(printed - real)

    assert not invented, f"the demo sets variables the agent has never heard of: {invented}"


def test_every_agent_path_carries_the_loopback_opt_in(demo_text):
    """The demo serves plain http, and the agent refuses that by default.

    Each block that sets TIDEWALL_BASE_URL to an http:// address must also set
    TIDEWALL_ALLOW_INSECURE_LOOPBACK, or the path fails at the first guard call
    -- which is precisely how three of the four printed paths were broken.
    """
    blocks = demo_text.split("------------------------------------------------------------")

    offenders = [
        # The heading is the line after the separator.
        next((ln.strip() for ln in b.splitlines() if "echo" in ln and "." in ln), "?")
        for b in blocks
        if "TIDEWALL_BASE_URL=http://" in b and "TIDEWALL_ALLOW_INSECURE_LOOPBACK" not in b
    ]

    assert not offenders, f"agent paths set a plaintext guard URL without the opt-in: {offenders}"


def test_the_extension_path_tells_the_reader_to_tick_the_box(demo_text):
    """The extension refuses plain http too, and its opt-in is a checkbox.

    A path that works only if you guess at a checkbox is the same defect as one
    that names a script that is not there.
    """
    assert "Allow an insecure local server" in demo_text
