"""Exercise the demo activation recipe without starting a server."""

import json
import os
import pathlib
import subprocess

import pytest

MAKEFILE = pathlib.Path(__file__).resolve().parents[1] / "Makefile"


@pytest.fixture
def demo(tmp_path):
    curl = tmp_path / "curl"
    curl.write_text(
        "#!/bin/sh\n"
        'printf "%s\\n" "$@" >> curl-args\n'
        'case "$*" in\n'
        '  *POST*) exit "${APPROVAL_STATUS:-0}" ;;\n'
        '  *) printf "%s" "${DEVICES:-[]}"; exit "${LIST_STATUS:-0}" ;;\n'
        "esac\n"
    )
    curl.chmod(0o755)
    (tmp_path / ".demo.key").write_text("ak_demo_test_credential\n")

    def run(code="ABCD2345\n", **variables):
        return subprocess.run(
            ["make", "-f", str(MAKEFILE), "demo-activate"],
            cwd=tmp_path,
            env={
                **os.environ,
                "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}",
                "DEVICE_ID": "",
                "DEVICES": '[{"id":"demo-device","status":"pending"}]',
                **variables,
            },
            capture_output=True,
            text=True,
            input=code,
            timeout=10,
        )

    return tmp_path, run


def test_activation_uses_saved_key_without_a_log(demo):
    directory, run = demo
    result = run()
    assert result.returncode == 0, result.stderr
    assert "Device demo-device approved" in result.stdout
    arguments = (directory / "curl-args").read_text()
    assert arguments.count("Authorization: Bearer ak_demo_test_credential") == 2
    assert "http://localhost:8080/v1/devices/demo-device/approve" in arguments
    assert '{"confirmation_code": "ABCD2345"}' in arguments
    assert "PATCH" not in arguments


@pytest.mark.parametrize("key", [None, ""])
def test_activation_requires_a_saved_key(demo, key):
    directory, run = demo
    if key is None:
        (directory / ".demo.key").unlink()
    else:
        (directory / ".demo.key").write_text(key)
    result = run()
    assert result.returncode != 0
    assert "Run make demo first" in result.stdout
    assert not (directory / "curl-args").exists()


@pytest.mark.parametrize(
    ("variables", "message"),
    [
        ({"LIST_STATUS": "22"}, "Could not list devices"),
        ({"APPROVAL_STATUS": "22"}, "Could not approve device"),
        ({"DEVICES": "[]"}, "Expected one pending device"),
    ],
)
def test_activation_does_not_report_success_on_failure(demo, variables, message):
    _, run = demo
    result = run(**variables)
    assert result.returncode != 0
    assert message in result.stdout + result.stderr
    assert " approved" not in result.stdout


def test_multiple_pending_devices_require_an_explicit_selection(demo):
    directory, run = demo
    devices = json.dumps([{"id": name, "status": "pending"} for name in ("first", "second")])
    result = run(DEVICES=devices)
    assert result.returncode != 0
    assert "DEVICE_ID=<id>" in result.stderr
    assert "POST" not in (directory / "curl-args").read_text()

    result = run(DEVICES=devices, DEVICE_ID="first")
    assert result.returncode == 0, result.stderr
    assert "Device first approved" in result.stdout


def test_active_devices_are_not_selected_for_approval(demo):
    directory, run = demo
    result = run(DEVICES='[{"id":"active-device","status":"active"}]')
    assert result.returncode != 0
    assert "POST" not in (directory / "curl-args").read_text()


def test_confirmation_code_is_required(demo):
    directory, run = demo
    result = run(code="")
    assert result.returncode != 0
    assert "No confirmation code supplied" in result.stdout
    assert "POST" not in (directory / "curl-args").read_text()
