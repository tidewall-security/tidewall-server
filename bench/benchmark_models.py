#!/usr/bin/env python
"""Orchestrate tidewall-aiguard-lab benchmarks against the local Tidewall server.

For each model+threshold combination:
  1. Writes a policy YAML with that model/threshold
  2. Starts the Tidewall server
  3. Runs tidewall-aiguard-lab against it
  4. Stops the server, repeats

Usage:
    .venv/bin/python bench/benchmark_models.py
    .venv/bin/python bench/benchmark_models.py --models deberta vijil_dome
    .venv/bin/python bench/benchmark_models.py --thresholds 0.5
    .venv/bin/python bench/benchmark_models.py --models vijil_dome --thresholds 0.5 0.9
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import requests
import yaml

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

TIDEWALL_DIR = Path(__file__).parent.parent
TIDEWALL_LAB_DIR = TIDEWALL_DIR.parent / "tmp" / "tidewall-aiguard-lab"
DATASET = TIDEWALL_LAB_DIR / "data" / "test_dataset.jsonl"
PORT = 8099
BASE_URL = f"http://127.0.0.1:{PORT}"

# ---------------------------------------------------------------------------
# Model configurations
# ---------------------------------------------------------------------------

MODELS: dict[str, dict[str, Any]] = {
    "deberta": {
        "label": "ProtectAI DeBERTa V2",
        "detector_config": {
            "enabled": True,
            "action": "block",
        },
    },
    "pg2_86m": {
        "label": "Meta PG2 86M",
        "detector_config": {
            "enabled": True,
            "action": "block",
            "model": "meta-llama/Llama-Prompt-Guard-2-86M",
            "injection_label": "LABEL_1",
        },
    },
    "pg2_22m": {
        "label": "Meta PG2 22M",
        "detector_config": {
            "enabled": True,
            "action": "block",
            "model": "meta-llama/Llama-Prompt-Guard-2-22M",
            "injection_label": "LABEL_1",
        },
    },
    "gelectra": {
        "label": "JasperLS gelectra",
        "detector_config": {
            "enabled": True,
            "action": "block",
            "model": "JasperLS/gelectra-base-injection",
            "injection_label": "INJECTION",
        },
    },
    "vijil_dome": {
        "label": "Vijil DOME",
        "detector_config": {
            "enabled": True,
            "action": "block",
            "model": "vijil/vijil_dome_prompt_injection_detection",
            "tokenizer": "answerdotai/ModernBERT-base",
            "injection_label": 1,
        },
    },
    "sentinel_v1": {
        "label": "Sentinel v1",
        "detector_config": {
            "enabled": True,
            "action": "block",
            "model": "qualifire/prompt-injection-sentinel",
            "injection_label": "jailbreak",
        },
    },
    "sentinel_v2": {
        "label": "Sentinel v2",
        "detector_config": {
            "enabled": True,
            "action": "block",
            "model": "qualifire/prompt-injection-jailbreak-sentinel-v2",
            "injection_label": "jailbreak",
        },
    },
}

THRESHOLDS = [0.5, 0.9]


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------

def write_policy(detector_config: dict[str, Any], threshold: float) -> Path:
    """Write a policy YAML with only malicious_prompt enabled."""
    cfg = {**detector_config, "threshold": threshold}
    policy = {
        "name": "benchmark_policy",
        "report_only": False,
        "detectors": {
            "malicious_prompt": cfg,
        },
    }
    path = TIDEWALL_DIR / "bench" / "_bench_policy.yaml"
    path.write_text(yaml.dump(policy, default_flow_style=False))
    return path


def start_server(policy_path: Path) -> subprocess.Popen:
    """Start Tidewall with a fresh DB and the given policy."""
    db_path = TIDEWALL_DIR / "data" / "bench-test.db"
    if db_path.exists():
        db_path.unlink()

    env = {
        **os.environ,
        "POLICY_FILE": str(policy_path),
        "DB_URL": f"sqlite:///{db_path}",
        "LOG_LEVEL": "warning",
        "PREWARM": "false",
        "AUTH_ENABLED": "false",
    }
    proc = subprocess.Popen(
        [
            str(TIDEWALL_DIR / ".venv" / "bin" / "python"), "-m", "uvicorn",
            "app.main:app", "--port", str(PORT), "--host", "127.0.0.1",
            "--log-level", "warning",
        ],
        cwd=str(TIDEWALL_DIR),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    for attempt in range(60):
        try:
            r = requests.get(f"{BASE_URL}/health", timeout=2)
            if r.status_code == 200:
                return proc
        except requests.ConnectionError:
            pass
        time.sleep(1)

    proc.terminate()
    stderr = proc.stderr.read().decode() if proc.stderr else ""
    raise RuntimeError(f"Server failed to start.\nStderr:\n{stderr[:2000]}")


def stop_server(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


# ---------------------------------------------------------------------------
# Run tidewall-aiguard-lab
# ---------------------------------------------------------------------------

def run_tidewall_lab(
    model_key: str,
    model_cfg: dict[str, Any],
    threshold: float,
    output_dir: Path,
    rps: int = 25,
) -> bool:
    """Run a single tidewall-aiguard-lab benchmark against the running server."""
    label = model_cfg["label"]
    run_name = f"{model_key}_t{threshold}"

    summary_file = output_dir / f"{run_name}.summary.txt"
    fps_file = output_dir / f"{run_name}.fps.csv"
    fns_file = output_dir / f"{run_name}.fns.csv"

    env = {
        **os.environ,
        "TIDEWALL_GUARD_TOKEN": "bench-token",
        "TIDEWALL_BASE_URL": BASE_URL,
    }

    cmd = [
        sys.executable, "aiguard_lab.py",
        "--input_file", str(DATASET),
        "--service", "tidewall",
        "--detectors", "malicious-prompt",
        "--rps", str(rps),
        "--report_title", f"{label} @ threshold={threshold}",
        "--summary_report_file", str(summary_file),
        "--fps_out_csv", str(fps_file),
        "--fns_out_csv", str(fns_file),
        "--print_label_stats",
    ]

    print(f"\n  Running tidewall-aiguard-lab...", flush=True)
    result = subprocess.run(
        cmd,
        cwd=str(TIDEWALL_LAB_DIR),
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )

    if result.returncode != 0:
        print(f"  tidewall-aiguard-lab failed (exit {result.returncode})", flush=True)
        if result.stderr:
            print(f"  stderr: {result.stderr[:500]}", flush=True)
        if result.stdout:
            print(f"  stdout: {result.stdout[:500]}", flush=True)
        return False

    # Print the summary output
    print(result.stdout, flush=True)

    if summary_file.exists():
        print(f"  Summary saved: {summary_file}", flush=True)

    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark prompt injection models via tidewall-aiguard-lab")
    parser.add_argument(
        "--models",
        nargs="+",
        choices=list(MODELS.keys()),
        default=list(MODELS.keys()),
        help="Models to benchmark (default: all)",
    )
    parser.add_argument(
        "--thresholds",
        nargs="+",
        type=float,
        default=THRESHOLDS,
        help="Thresholds to test (default: 0.5 0.9)",
    )
    parser.add_argument(
        "--rps",
        type=int,
        default=25,
        help="Requests per second to tidewall-aiguard-lab (default: 25)",
    )
    parser.add_argument(
        "--output-dir",
        default=str(TIDEWALL_DIR / "bench" / "results"),
        help="Directory for summary reports and CSV exports",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    total_runs = len(args.models) * len(args.thresholds)
    print(f"Models: {', '.join(args.models)}")
    print(f"Thresholds: {args.thresholds}")
    print(f"Total runs: {total_runs}")
    print(f"Output: {output_dir}")

    run_num = 0
    for threshold in args.thresholds:
        for model_key in args.models:
            run_num += 1
            cfg = MODELS[model_key]
            print(f"\n{'='*60}", flush=True)
            print(f"  [{run_num}/{total_runs}] {cfg['label']} @ threshold={threshold}", flush=True)
            print(f"{'='*60}", flush=True)

            policy_path = write_policy(cfg["detector_config"], threshold)
            print(f"  Starting Tidewall server...", flush=True)

            try:
                proc = start_server(policy_path)
            except RuntimeError as e:
                print(f"  FAILED: {e}", flush=True)
                continue

            try:
                run_tidewall_lab(model_key, cfg, threshold, output_dir, rps=args.rps)
            except subprocess.TimeoutExpired:
                print(f"  TIMEOUT after 600s", flush=True)
            finally:
                stop_server(proc)

    # Print all summary files at the end
    print(f"\n\n{'='*60}")
    print("  ALL RESULTS")
    print(f"{'='*60}\n")
    for f in sorted(output_dir.glob("*.summary.txt")):
        print(f"--- {f.name} ---")
        print(f.read_text())
        print()


if __name__ == "__main__":
    main()
