"""Smoke tests for the local install/restart helper scripts."""

import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def test_local_runtime_scripts_are_valid_bash():
    scripts = [
        ROOT / "scripts" / "_lib" / "local_runtime.sh",
        ROOT / "scripts" / "install_local.sh",
        ROOT / "scripts" / "restart_local.sh",
        ROOT / "scripts" / "healthcheck_local.sh",
    ]
    proc = subprocess.run(
        ["bash", "-n", *map(str, scripts)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr


def test_local_runtime_scripts_are_executable():
    for rel in (
        "scripts/install_local.sh",
        "scripts/restart_local.sh",
        "scripts/healthcheck_local.sh",
    ):
        assert (ROOT / rel).stat().st_mode & 0o111, f"{rel} should be executable"
