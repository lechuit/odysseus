#!/usr/bin/env python3
"""Run Odysseus sandbox readiness/enforcement diagnostics.

This script is intentionally side-effect-light: when a preset is supplied it
overrides sandbox settings only inside this Python process.  It does not edit
the user's persisted settings file.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run local OS sandbox status and enforcement self-tests.",
    )
    parser.add_argument(
        "--cwd",
        default=os.getcwd(),
        help="Workspace directory to use for sandbox planning/self-test. Defaults to the current directory.",
    )
    parser.add_argument(
        "--preset",
        choices=("current", "off", "local", "network_deny", "strict_local"),
        default="strict_local",
        help=(
            "Temporary sandbox preset to apply inside this process only. "
            "Use 'current' to honor persisted settings. Default: strict_local."
        ),
    )
    parser.add_argument(
        "--status-only",
        action="store_true",
        help="Only print sandbox_status; do not run enforcement checks.",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output.",
    )
    parser.add_argument(
        "--fail-on-fail",
        action="store_true",
        help="Exit non-zero if the sandbox is skipped or any enforcement check fails.",
    )
    return parser


def _apply_process_only_preset(preset: str) -> Optional[Dict[str, Any]]:
    if preset == "current":
        return None

    from src import sandbox_runner

    settings = sandbox_runner.sandbox_preset_settings(preset, {})
    sandbox_runner.clear_sandbox_runtime_probe_cache()
    sandbox_runner._settings = lambda: settings  # type: ignore[attr-defined]
    return settings


def run(argv: Optional[list[str]] = None) -> int:
    from src import sandbox_runner

    parser = _build_parser()
    args = parser.parse_args(argv)
    original_settings_func = sandbox_runner._settings  # type: ignore[attr-defined]
    try:
        applied_settings = _apply_process_only_preset(args.preset)
        cwd = os.path.realpath(os.path.expanduser(args.cwd))

        status = sandbox_runner.sandbox_status(cwd=cwd)
        payload: Dict[str, Any] = {
            "cwd": cwd,
            "preset": args.preset,
            "process_only_settings": applied_settings,
            "status": status,
        }
        if not args.status_only:
            self_test = sandbox_runner.sandbox_self_test(cwd=cwd)
            payload["self_test"] = self_test
            payload["summary"] = {
                "overall_passed": self_test.get("overall_passed"),
                "skipped": self_test.get("skipped", False),
                "passed_count": self_test.get("passed_count", 0),
                "total_count": self_test.get("total_count", len(self_test.get("checks") or [])),
                "failed_checks": [
                    check.get("name")
                    for check in (self_test.get("checks") or [])
                    if not check.get("passed")
                ],
            }
        else:
            payload["summary"] = {
                "effective_mode": status.get("effective_mode"),
                "sandboxed": status.get("sandboxed"),
                "selected_backend": status.get("selected_backend"),
                "backend_runtime_ready": status.get("backend_runtime_ready"),
                "warnings": status.get("warnings") or [],
            }

        indent = 2 if args.pretty else None
        print(json.dumps(payload, indent=indent, sort_keys=bool(args.pretty)))

        if args.fail_on_fail and not args.status_only:
            summary = payload["summary"]
            if summary.get("skipped") or not summary.get("overall_passed"):
                return 1
        if args.fail_on_fail and args.status_only and not status.get("sandboxed"):
            return 1
        return 0
    finally:
        sandbox_runner._settings = original_settings_func  # type: ignore[attr-defined]
        sandbox_runner.clear_sandbox_runtime_probe_cache()


if __name__ == "__main__":
    raise SystemExit(run())
