import os
import platform
import shutil
import subprocess

import pytest


def test_sandbox_plan_disabled(monkeypatch):
    from src import sandbox_runner

    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {"enabled": "false"})
    plan = sandbox_runner.build_sandbox_plan(("echo", "hi"), cwd="/tmp")
    assert plan.enabled is False
    assert plan.sandboxed is False
    assert plan.command == ("echo", "hi")


def test_normalize_sandbox_settings_accepts_known_fields_only(tmp_path):
    from src import sandbox_runner

    raw = {
        "enabled": "yes",
        "failIfUnavailable": "1",
        "network_deny": "true",
        "ignored": "drop me",
        "filesystem": {
            "allowRead": [str(tmp_path), ""],
            "allow_write": str(tmp_path / "out"),
            "denyRead": str(tmp_path / ".env"),
            "deny_write": [str(tmp_path / ".git")],
        },
    }
    normalized = sandbox_runner.normalize_sandbox_settings(raw)
    assert normalized["enabled"] is True
    assert normalized["fail_if_unavailable"] is True
    assert normalized["network"]["deny"] is True
    assert "ignored" not in normalized
    assert normalized["filesystem"]["allow_read"] == [str(tmp_path)]
    assert normalized["filesystem"]["allow_write"] == [str(tmp_path / "out")]
    assert normalized["filesystem"]["deny_read"] == [str(tmp_path / ".env")]
    assert normalized["filesystem"]["deny_write"] == [str(tmp_path / ".git")]


def test_sandbox_plan_fail_open_when_backend_missing(monkeypatch):
    from src import sandbox_runner

    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {"enabled": True, "fail_if_unavailable": False})
    monkeypatch.setattr(sandbox_runner.platform, "system", lambda: "Plan9")
    plan = sandbox_runner.build_sandbox_plan(("echo", "hi"), cwd="/tmp")
    assert plan.enabled is True
    assert plan.sandboxed is False
    assert "running unsandboxed" in plan.reason


def test_sandbox_plan_fail_closed_when_backend_missing(monkeypatch):
    from src import sandbox_runner

    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {"enabled": True, "fail_if_unavailable": True})
    monkeypatch.setattr(sandbox_runner.platform, "system", lambda: "Plan9")
    plan = sandbox_runner.build_sandbox_plan(("echo", "hi"), cwd="/tmp")
    assert plan.enabled is True
    assert plan.sandboxed is False
    assert "no supported backend" in plan.reason


def test_macos_profile_contains_workspace_and_denies_sensitive(monkeypatch, tmp_path):
    from src import sandbox_runner

    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / ".git").mkdir()
    (ws / ".github").mkdir()
    (ws / ".github" / "workflows").mkdir()
    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {
        "enabled": True,
        "filesystem": {"allow_read": [], "allow_write": [], "deny": []},
        "network": {"deny": True},
    })
    profile = sandbox_runner._macos_sandbox_profile(str(ws))
    assert str(ws) in profile
    assert "(allow file-read*)" in profile
    assert ".ssh" in profile
    assert ".git" in profile
    assert ".github/workflows" in profile
    assert "(deny file-write*" in profile
    assert "network-outbound" not in profile


def test_macos_profile_appends_operation_allowances_after_denies(monkeypatch, tmp_path):
    from src import sandbox_runner

    ws = tmp_path / "ws"
    ws.mkdir()
    approved_read = tmp_path / "secret.txt"
    approved_write_dir = tmp_path / "outside"
    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {
        "enabled": True,
        "filesystem": {
            "deny_read": [str(approved_read)],
            "deny_write": [str(approved_write_dir)],
        },
        "network": {"deny": False},
    })
    profile = sandbox_runner._macos_sandbox_profile(
        str(ws),
        extra_allow_read=[str(approved_read)],
        extra_allow_write=[str(approved_write_dir)],
    )
    deny_read_idx = profile.index(f'(deny file-read* (literal "{approved_read}"))')
    allow_read_idx = profile.index(f'(allow file-read* (literal "{approved_read}"))')
    deny_write_idx = profile.index(f'(deny file-write* (literal "{approved_write_dir}"))')
    allow_write_idx = profile.index(f'(allow file-write* (literal "{approved_write_dir}"))')
    assert allow_read_idx > deny_read_idx
    assert allow_write_idx > deny_write_idx


@pytest.mark.skipif(platform.system() != "Darwin" or not shutil.which("sandbox-exec"), reason="requires macOS sandbox-exec")
def test_macos_sandbox_exec_profile_runs_and_enforces_paths(monkeypatch, tmp_path):
    from src import sandbox_runner

    ws = tmp_path / "ws"
    ws.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("secret-ok", encoding="utf-8")
    outside = os.path.expanduser(f"~/.odysseus-sandbox-write-test-{os.getpid()}")
    try:
        os.unlink(outside)
    except FileNotFoundError:
        pass

    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {
        "enabled": True,
        "fail_if_unavailable": True,
        "filesystem": {
            "deny_read": [str(secret)],
        },
        "network": {"deny": False},
    })

    def run(command, **kwargs):
        plan = sandbox_runner.build_sandbox_plan(command, cwd=str(ws), **kwargs)
        try:
            return subprocess.run(plan.command, cwd=str(ws), text=True, capture_output=True, timeout=10)
        finally:
            if plan.backend == "sandbox-exec" and plan.reason:
                try:
                    os.unlink(plan.reason)
                except OSError:
                    pass

    assert run(("/usr/bin/true",)).returncode == 0

    write_ws = run(("/bin/sh", "-c", "echo ok > inside.txt && cat inside.txt"))
    assert write_ws.returncode == 0
    assert write_ws.stdout.strip() == "ok"

    write_outside = run(("/bin/sh", "-c", f"echo nope > {outside}"))
    assert write_outside.returncode != 0
    assert not os.path.exists(outside)

    read_denied = run(("/bin/cat", str(secret)))
    assert read_denied.returncode != 0

    read_allowed = run(("/bin/cat", str(secret)), extra_allow_read=[str(secret)])
    assert read_allowed.returncode == 0
    assert read_allowed.stdout.strip() == "secret-ok"

    write_allowed = run(("/bin/sh", "-c", f"echo approved > {outside}"), extra_allow_write=[os.path.dirname(outside)])
    assert write_allowed.returncode == 0
    with open(outside, "r", encoding="utf-8") as f:
        assert f.read().strip() == "approved"
    os.unlink(outside)


def test_bubblewrap_plan_overlays_write_denies(monkeypatch, tmp_path):
    from src import sandbox_runner

    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / ".git").mkdir()
    (ws / ".env").write_text("SECRET=1", encoding="utf-8")
    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {"enabled": True, "network": {"deny": True}})
    monkeypatch.setattr(sandbox_runner.shutil, "which", lambda name: "/usr/bin/bwrap" if name == "bwrap" else None)
    plan = sandbox_runner._linux_bwrap_plan(("echo", "hi"), str(ws))
    assert plan is not None
    command = list(plan.command)
    assert "--unshare-net" in command
    git_index = command.index(str(ws / ".git"))
    assert command[git_index - 1] == "--ro-bind"
    assert any(command[i : i + 3] == ["--ro-bind", "/dev/null", str(ws / ".env")] for i in range(len(command) - 2))


def test_sandbox_status_reports_disabled(monkeypatch, tmp_path):
    from src import sandbox_runner

    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {"enabled": False})
    monkeypatch.setattr(sandbox_runner.platform, "system", lambda: "Plan9")
    status = sandbox_runner.sandbox_status(cwd=str(tmp_path))
    assert status["enabled"] is False
    assert status["sandboxed"] is False
    assert status["selected_backend"] == ""
    assert status["filesystem"]["deny_read_count"] >= 1
    assert status["warnings"] == ["sandbox is disabled; operation permissions still run before Bash/Python"]


def test_sandbox_status_warns_when_enabled_without_backend(monkeypatch, tmp_path):
    from src import sandbox_runner

    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {"enabled": True, "fail_if_unavailable": False})
    monkeypatch.setattr(sandbox_runner.platform, "system", lambda: "Plan9")
    status = sandbox_runner.sandbox_status(cwd=str(tmp_path))
    assert status["enabled"] is True
    assert status["sandboxed"] is False
    assert "running unsandboxed" in status["warnings"][0]
