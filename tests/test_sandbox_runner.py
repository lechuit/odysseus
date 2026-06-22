import os
import platform
import shutil
import subprocess
from pathlib import Path

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


def test_sandbox_strict_local_preset_preserves_filesystem_lists(tmp_path):
    from src import sandbox_runner

    base = {
        "enabled": False,
        "fail_if_unavailable": False,
        "network": {"deny": False},
        "filesystem": {
            "allow_read": [str(tmp_path / "read")],
            "allow_write": [str(tmp_path / "write")],
            "deny_read": [str(tmp_path / ".env")],
            "deny_write": [str(tmp_path / ".git")],
        },
    }

    preset = sandbox_runner.sandbox_preset_settings("strict-local", base)

    assert preset["enabled"] is True
    assert preset["fail_if_unavailable"] is True
    assert preset["network"]["deny"] is True
    assert preset["filesystem"]["allow_read"] == [str(tmp_path / "read")]
    assert preset["filesystem"]["allow_write"] == [str(tmp_path / "write")]
    assert preset["filesystem"]["deny_read"] == [str(tmp_path / ".env")]
    assert preset["filesystem"]["deny_write"] == [str(tmp_path / ".git")]


def test_sandbox_unknown_preset_is_rejected():
    from src import sandbox_runner

    with pytest.raises(ValueError, match="unknown sandbox preset"):
        sandbox_runner.sandbox_preset_settings("maximum-chaos")


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


def test_macos_profile_can_allow_network_for_approved_operation(monkeypatch, tmp_path):
    from src import sandbox_runner

    ws = tmp_path / "ws"
    ws.mkdir()
    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {
        "enabled": True,
        "filesystem": {"allow_read": [], "allow_write": [], "deny": []},
        "network": {"deny": True},
    })

    profile = sandbox_runner._macos_sandbox_profile(str(ws), extra_allow_network=True)

    assert "(allow network-outbound)" in profile
    assert "(allow network-bind)" in profile


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


def test_macos_profile_appends_configured_allow_read_after_denies(monkeypatch, tmp_path):
    from src import sandbox_runner

    ws = tmp_path / "ws"
    ws.mkdir()
    secret = tmp_path / "secret.txt"
    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {
        "enabled": True,
        "filesystem": {
            "deny_read": [str(secret)],
            "allow_read": [str(secret)],
        },
        "network": {"deny": False},
    })

    profile = sandbox_runner._macos_sandbox_profile(str(ws))

    deny_idx = profile.index(f'(deny file-read* (literal "{secret}"))')
    allow_idx = profile.index(f'(allow file-read* (literal "{secret}"))')
    assert allow_idx > deny_idx


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


def test_bare_git_scrub_candidates_remove_only_planted_sentinels(tmp_path):
    from src import sandbox_runner

    ws = tmp_path / "ws"
    ws.mkdir()
    preexisting_config = ws / "config"
    preexisting_config.write_text("keep me", encoding="utf-8")

    candidates = sandbox_runner.bare_git_scrub_candidates(str(ws))
    assert str(preexisting_config) not in candidates

    symlink_target = tmp_path / "head-target"
    symlink_target.write_text("do not remove target", encoding="utf-8")
    os.symlink(symlink_target, ws / "HEAD")
    (ws / "objects").mkdir()
    (ws / "refs").mkdir()
    (ws / "hooks").mkdir()

    removed = sandbox_runner.scrub_planted_bare_git_files(str(ws), candidates)

    assert set(map(os.path.basename, removed)) == {"HEAD", "objects", "refs", "hooks"}
    assert not (ws / "HEAD").exists()
    assert symlink_target.read_text(encoding="utf-8") == "do not remove target"
    assert not (ws / "objects").exists()
    assert not (ws / "refs").exists()
    assert not (ws / "hooks").exists()
    assert preexisting_config.read_text(encoding="utf-8") == "keep me"


def test_existing_bare_git_sentinels_are_write_denied(monkeypatch, tmp_path):
    from src import sandbox_runner

    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (ws / "objects").mkdir()
    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {"enabled": True, "network": {"deny": False}})
    monkeypatch.setattr(sandbox_runner.shutil, "which", lambda name: "/usr/bin/bwrap" if name == "bwrap" else None)

    plan = sandbox_runner._linux_bwrap_plan(("echo", "hi"), str(ws))

    assert plan is not None
    command = list(plan.command)
    assert _has_arg_pair(command, "--ro-bind", str(ws / "HEAD"))
    assert _has_arg_pair(command, "--ro-bind", str(ws / "objects"))


@pytest.mark.skipif(platform.system() != "Linux" or not shutil.which("bwrap"), reason="requires Linux bubblewrap")
def test_linux_bubblewrap_runtime_enforces_paths(monkeypatch, tmp_path):
    from src import sandbox_runner

    ws = tmp_path / "ws"
    ws.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("secret-ok", encoding="utf-8")
    outside_dir = Path.home() / f".odysseus-sandbox-runtime-{os.getpid()}"
    outside = outside_dir / "outside.txt"
    outside_dir.mkdir(exist_ok=False)
    outside.write_text("outside-before", encoding="utf-8")

    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {
        "enabled": True,
        "fail_if_unavailable": True,
        "filesystem": {"deny_read": [str(secret)]},
        "network": {"deny": False},
    })

    def run(command, **kwargs):
        plan = sandbox_runner._linux_bwrap_plan(command, str(ws), **kwargs)
        assert plan is not None
        return subprocess.run(plan.command, cwd=str(ws), text=True, capture_output=True, timeout=10)

    try:
        smoke = run(("/bin/true",))
        if smoke.returncode != 0:
            pytest.skip(f"bubblewrap is installed but not runnable here: {smoke.stderr[:240]}")

        write_ws = run(("/bin/sh", "-c", "echo ok > inside.txt && cat inside.txt"))
        assert write_ws.returncode == 0
        assert write_ws.stdout.strip() == "ok"

        write_outside = run(("/bin/sh", "-c", f"echo nope > {outside}"))
        assert write_outside.returncode != 0
        assert outside.read_text(encoding="utf-8") == "outside-before"

        read_denied = run(("/bin/cat", str(secret)))
        assert read_denied.returncode != 0

        read_allowed = run(("/bin/cat", str(secret)), extra_allow_read=[str(secret)])
        assert read_allowed.returncode == 0
        assert read_allowed.stdout.strip() == "secret-ok"

        write_allowed = run(
            ("/bin/sh", "-c", f"echo approved > {outside} && cat {outside}"),
            extra_allow_write=[str(outside_dir)],
        )
        assert write_allowed.returncode == 0
        assert write_allowed.stdout.strip() == "approved"
        assert outside.read_text(encoding="utf-8").strip() == "approved"
    finally:
        try:
            outside.unlink()
        except FileNotFoundError:
            pass
        try:
            outside_dir.rmdir()
        except OSError:
            pass


@pytest.mark.skipif(platform.system() != "Linux" or not shutil.which("bwrap"), reason="requires Linux bubblewrap")
def test_linux_bubblewrap_runtime_rebinds_approved_child_inside_mask(monkeypatch, tmp_path):
    from src import sandbox_runner

    ws = tmp_path / "ws"
    ws.mkdir()
    secret_dir = tmp_path / "sensitive"
    nested_dir = secret_dir / "nested"
    nested_dir.mkdir(parents=True)
    secret = nested_dir / "token.txt"
    secret.write_text("nested-secret-ok", encoding="utf-8")
    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {
        "enabled": True,
        "fail_if_unavailable": True,
        "filesystem": {"deny_read": [str(secret_dir)]},
        "network": {"deny": False},
    })

    def run(command, **kwargs):
        plan = sandbox_runner._linux_bwrap_plan(command, str(ws), **kwargs)
        assert plan is not None
        return subprocess.run(plan.command, cwd=str(ws), text=True, capture_output=True, timeout=10)

    smoke = run(("/bin/true",))
    if smoke.returncode != 0:
        pytest.skip(f"bubblewrap is installed but not runnable here: {smoke.stderr[:240]}")

    read_denied = run(("/bin/cat", str(secret)))
    assert read_denied.returncode != 0

    read_allowed = run(("/bin/cat", str(secret)), extra_allow_read=[str(secret)])
    assert read_allowed.returncode == 0
    assert read_allowed.stdout.strip() == "nested-secret-ok"


@pytest.mark.skipif(platform.system() != "Linux" or not shutil.which("bwrap"), reason="requires Linux bubblewrap")
def test_linux_bubblewrap_runtime_honors_configured_allow_read_inside_mask(monkeypatch, tmp_path):
    from src import sandbox_runner

    ws = tmp_path / "ws"
    ws.mkdir()
    secret_dir = tmp_path / "sensitive"
    secret_dir.mkdir()
    secret = secret_dir / "token.txt"
    secret.write_text("configured-allow-read-ok", encoding="utf-8")
    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {
        "enabled": True,
        "fail_if_unavailable": True,
        "filesystem": {
            "deny_read": [str(secret_dir)],
            "allow_read": [str(secret)],
        },
        "network": {"deny": False},
    })

    def run(command, **kwargs):
        plan = sandbox_runner._linux_bwrap_plan(command, str(ws), **kwargs)
        assert plan is not None
        return subprocess.run(plan.command, cwd=str(ws), text=True, capture_output=True, timeout=10)

    smoke = run(("/bin/true",))
    if smoke.returncode != 0:
        pytest.skip(f"bubblewrap is installed but not runnable here: {smoke.stderr[:240]}")

    read_allowed = run(("/bin/cat", str(secret)))
    assert read_allowed.returncode == 0
    assert read_allowed.stdout.strip() == "configured-allow-read-ok"


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


def test_bubblewrap_plan_skips_missing_system_mounts(monkeypatch, tmp_path):
    from src import sandbox_runner

    ws = tmp_path / "ws"
    ws.mkdir()
    real_exists = os.path.exists

    def fake_exists(path):
        if path in {"/dev", "/usr", "/bin", "/lib", "/etc"}:
            return True
        if path == "/lib64":
            return False
        return real_exists(path)

    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {"enabled": True, "network": {"deny": False}})
    monkeypatch.setattr(sandbox_runner.shutil, "which", lambda name: "/usr/bin/bwrap" if name == "bwrap" else None)
    monkeypatch.setattr(sandbox_runner.os.path, "exists", fake_exists)

    plan = sandbox_runner._linux_bwrap_plan(("echo", "hi"), str(ws))

    assert plan is not None
    command = list(plan.command)
    _arg_triplet_index(command, "--ro-bind", "/usr", "/usr")
    assert not any(command[i : i + 3] == ["--ro-bind", "/lib64", "/lib64"] for i in range(len(command) - 2))


def test_bubblewrap_plan_can_allow_network_for_approved_operation(monkeypatch, tmp_path):
    from src import sandbox_runner

    ws = tmp_path / "ws"
    ws.mkdir()
    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {"enabled": True, "network": {"deny": True}})
    monkeypatch.setattr(sandbox_runner.shutil, "which", lambda name: "/usr/bin/bwrap" if name == "bwrap" else None)

    plan = sandbox_runner._linux_bwrap_plan(("echo", "hi"), str(ws), extra_allow_network=True)

    assert plan is not None
    assert "--unshare-net" not in list(plan.command)


def test_bubblewrap_plan_creates_parent_dirs_for_outside_mounts(monkeypatch, tmp_path):
    from src import sandbox_runner

    workspace_parent = tmp_path / "home" / "user"
    ws = workspace_parent / "project"
    outside = tmp_path / "shared" / "secret.txt"
    write_dir = tmp_path / "exports"
    ws.mkdir(parents=True)
    outside.parent.mkdir()
    outside.write_text("secret", encoding="utf-8")
    write_dir.mkdir()
    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {"enabled": True, "network": {"deny": False}})
    monkeypatch.setattr(sandbox_runner.shutil, "which", lambda name: "/usr/bin/bwrap" if name == "bwrap" else None)

    plan = sandbox_runner._linux_bwrap_plan(
        ("echo", "hi"),
        str(ws),
        extra_allow_read=[str(outside)],
        extra_allow_write=[str(write_dir)],
    )

    assert plan is not None
    command = list(plan.command)
    assert _has_arg_pair(command, "--dir", str(workspace_parent))
    assert _has_arg_pair(command, "--dir", str(outside.parent))
    assert _has_arg_pair(command, "--bind", str(ws))
    assert _has_arg_pair(command, "--ro-bind", str(outside))
    assert _has_arg_pair(command, "--bind", str(write_dir))


def test_bubblewrap_plan_rebinds_approved_read_after_file_deny(monkeypatch, tmp_path):
    from src import sandbox_runner

    ws = tmp_path / "ws"
    ws.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("secret", encoding="utf-8")
    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {
        "enabled": True,
        "filesystem": {"deny_read": [str(secret)]},
        "network": {"deny": False},
    })
    monkeypatch.setattr(sandbox_runner.shutil, "which", lambda name: "/usr/bin/bwrap" if name == "bwrap" else None)

    plan = sandbox_runner._linux_bwrap_plan(("echo", "hi"), str(ws), extra_allow_read=[str(secret)])

    assert plan is not None
    command = list(plan.command)
    deny_idx = _arg_triplet_index(command, "--ro-bind", "/dev/null", str(secret))
    allow_idx = _arg_triplet_index(command, "--ro-bind", str(secret), str(secret), start=deny_idx + 1)
    assert allow_idx > deny_idx


def test_bubblewrap_plan_rebinds_configured_allow_read_after_file_deny(monkeypatch, tmp_path):
    from src import sandbox_runner

    ws = tmp_path / "ws"
    ws.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("secret", encoding="utf-8")
    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {
        "enabled": True,
        "filesystem": {
            "deny_read": [str(secret)],
            "allow_read": [str(secret)],
        },
        "network": {"deny": False},
    })
    monkeypatch.setattr(sandbox_runner.shutil, "which", lambda name: "/usr/bin/bwrap" if name == "bwrap" else None)

    plan = sandbox_runner._linux_bwrap_plan(("echo", "hi"), str(ws))

    assert plan is not None
    command = list(plan.command)
    deny_idx = _arg_triplet_index(command, "--ro-bind", "/dev/null", str(secret))
    allow_idx = _arg_triplet_index(command, "--ro-bind", str(secret), str(secret), start=deny_idx + 1)
    assert allow_idx > deny_idx


def test_bubblewrap_plan_recreates_masked_parent_for_approved_nested_read(monkeypatch, tmp_path):
    from src import sandbox_runner

    ws = tmp_path / "ws"
    ws.mkdir()
    secret_dir = tmp_path / "sensitive"
    nested_dir = secret_dir / "nested"
    nested_dir.mkdir(parents=True)
    secret = nested_dir / "token.txt"
    secret.write_text("secret", encoding="utf-8")
    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {
        "enabled": True,
        "filesystem": {"deny_read": [str(secret_dir)]},
        "network": {"deny": False},
    })
    monkeypatch.setattr(sandbox_runner.shutil, "which", lambda name: "/usr/bin/bwrap" if name == "bwrap" else None)

    plan = sandbox_runner._linux_bwrap_plan(("echo", "hi"), str(ws), extra_allow_read=[str(secret)])

    assert plan is not None
    command = list(plan.command)
    mask_idx = _arg_pair_index(command, "--tmpfs", str(secret_dir))
    nested_dir_idx = _arg_pair_index(command, "--dir", str(nested_dir), start=mask_idx + 1)
    allow_idx = _arg_triplet_index(command, "--ro-bind", str(secret), str(secret), start=nested_dir_idx + 1)
    assert mask_idx < nested_dir_idx < allow_idx


def test_bubblewrap_plan_recreates_masked_parent_for_configured_allow_read(monkeypatch, tmp_path):
    from src import sandbox_runner

    ws = tmp_path / "ws"
    ws.mkdir()
    secret_dir = tmp_path / "sensitive"
    nested_dir = secret_dir / "nested"
    nested_dir.mkdir(parents=True)
    secret = nested_dir / "token.txt"
    secret.write_text("secret", encoding="utf-8")
    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {
        "enabled": True,
        "filesystem": {
            "deny_read": [str(secret_dir)],
            "allow_read": [str(secret)],
        },
        "network": {"deny": False},
    })
    monkeypatch.setattr(sandbox_runner.shutil, "which", lambda name: "/usr/bin/bwrap" if name == "bwrap" else None)

    plan = sandbox_runner._linux_bwrap_plan(("echo", "hi"), str(ws))

    assert plan is not None
    command = list(plan.command)
    mask_idx = _arg_pair_index(command, "--tmpfs", str(secret_dir))
    nested_dir_idx = _arg_pair_index(command, "--dir", str(nested_dir), start=mask_idx + 1)
    allow_idx = _arg_triplet_index(command, "--ro-bind", str(secret), str(secret), start=nested_dir_idx + 1)
    assert mask_idx < nested_dir_idx < allow_idx


def test_bubblewrap_plan_rebinds_approved_write_after_write_deny(monkeypatch, tmp_path):
    from src import sandbox_runner

    ws = tmp_path / "ws"
    ws.mkdir()
    outside = tmp_path / "outside-write"
    outside.mkdir()
    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {
        "enabled": True,
        "filesystem": {"deny_write": [str(outside)]},
        "network": {"deny": False},
    })
    monkeypatch.setattr(sandbox_runner.shutil, "which", lambda name: "/usr/bin/bwrap" if name == "bwrap" else None)

    plan = sandbox_runner._linux_bwrap_plan(("echo", "hi"), str(ws), extra_allow_write=[str(outside)])

    assert plan is not None
    command = list(plan.command)
    deny_idx = _arg_triplet_index(command, "--ro-bind", str(outside), str(outside))
    allow_idx = _arg_triplet_index(command, "--bind", str(outside), str(outside), start=deny_idx + 1)
    assert allow_idx > deny_idx


def test_firejail_plan_honors_approved_read_write_overrides(monkeypatch, tmp_path):
    from src import sandbox_runner

    ws = tmp_path / "ws"
    ws.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    write_dir = tmp_path / "write"
    write_dir.mkdir()
    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {"enabled": True, "network": {"deny": True}})
    monkeypatch.setattr(sandbox_runner.shutil, "which", lambda name: "/usr/bin/firejail" if name == "firejail" else None)

    plan = sandbox_runner._linux_firejail_plan(
        ("echo", "hi"),
        str(ws),
        extra_allow_read=[str(outside)],
        extra_allow_write=[str(write_dir)],
    )

    assert plan is not None
    command = list(plan.command)
    assert "--net=none" in command
    assert f"--whitelist={ws}" in command
    assert f"--read-write={ws}" in command
    assert f"--read-only={tmp_path}" in command
    assert f"--whitelist={outside}" in command
    assert f"--whitelist={write_dir}" in command
    assert f"--read-write={write_dir}" in command


def test_firejail_plan_skips_implicit_runtime_tmp(monkeypatch, tmp_path):
    from src import sandbox_runner

    ws = tmp_path / "ws"
    ws.mkdir()
    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {"enabled": True, "network": {"deny": False}})
    monkeypatch.setattr(sandbox_runner.shutil, "which", lambda name: "/usr/bin/firejail" if name == "firejail" else None)

    plan = sandbox_runner._linux_firejail_plan(("echo", "hi"), str(ws))

    assert plan is not None
    command = list(plan.command)
    assert "--whitelist=/tmp" not in command
    assert "--read-write=/tmp" not in command


def test_firejail_plan_orders_operation_overrides_after_denies(monkeypatch, tmp_path):
    from src import sandbox_runner

    ws = tmp_path / "ws"
    ws.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("secret", encoding="utf-8")
    outside = tmp_path / "outside-write"
    outside.mkdir()
    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {
        "enabled": True,
        "filesystem": {
            "deny_read": [str(secret)],
            "deny_write": [str(outside)],
        },
        "network": {"deny": False},
    })
    monkeypatch.setattr(sandbox_runner.shutil, "which", lambda name: "/usr/bin/firejail" if name == "firejail" else None)

    plan = sandbox_runner._linux_firejail_plan(
        ("echo", "hi"),
        str(ws),
        extra_allow_read=[str(secret)],
        extra_allow_write=[str(outside)],
    )

    assert plan is not None
    command = list(plan.command)
    assert f"--blacklist={secret}" not in command
    assert f"--whitelist={secret}" in command
    assert command.index(f"--read-only={outside}") < command.index(f"--read-write={outside}")


def test_firejail_plan_keeps_parent_read_deny_for_approved_child(monkeypatch, tmp_path):
    from src import sandbox_runner

    ws = tmp_path / "ws"
    ws.mkdir()
    secret_dir = tmp_path / "secret-dir"
    secret_dir.mkdir()
    secret = secret_dir / "token.txt"
    secret.write_text("secret", encoding="utf-8")
    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {
        "enabled": True,
        "filesystem": {"deny_read": [str(secret_dir)]},
        "network": {"deny": False},
    })
    monkeypatch.setattr(sandbox_runner.shutil, "which", lambda name: "/usr/bin/firejail" if name == "firejail" else None)

    plan = sandbox_runner._linux_firejail_plan(("echo", "hi"), str(ws), extra_allow_read=[str(secret)])

    assert plan is not None
    command = list(plan.command)
    assert f"--blacklist={secret_dir}" in command
    assert f"--whitelist={secret}" in command


def test_firejail_plan_orders_configured_allow_read_after_deny(monkeypatch, tmp_path):
    from src import sandbox_runner

    ws = tmp_path / "ws"
    ws.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("secret", encoding="utf-8")
    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {
        "enabled": True,
        "filesystem": {
            "deny_read": [str(secret)],
            "allow_read": [str(secret)],
        },
        "network": {"deny": False},
    })
    monkeypatch.setattr(sandbox_runner.shutil, "which", lambda name: "/usr/bin/firejail" if name == "firejail" else None)

    plan = sandbox_runner._linux_firejail_plan(("echo", "hi"), str(ws))

    assert plan is not None
    command = list(plan.command)
    assert f"--blacklist={secret}" not in command
    assert f"--whitelist={secret}" in command


def _has_arg_pair(command, option, value):
    return any(command[i : i + 2] == [option, value] for i in range(len(command) - 1))


def _arg_pair_index(command, option, value, *, start=0):
    for i in range(start, len(command) - 1):
        if command[i : i + 2] == [option, value]:
            return i
    raise AssertionError(f"missing {option} {value} in {command}")


def _arg_triplet_index(command, option, first, second, *, start=0):
    for i in range(start, len(command) - 2):
        if command[i : i + 3] == [option, first, second]:
            return i
    raise AssertionError(f"missing {option} {first} {second} in {command}")


def test_sandbox_status_reports_disabled(monkeypatch, tmp_path):
    from src import sandbox_runner

    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {"enabled": False})
    monkeypatch.setattr(sandbox_runner.platform, "system", lambda: "Plan9")
    status = sandbox_runner.sandbox_status(cwd=str(tmp_path))
    assert status["enabled"] is False
    assert status["sandboxed"] is False
    assert status["selected_backend"] == ""
    assert status["effective_mode"] == "disabled"
    assert status["enforcement_level"] == "operation_permissions_only"
    assert status["command_execution_blocked"] is False
    assert status["fallback_unsandboxed"] is False
    assert status["filesystem"]["deny_read_count"] >= 1
    assert status["warnings"] == ["sandbox is disabled; operation permissions still run before Bash/Python"]


def test_sandbox_status_warns_when_enabled_without_backend(monkeypatch, tmp_path):
    from src import sandbox_runner

    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {"enabled": True, "fail_if_unavailable": False})
    monkeypatch.setattr(sandbox_runner.platform, "system", lambda: "Plan9")
    status = sandbox_runner.sandbox_status(cwd=str(tmp_path))
    assert status["enabled"] is True
    assert status["sandboxed"] is False
    assert status["effective_mode"] == "unsandboxed_fallback"
    assert status["enforcement_level"] == "operation_permissions_only_fallback"
    assert status["command_execution_blocked"] is False
    assert status["fallback_unsandboxed"] is True
    assert "running unsandboxed" in status["warnings"][0]


def test_sandbox_status_reports_fail_closed_blocking(monkeypatch, tmp_path):
    from src import sandbox_runner

    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {"enabled": True, "fail_if_unavailable": True})
    monkeypatch.setattr(sandbox_runner.platform, "system", lambda: "Plan9")

    status = sandbox_runner.sandbox_status(cwd=str(tmp_path))

    assert status["enabled"] is True
    assert status["sandboxed"] is False
    assert status["effective_mode"] == "blocked"
    assert status["enforcement_level"] == "blocked"
    assert status["command_execution_blocked"] is True
    assert status["fallback_unsandboxed"] is False
    assert "no supported backend" in status["warnings"][0]


def test_sandbox_status_reports_sandboxed_mode(monkeypatch, tmp_path):
    from src import sandbox_runner

    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {"enabled": True, "fail_if_unavailable": True})
    monkeypatch.setattr(sandbox_runner.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(sandbox_runner.shutil, "which", lambda name: "/usr/bin/sandbox-exec" if name == "sandbox-exec" else None)
    monkeypatch.setattr(
        sandbox_runner,
        "_macos_plan",
        lambda command, cwd, **_kwargs: sandbox_runner.SandboxPlan(
            enabled=True,
            backend="sandbox-exec",
            command=tuple(command),
            reason="",
            sandboxed=True,
        ),
    )

    status = sandbox_runner.sandbox_status(cwd=str(tmp_path))

    assert status["sandboxed"] is True
    assert status["effective_mode"] == "sandboxed"
    assert status["enforcement_level"] == "os_sandbox"
    assert status["command_execution_blocked"] is False
    assert status["fallback_unsandboxed"] is False


def test_sandbox_status_warns_about_glob_filesystem_paths(monkeypatch, tmp_path):
    from src import sandbox_runner

    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {
        "enabled": True,
        "fail_if_unavailable": False,
        "filesystem": {
            "deny_read": [str(tmp_path / "secrets" / "**")],
            "allow_write": [str(tmp_path / "build" / "*.tmp")],
        },
    })
    monkeypatch.setattr(sandbox_runner.platform, "system", lambda: "Plan9")

    status = sandbox_runner.sandbox_status(cwd=str(tmp_path))

    warnings = "\n".join(status["warnings"])
    assert "filesystem.deny_read contains glob-like path" in warnings
    assert "filesystem.allow_write contains glob-like path" in warnings
    assert "concrete paths" in warnings


def test_sandbox_status_includes_linux_dependency_report(monkeypatch, tmp_path):
    from src import sandbox_runner

    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {"enabled": True, "fail_if_unavailable": False})
    monkeypatch.setattr(sandbox_runner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(sandbox_runner.shutil, "which", lambda _name: None)

    status = sandbox_runner.sandbox_status(cwd=str(tmp_path))

    assert status["dependencies"]["platform"] == "linux"
    assert "Linux sandbox requires bubblewrap or firejail" in status["dependencies"]["errors"]
    assert "apt install bubblewrap firejail" in status["dependencies"]["install_hint"]
    assert any("bubblewrap or firejail" in warning for warning in status["warnings"])


def test_linux_build_skips_unrunnable_bubblewrap_for_firejail(monkeypatch, tmp_path):
    from src import sandbox_runner

    ws = tmp_path / "ws"
    ws.mkdir()
    sandbox_runner.clear_sandbox_runtime_probe_cache()
    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {"enabled": True, "fail_if_unavailable": True})
    monkeypatch.setattr(sandbox_runner.platform, "system", lambda: "Linux")

    def fake_which(name):
        return {
            "bwrap": "/usr/bin/bwrap",
            "firejail": "/usr/bin/firejail",
            "true": "/usr/bin/true",
        }.get(name)

    def fake_run(command, **_kwargs):
        if command[0] == "/usr/bin/bwrap":
            return subprocess.CompletedProcess(command, 1, "", "No permissions to create namespace")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(sandbox_runner.shutil, "which", fake_which)
    monkeypatch.setattr(sandbox_runner.subprocess, "run", fake_run)

    plan = sandbox_runner.build_sandbox_plan(("echo", "hi"), cwd=str(ws))

    assert plan.sandboxed is True
    assert plan.backend == "firejail"


def test_sandbox_status_reports_unrunnable_linux_backend(monkeypatch, tmp_path):
    from src import sandbox_runner

    sandbox_runner.clear_sandbox_runtime_probe_cache()
    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {"enabled": True, "fail_if_unavailable": True})
    monkeypatch.setattr(sandbox_runner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        sandbox_runner.shutil,
        "which",
        lambda name: {"bwrap": "/usr/bin/bwrap", "true": "/usr/bin/true"}.get(name),
    )
    monkeypatch.setattr(
        sandbox_runner.subprocess,
        "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(
            command,
            1,
            "",
            "No permissions to create namespace",
        ),
    )

    status = sandbox_runner.sandbox_status(cwd=str(tmp_path))

    checks = status["dependencies"]["runtime_checks"]
    assert checks["bubblewrap"]["available"] is True
    assert checks["bubblewrap"]["runnable"] is False
    assert status["sandboxed"] is False
    assert status["effective_mode"] == "blocked"
    assert status["command_execution_blocked"] is True
    assert "installed Linux backends failed runtime smoke tests" in status["reason"]
    assert "Linux sandbox backends are installed but none passed a runtime smoke test" in status["dependencies"]["errors"]
    assert any("bubblewrap is installed but failed a sandbox smoke test" in warning for warning in status["warnings"])


def test_sandbox_status_reports_runnable_linux_backend(monkeypatch, tmp_path):
    from src import sandbox_runner

    sandbox_runner.clear_sandbox_runtime_probe_cache()
    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {"enabled": True, "fail_if_unavailable": True})
    monkeypatch.setattr(sandbox_runner.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        sandbox_runner.shutil,
        "which",
        lambda name: {"bwrap": "/usr/bin/bwrap", "true": "/usr/bin/true"}.get(name),
    )
    monkeypatch.setattr(
        sandbox_runner.subprocess,
        "run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, "", ""),
    )

    status = sandbox_runner.sandbox_status(cwd=str(tmp_path))

    checks = status["dependencies"]["runtime_checks"]
    assert checks["bubblewrap"]["runnable"] is True
    assert status["sandboxed"] is True
    assert status["selected_backend"] == "bubblewrap"
    assert status["backend_runtime_ready"] is True
    assert status["effective_mode"] == "sandboxed"


def test_sandbox_self_test_skips_when_disabled(monkeypatch, tmp_path):
    from src import sandbox_runner

    monkeypatch.setattr(
        sandbox_runner,
        "sandbox_status",
        lambda cwd=None: {
            "enabled": False,
            "sandboxed": False,
            "reason": "sandbox disabled",
            "warnings": [],
        },
    )

    result = sandbox_runner.sandbox_self_test(cwd=str(tmp_path))

    assert result["overall_passed"] is False
    assert result["skipped"] is True
    assert result["skip_reason"] == "sandbox is disabled"
    assert result["checks"] == []


def test_sandbox_self_test_passes_with_expected_enforcement(monkeypatch, tmp_path):
    from src import sandbox_runner

    active = tmp_path / "active"
    active.mkdir()
    monkeypatch.setattr(
        sandbox_runner,
        "sandbox_status",
        lambda cwd=None: {
            "enabled": True,
            "sandboxed": True,
            "selected_backend": "fake-sandbox",
            "reason": "",
            "warnings": [],
        },
    )

    def fake_run(command, *, cwd, extra_allow_read=None, extra_allow_write=None, timeout=10.0):
        extra_allow_read = [os.path.realpath(p) for p in (extra_allow_read or [])]
        extra_allow_write = [os.path.realpath(p) for p in (extra_allow_write or [])]
        script = command[2]
        if "printf" in script:
            value = command[4]
            path = command[5]
            path_real = os.path.realpath(path)
            allowed_write = path_real.startswith(os.path.realpath(cwd) + os.sep) or any(
                path_real == allowed or path_real.startswith(allowed + os.sep)
                for allowed in extra_allow_write
            )
            if not allowed_write:
                return {
                    "ran": True,
                    "sandboxed": True,
                    "backend": "fake-sandbox",
                    "exit_code": 1,
                    "stdout": "",
                    "stderr": "permission denied",
                    "error": "",
                }
            with open(path, "w", encoding="utf-8") as f:
                f.write(value)
            return {
                "ran": True,
                "sandboxed": True,
                "backend": "fake-sandbox",
                "exit_code": 0,
                "stdout": value,
                "stderr": "",
                "error": "",
            }
        if "cat" in script:
            path = command[4]
            path_real = os.path.realpath(path)
            protected = os.path.basename(path_real) == ".env"
            allowed_read = any(path_real == allowed for allowed in extra_allow_read)
            if protected and not allowed_read:
                return {
                    "ran": True,
                    "sandboxed": True,
                    "backend": "fake-sandbox",
                    "exit_code": 1,
                    "stdout": "",
                    "stderr": "permission denied",
                    "error": "",
                }
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            return {
                "ran": True,
                "sandboxed": True,
                "backend": "fake-sandbox",
                "exit_code": 0,
                "stdout": content,
                "stderr": "",
                "error": "",
            }
        raise AssertionError(f"unexpected command: {command}")

    monkeypatch.setattr(sandbox_runner, "_run_sandbox_self_test_command", fake_run)

    result = sandbox_runner.sandbox_self_test(cwd=str(active))

    assert result["skipped"] is False
    assert result["overall_passed"] is True
    assert result["passed_count"] == result["total_count"] == 5
    assert {check["name"] for check in result["checks"]} == {
        "workspace_write_allowed",
        "outside_write_denied",
        "protected_read_no_leak",
        "approved_outside_write_allowed",
        "approved_protected_read_allowed",
    }
