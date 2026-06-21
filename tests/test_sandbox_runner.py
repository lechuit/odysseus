def test_sandbox_plan_disabled(monkeypatch):
    from src import sandbox_runner

    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {"enabled": False})
    plan = sandbox_runner.build_sandbox_plan(("echo", "hi"), cwd="/tmp")
    assert plan.enabled is False
    assert plan.sandboxed is False
    assert plan.command == ("echo", "hi")


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
    monkeypatch.setattr(sandbox_runner, "_settings", lambda: {
        "enabled": True,
        "filesystem": {"allow_read": [], "allow_write": [], "deny": []},
        "network": {"deny": True},
    })
    profile = sandbox_runner._macos_sandbox_profile(str(ws))
    assert str(ws) in profile
    assert ".ssh" in profile
    assert "network-outbound" not in profile

