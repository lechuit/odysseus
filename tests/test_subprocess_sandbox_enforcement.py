import pytest


@pytest.mark.asyncio
async def test_bash_uses_sandbox_plan_command_when_enabled(monkeypatch):
    from src.agent_tools import subprocess_tools
    from src.agent_tools.subprocess_tools import BashTool
    from src.sandbox_runner import SandboxPlan

    captured = {}

    def fake_plan(command, **kwargs):
        captured["raw_command"] = command
        captured["plan_kwargs"] = kwargs
        return SandboxPlan(
            enabled=True,
            backend="test-sandbox",
            command=("sandbox-wrapper", "--", *command),
            sandboxed=True,
        )

    async def fake_exec(*args, **kwargs):
        captured["exec_args"] = args
        captured["exec_kwargs"] = kwargs
        return object()

    async def fail_shell(*args, **kwargs):  # pragma: no cover - failure path
        raise AssertionError("sandboxed bash must not use create_subprocess_shell")

    async def fake_streaming(proc, **kwargs):
        return "ok", "", 0, False

    monkeypatch.setattr("src.sandbox_runner.build_sandbox_plan", fake_plan)
    monkeypatch.setattr("src.sandbox_runner.sandbox_enabled", lambda: True)
    monkeypatch.setattr("src.sandbox_runner.fail_if_unavailable", lambda: True)
    monkeypatch.setattr("src.sandbox_runner.bare_git_scrub_candidates", lambda _cwd: ["HEAD"])
    monkeypatch.setattr(
        "src.sandbox_runner.scrub_planted_bare_git_files",
        lambda cwd, candidates: captured.setdefault("scrubbed", (cwd, list(candidates))) or [],
    )
    monkeypatch.setattr(subprocess_tools.asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(subprocess_tools.asyncio, "create_subprocess_shell", fail_shell)
    monkeypatch.setattr(subprocess_tools, "_run_subprocess_streaming", fake_streaming)

    result = await BashTool().execute("echo ok", {"sandbox_allow": {"allow_network": True}})

    assert result["exit_code"] == 0
    assert result["sandboxed"] is True
    assert captured["raw_command"] == ("/bin/sh", "-c", "echo ok")
    assert captured["plan_kwargs"]["extra_allow_network"] is True
    assert captured["exec_args"][:2] == ("sandbox-wrapper", "--")
    assert captured["scrubbed"][1] == ["HEAD"]


@pytest.mark.asyncio
async def test_python_uses_sandbox_plan_command_when_enabled(monkeypatch):
    from src.agent_tools import subprocess_tools
    from src.agent_tools.subprocess_tools import PythonTool
    from src.sandbox_runner import SandboxPlan

    captured = {}

    def fake_plan(command, **kwargs):
        captured["raw_command"] = command
        captured["plan_kwargs"] = kwargs
        return SandboxPlan(
            enabled=True,
            backend="test-sandbox",
            command=("sandbox-wrapper", "--", *command),
            sandboxed=True,
        )

    async def fake_exec(*args, **kwargs):
        captured["exec_args"] = args
        captured["exec_kwargs"] = kwargs
        return object()

    async def fake_streaming(proc, **kwargs):
        return "py-ok", "", 0, False

    monkeypatch.setattr("src.sandbox_runner.build_sandbox_plan", fake_plan)
    monkeypatch.setattr("src.sandbox_runner.sandbox_enabled", lambda: True)
    monkeypatch.setattr("src.sandbox_runner.fail_if_unavailable", lambda: True)
    monkeypatch.setattr("src.sandbox_runner.bare_git_scrub_candidates", lambda _cwd: ["objects"])
    monkeypatch.setattr(
        "src.sandbox_runner.scrub_planted_bare_git_files",
        lambda cwd, candidates: captured.setdefault("scrubbed", (cwd, list(candidates))) or [],
    )
    monkeypatch.setattr(subprocess_tools.asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(subprocess_tools, "_run_subprocess_streaming", fake_streaming)

    result = await PythonTool().execute("print('ok')", {"sandbox_allow": {"allow_read": ["/tmp/x"]}})

    assert result["exit_code"] == 0
    assert result["sandboxed"] is True
    assert captured["raw_command"][-2:] == ("-c", "print('ok')")
    assert captured["plan_kwargs"]["extra_allow_read"] == ["/tmp/x"]
    assert captured["exec_args"][:2] == ("sandbox-wrapper", "--")
    assert captured["scrubbed"][1] == ["objects"]
