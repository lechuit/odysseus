import json


def test_sandbox_self_test_cli_status_only(monkeypatch, tmp_path, capsys):
    from scripts import sandbox_self_test as cli
    from src import sandbox_runner

    monkeypatch.setattr(
        sandbox_runner,
        "sandbox_status",
        lambda cwd=None: {
            "enabled": True,
            "sandboxed": True,
            "effective_mode": "sandboxed",
            "selected_backend": "bubblewrap",
            "backend_runtime_ready": True,
            "warnings": [],
        },
    )

    rc = cli.run(["--cwd", str(tmp_path), "--preset", "strict_local", "--status-only", "--fail-on-fail"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["cwd"] == str(tmp_path)
    assert payload["preset"] == "strict_local"
    assert payload["process_only_settings"]["enabled"] is True
    assert payload["process_only_settings"]["fail_if_unavailable"] is True
    assert payload["summary"]["selected_backend"] == "bubblewrap"
    assert payload["summary"]["backend_runtime_ready"] is True


def test_sandbox_self_test_cli_fail_on_failed_self_test(monkeypatch, tmp_path, capsys):
    from scripts import sandbox_self_test as cli
    from src import sandbox_runner

    monkeypatch.setattr(
        sandbox_runner,
        "sandbox_status",
        lambda cwd=None: {
            "enabled": True,
            "sandboxed": True,
            "effective_mode": "sandboxed",
            "selected_backend": "bubblewrap",
            "backend_runtime_ready": True,
            "warnings": [],
        },
    )
    monkeypatch.setattr(
        sandbox_runner,
        "sandbox_self_test",
        lambda cwd=None: {
            "overall_passed": False,
            "skipped": False,
            "passed_count": 4,
            "total_count": 5,
            "checks": [
                {"name": "workspace_write_allowed", "passed": True},
                {"name": "outside_write_denied", "passed": False},
            ],
            "warnings": [],
        },
    )

    rc = cli.run(["--cwd", str(tmp_path), "--preset", "strict_local", "--fail-on-fail"])

    assert rc == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["overall_passed"] is False
    assert payload["summary"]["failed_checks"] == ["outside_write_denied"]


def test_sandbox_self_test_cli_current_preset_does_not_override(monkeypatch, tmp_path, capsys):
    from scripts import sandbox_self_test as cli
    from src import sandbox_runner

    def explode(_preset, _base):
        raise AssertionError("current preset should not call sandbox_preset_settings")

    monkeypatch.setattr(sandbox_runner, "sandbox_preset_settings", explode)
    monkeypatch.setattr(
        sandbox_runner,
        "sandbox_status",
        lambda cwd=None: {
            "enabled": False,
            "sandboxed": False,
            "effective_mode": "disabled",
            "selected_backend": "",
            "backend_runtime_ready": None,
            "warnings": ["sandbox is disabled"],
        },
    )

    rc = cli.run(["--cwd", str(tmp_path), "--preset", "current", "--status-only"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["process_only_settings"] is None
    assert payload["summary"]["effective_mode"] == "disabled"
