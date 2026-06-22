import asyncio
import json


def test_manage_settings_add_list_delete_permission_rule(tmp_path, monkeypatch):
    import src.settings as settings
    from src.tool_implementations import do_manage_settings

    settings_path = tmp_path / "settings.json"
    monkeypatch.setattr(settings, "SETTINGS_FILE", str(settings_path))
    settings._invalidate_caches()

    add = asyncio.run(do_manage_settings(json.dumps({
        "action": "add_permission_rule",
        "behavior": "deny",
        "tool": "bash",
        "match": "prefix",
        "pattern": "git push",
        "description": "No pushes from agent",
    })))
    assert add["exit_code"] == 0
    rule_id = add["rule"]["id"]

    listed = asyncio.run(do_manage_settings(json.dumps({"action": "list_permission_rules"})))
    assert listed["exit_code"] == 0
    assert listed["rules"][0]["pattern"] == "git push"

    deleted = asyncio.run(do_manage_settings(json.dumps({
        "action": "delete_permission_rule",
        "id": rule_id,
    })))
    assert deleted["exit_code"] == 0
    assert deleted["deleted"] is True


def test_manage_settings_rejects_malformed_permission_rule(tmp_path, monkeypatch):
    import src.settings as settings
    from src.tool_implementations import do_manage_settings

    settings_path = tmp_path / "settings.json"
    monkeypatch.setattr(settings, "SETTINGS_FILE", str(settings_path))
    settings._invalidate_caches()

    result = asyncio.run(do_manage_settings(json.dumps({
        "action": "add_permission_rule",
        "behavior": "maybe",
        "tool": "bash",
        "pattern": "git push",
    })))
    assert result["exit_code"] == 1
    assert "Invalid permission rule" in result["error"]


def test_manage_settings_set_sandbox_structured_value(tmp_path, monkeypatch):
    import src.settings as settings
    from src.tool_implementations import do_manage_settings

    settings_path = tmp_path / "settings.json"
    monkeypatch.setattr(settings, "SETTINGS_FILE", str(settings_path))
    settings._invalidate_caches()

    result = asyncio.run(do_manage_settings(json.dumps({
        "action": "set_sandbox",
        "value": {
            "enabled": "true",
            "failIfUnavailable": "false",
            "network": {"deny": "yes"},
            "filesystem": {"denyWrite": [str(tmp_path / ".git")]},
            "unknown": "ignored",
        },
    })))
    assert result["exit_code"] == 0
    assert result["value"]["enabled"] is True
    assert result["value"]["fail_if_unavailable"] is False
    assert result["value"]["network"]["deny"] is True
    assert result["value"]["filesystem"]["deny_write"] == [str(tmp_path / ".git")]
    assert "unknown" not in result["value"]

    saved = settings.load_settings()["operation_permissions_sandbox"]
    assert saved == result["value"]


def test_manage_settings_set_operation_permissions_sandbox_alias(tmp_path, monkeypatch):
    import src.settings as settings
    from src.tool_implementations import do_manage_settings

    settings_path = tmp_path / "settings.json"
    monkeypatch.setattr(settings, "SETTINGS_FILE", str(settings_path))
    settings._invalidate_caches()

    result = asyncio.run(do_manage_settings(json.dumps({
        "action": "set",
        "key": "sandbox",
        "value": {
            "enabled": "false",
            "network_deny": "false",
            "allow_read": [str(tmp_path)],
        },
    })))
    assert result["exit_code"] == 0
    assert result["value"]["enabled"] is False
    assert result["value"]["network"]["deny"] is False
    assert result["value"]["filesystem"]["allow_read"] == [str(tmp_path)]


def test_manage_settings_sandbox_status(tmp_path, monkeypatch):
    import src.settings as settings
    from src import sandbox_runner
    from src.tool_implementations import do_manage_settings

    settings_path = tmp_path / "settings.json"
    monkeypatch.setattr(settings, "SETTINGS_FILE", str(settings_path))
    settings._invalidate_caches()
    monkeypatch.setattr(sandbox_runner.platform, "system", lambda: "Plan9")

    result = asyncio.run(do_manage_settings(json.dumps({
        "action": "sandbox_status",
        "cwd": str(tmp_path),
    })))
    assert result["exit_code"] == 0
    assert result["sandbox"]["cwd"] == str(tmp_path)
    assert result["sandbox"]["enabled"] is False
    assert "Sandbox enabled=False" in result["response"]
