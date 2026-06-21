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

