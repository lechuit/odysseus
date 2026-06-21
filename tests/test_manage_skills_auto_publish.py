import json

import pytest


class _FakeSkillsManager:
    instances = []

    def __init__(self, data_dir):
        self.data_dir = data_dir
        self.added = []
        _FakeSkillsManager.instances.append(self)

    def add_skill(self, **kwargs):
        self.added.append(kwargs)
        return {
            "name": kwargs.get("name"),
            "status": kwargs.get("status"),
            "title": kwargs.get("title") or kwargs.get("name"),
        }


@pytest.mark.asyncio
async def test_manage_skills_add_defaults_to_draft_even_with_auto_approve_pref(monkeypatch):
    from src import tool_implementations
    from services.memory import skills as skills_mod

    _FakeSkillsManager.instances.clear()
    monkeypatch.setattr(skills_mod, "SkillsManager", _FakeSkillsManager)

    # This pref used to implicitly publish a newly-added skill. Manual add now
    # stays draft unless the caller passes an explicit status.
    monkeypatch.setattr("routes.prefs_routes._load_for_user", lambda owner: {"auto_approve_skills": True})

    result = await tool_implementations.do_manage_skills(
        json.dumps(
            {
                "action": "add",
                "name": "manual-local-runbook",
                "description": "Manual local runbook",
                "procedure": ["Do the thing explicitly"],
            }
        ),
        owner="alice",
    )

    assert "DRAFT" in result.get("results", "")
    assert _FakeSkillsManager.instances
    assert _FakeSkillsManager.instances[-1].added[-1]["status"] == "draft"
