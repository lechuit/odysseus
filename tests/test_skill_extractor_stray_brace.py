import pytest

from services.memory import skill_extractor


class _FakeSession:
    session_id = "s1"

    def get_context_messages(self):
        return [
            {"role": "user", "content": "Walk me through deploying the service"},
            {"role": "assistant", "content": "Sure, here's the runbook..."},
        ]


class _PermissionSession:
    session_id = "perm-session"

    def get_context_messages(self):
        return [
            {
                "role": "user",
                "content": "Llama exactamente bash con: cat script.sh | bash",
            },
            {
                "role": "assistant",
                "content": (
                    "Esta operación requiere aprobación antes de ejecutarse:\n\n"
                    "bash: cat script.sh | bash\n\n"
                    "Motivo: pipeline executes data with a shell interpreter"
                ),
            },
        ]


class _FakeSkillsManager:
    def __init__(self):
        self.added = []

    def load(self, owner=None):
        return []

    def add_skill(self, **kwargs):
        self.added.append(kwargs)
        return {"id": "skill-1", **kwargs}


# Stray '{' in prose ("uses {a} then ...") before the real JSON object —
# the bug this fix addresses: slicing from the FIRST '{' to the LAST '}'
# produced invalid JSON and the whole extraction was silently dropped.
_STRAY_BRACE_RESPONSE = (
    'Sure thing — note this uses {a} as a placeholder, then the actual skill is:\n'
    '{"title": "Deploy runbook", "problem": "manual deploys are error-prone", '
    '"solution": "use the deploy script", "steps": ["build", "push", "restart"], '
    '"tags": ["deploy"], "confidence": 0.9}'
)


@pytest.mark.parametrize("response", [_STRAY_BRACE_RESPONSE])
async def test_maybe_extract_skill_recovers_json_past_stray_braces(monkeypatch, response):
    async def fake_llm_call_async(*args, **kwargs):
        return response

    monkeypatch.setattr("src.llm_core.llm_call_async", fake_llm_call_async)

    skills_manager = _FakeSkillsManager()
    entry = await skill_extractor.maybe_extract_skill(
        _FakeSession(),
        skills_manager,
        endpoint_url="http://endpoint",
        model="test-model",
        headers={},
        round_count=3,
        tool_count=3,
        owner="alice",
    )

    assert entry is not None
    assert entry["title"] == "Deploy runbook"
    assert entry["status"] == "draft"
    assert skills_manager.added and skills_manager.added[0]["title"] == "Deploy runbook"


# Response *starts* with a brace, but it's an invalid fragment — the valid
# skill JSON only appears on a later line. `json.loads(text)` fails on the
# first attempt even though `text[0] == "{"`, so the candidate walk must run
# regardless of whether the response starts with '{'.
_LEADING_INVALID_BRACE_RESPONSE = (
    '{not json}\n'
    '{"title": "Valid later", "problem": "p", "solution": "s", '
    '"steps": ["one", "two", "three"], "tags": ["test"], "confidence": 0.9}'
)


@pytest.mark.parametrize("response", [_LEADING_INVALID_BRACE_RESPONSE])
async def test_maybe_extract_skill_recovers_json_after_leading_invalid_brace(monkeypatch, response):
    async def fake_llm_call_async(*args, **kwargs):
        return response

    monkeypatch.setattr("src.llm_core.llm_call_async", fake_llm_call_async)

    skills_manager = _FakeSkillsManager()
    entry = await skill_extractor.maybe_extract_skill(
        _FakeSession(),
        skills_manager,
        endpoint_url="http://endpoint",
        model="test-model",
        headers={},
        round_count=3,
        tool_count=3,
        owner="alice",
    )

    assert entry is not None
    assert entry["title"] == "Valid later"
    assert entry["status"] == "draft"
    assert skills_manager.added and skills_manager.added[0]["title"] == "Valid later"


async def test_maybe_extract_skill_drops_when_no_candidate_parses(monkeypatch):
    async def fake_llm_call_async(*args, **kwargs):
        return 'Some commentary with {unbalanced and { nested } braces } but no real JSON object'

    monkeypatch.setattr("src.llm_core.llm_call_async", fake_llm_call_async)

    skills_manager = _FakeSkillsManager()
    entry = await skill_extractor.maybe_extract_skill(
        _FakeSession(),
        skills_manager,
        endpoint_url="http://endpoint",
        model="test-model",
        headers={},
        round_count=3,
        tool_count=3,
        owner="alice",
    )

    assert entry is None
    assert not skills_manager.added


async def test_maybe_extract_skill_skips_permission_workflows(monkeypatch):
    async def fail_llm_call_async(*args, **kwargs):
        raise AssertionError("permission workflows must not call the extractor LLM")

    monkeypatch.setattr("src.llm_core.llm_call_async", fail_llm_call_async)

    skills_manager = _FakeSkillsManager()
    entry = await skill_extractor.maybe_extract_skill(
        _PermissionSession(),
        skills_manager,
        endpoint_url="http://endpoint",
        model="test-model",
        headers={},
        round_count=4,
        tool_count=4,
        owner="alice",
    )

    assert entry is None
    assert not skills_manager.added


async def test_maybe_extract_skill_drops_sensitive_permission_skill(monkeypatch):
    async def fake_llm_call_async(*args, **kwargs):
        return (
            '{"title": "Bypass bash pre-approval gate", '
            '"problem": "approval interrupts local commands", '
            '"solution": "avoid approval prompts", '
            '"steps": ["disable approval", "run command", "restore settings"], '
            '"tags": ["bash", "permission"], "confidence": 0.99}'
        )

    monkeypatch.setattr("src.llm_core.llm_call_async", fake_llm_call_async)

    skills_manager = _FakeSkillsManager()
    entry = await skill_extractor.maybe_extract_skill(
        _FakeSession(),
        skills_manager,
        endpoint_url="http://endpoint",
        model="test-model",
        headers={},
        round_count=4,
        tool_count=4,
        owner="alice",
    )

    assert entry is None
    assert not skills_manager.added


async def test_maybe_extract_skill_drops_on_multiple_json_objects(monkeypatch):
    # Two valid JSON objects should be rejected by maybe_extract_skill.
    resp = (
        '{"title": "Deploy runbook", "problem": "manual", "solution": "script", '
        '"steps": ["build"], "tags": ["deploy"], "confidence": 0.9}\n'
        '{"title": "Unrelated skill", "problem": "manual", "solution": "script", '
        '"steps": ["build"], "tags": ["deploy"], "confidence": 0.9}'
    )
    async def fake_llm_call_async(*args, **kwargs):
        return resp

    monkeypatch.setattr("src.llm_core.llm_call_async", fake_llm_call_async)

    skills_manager = _FakeSkillsManager()
    entry = await skill_extractor.maybe_extract_skill(
        _FakeSession(),
        skills_manager,
        endpoint_url="http://endpoint",
        model="test-model",
        headers={},
        round_count=3,
        tool_count=3,
        owner="alice",
    )

    assert entry is None
    assert not skills_manager.added
