import pytest
from fastapi import HTTPException
from types import SimpleNamespace

from routes.chat_helpers import (
    PresetInfo,
    PreprocessedMessage,
    _enforce_chat_privileges,
    build_chat_context,
    clean_thinking_for_save,
    needs_auto_name,
    save_assistant_response,
)


class _AuthManager:
    def __init__(self, privileges):
        self._privileges = privileges

    def get_privileges(self, username):
        assert username == "alice"
        return self._privileges


class _Request:
    def __init__(self, privileges):
        self.app = type("App", (), {})()
        self.app.state = type("State", (), {"auth_manager": _AuthManager(privileges)})()


class _Session:
    def __init__(self, model):
        self.model = model


def test_allowed_models_legacy_empty_list_remains_unrestricted(monkeypatch):
    monkeypatch.setattr("routes.chat_helpers.get_current_user", lambda request: "alice")

    _enforce_chat_privileges(
        _Request({"allowed_models": [], "max_messages_per_day": 0}),
        _Session("provider/model-a"),
    )


def test_allowed_models_explicit_empty_restricted_list_blocks_all_models(monkeypatch):
    monkeypatch.setattr("routes.chat_helpers.get_current_user", lambda request: "alice")

    with pytest.raises(HTTPException) as exc:
        _enforce_chat_privileges(
            _Request({
                "allowed_models": [],
                "allowed_models_restricted": True,
                "max_messages_per_day": 0,
            }),
            _Session("provider/model-a"),
        )

    assert exc.value.status_code == 403
    assert "provider/model-a" in exc.value.detail


def test_allowed_models_nonempty_list_still_restricts_without_new_flag(monkeypatch):
    monkeypatch.setattr("routes.chat_helpers.get_current_user", lambda request: "alice")

    _enforce_chat_privileges(
        _Request({"allowed_models": ["provider/model-a"], "max_messages_per_day": 0}),
        _Session("provider/model-a"),
    )
    with pytest.raises(HTTPException):
        _enforce_chat_privileges(
            _Request({"allowed_models": ["provider/model-a"], "max_messages_per_day": 0}),
            _Session("provider/model-b"),
        )


def test_no_restriction_allows_any_model(monkeypatch):
    monkeypatch.setattr("routes.chat_helpers.get_current_user", lambda request: "alice")

    privs = {"allowed_models": [], "block_all_models": False, "max_messages_per_day": 0}
    _enforce_chat_privileges(_Request(privs), _Session("provider/model-a"))
    _enforce_chat_privileges(_Request(privs), _Session("provider/model-z"))


def test_specific_allowlist_blocks_models_outside_it(monkeypatch):
    monkeypatch.setattr("routes.chat_helpers.get_current_user", lambda request: "alice")

    privs = {
        "allowed_models": ["gpt-4"],
        "block_all_models": False,
        "max_messages_per_day": 0,
    }
    _enforce_chat_privileges(_Request(privs), _Session("gpt-4"))
    with pytest.raises(HTTPException) as exc:
        _enforce_chat_privileges(_Request(privs), _Session("gpt-3.5"))
    assert exc.value.status_code == 403


def test_block_all_models_blocks_regardless_of_allowed_models_contents(monkeypatch):
    monkeypatch.setattr("routes.chat_helpers.get_current_user", lambda request: "alice")

    # Even if allowed_models contains entries, block_all_models wins.
    privs = {
        "allowed_models": ["gpt-4", "gpt-3.5"],
        "block_all_models": True,
        "max_messages_per_day": 0,
    }
    with pytest.raises(HTTPException) as exc:
        _enforce_chat_privileges(_Request(privs), _Session("gpt-4"))
    assert exc.value.status_code == 403

    with pytest.raises(HTTPException):
        _enforce_chat_privileges(_Request(privs), _Session("anything-else"))


def test_admin_user_is_never_blocked(monkeypatch):
    from core.auth import ADMIN_PRIVILEGES

    monkeypatch.setattr("routes.chat_helpers.get_current_user", lambda request: "admin")

    class _AdminAuthManager:
        def get_privileges(self, username):
            assert username == "admin"
            return dict(ADMIN_PRIVILEGES)

    class _AdminRequest:
        def __init__(self):
            self.app = type("App", (), {})()
            self.app.state = type("State", (), {"auth_manager": _AdminAuthManager()})()

    _enforce_chat_privileges(_AdminRequest(), _Session("provider/model-a"))
    _enforce_chat_privileges(_AdminRequest(), _Session("anything-else"))


class _FakeSession:
    def __init__(self, model="selected-model"):
        self.model = model
        self.history = []

    def add_message(self, message):
        self.history.append(message)


@pytest.mark.parametrize("name,expected", [
    # 24h format (the bug this PR fixes)
    ("deepseek-v4-flash 14:05:33", True),
    ("qwq 17:46:02", True),
    ("gemma3 23:59:59", True),
    ("claude-sonnet 4 0:00:00", True),

    # 12h format (was already working)
    ("deepseek-v4-flash 2:05:33 PM", True),
    ("qwq 06:46:02 AM", True),
    ("claude-sonnet-4 8:05:17 am", True),

    # empty / default
    ("", True),
    ("  ", False),
    ("Chat: something", True),

    # custom titles – should NOT trigger auto-naming
    ("custom title", False),
    ("CW Decoder for STM32", False),
    ("my chat about python", False),
    ("Fix the login bug", False),
])
def test_needs_auto_name(name, expected):
    assert needs_auto_name(name) == expected, f"needs_auto_name({name!r}) should be {expected}"


def test_clean_thinking_for_save_extracts_gemma4_thought_channel():
    content, metadata = clean_thinking_for_save(
        "<|channel>thought\ninternal reasoning<channel|>Final answer.",
        {"model": "google/gemma-4-31B-it"},
    )

    assert content == "Final answer."
    assert metadata["thinking"] == "internal reasoning"
    assert metadata["model"] == "google/gemma-4-31B-it"


def test_clean_thinking_for_save_strips_empty_gemma4_thought_channel():
    content, metadata = clean_thinking_for_save(
        "<|channel>thought\n<channel|>Final answer.",
        {"model": "google/gemma-4-31B-it"},
    )

    assert content == "Final answer."
    assert "thinking" not in metadata


def test_clean_thinking_for_save_unwraps_gemma4_response_channel():
    content, metadata = clean_thinking_for_save(
        "<|channel>thought\ninternal reasoning<channel|><|channel>response\nFinal answer.<channel|>",
        {"model": "google/gemma-4-31B-it"},
    )

    assert content == "Final answer."
    assert metadata["thinking"] == "internal reasoning"


def test_clean_thinking_for_save_extracts_thought_tag():
    content, metadata = clean_thinking_for_save(
        "<thought>internal reasoning</thought>Final answer.",
        {},
    )

    assert content == "Final answer."
    assert metadata["thinking"] == "internal reasoning"


def test_save_assistant_response_preserves_actual_and_requested_model():
    sess = _FakeSession("selected-model")

    save_assistant_response(
        sess,
        session_manager=None,
        session_id="s1",
        full_response="hello",
        last_metrics={"model": "actual-model", "input_tokens": 1, "output_tokens": 2},
        incognito=True,
    )

    assert sess.history[-1].metadata["requested_model"] == "selected-model"
    assert sess.history[-1].metadata["model"] == "actual-model"


from routes.chat_helpers import _session_is_research_spinoff


class _SpinMsg:
    def __init__(self, role, metadata=None):
        self.role = role
        self.metadata = metadata


def test_spinoff_detected_from_chatmessage_history():
    sess = SimpleNamespace(history=[
        _SpinMsg("system", {"research_spinoff_from": "rp-1"}),
        _SpinMsg("user", None),
    ])
    assert _session_is_research_spinoff(sess) is True


def test_spinoff_detected_from_dict_history():
    sess = SimpleNamespace(history=[
        {"role": "system", "metadata": {"research_spinoff_from": "rp-2"}},
        {"role": "user", "content": "hi"},
    ])
    assert _session_is_research_spinoff(sess) is True


def test_non_spinoff_plain_session_is_false():
    sess = SimpleNamespace(history=[
        _SpinMsg("system", {"compacted": True}),
        _SpinMsg("user", None),
    ])
    assert _session_is_research_spinoff(sess) is False


def test_metadata_on_non_system_message_ignored():
    sess = SimpleNamespace(history=[_SpinMsg("user", {"research_spinoff_from": "rp-3"})])
    assert _session_is_research_spinoff(sess) is False


@pytest.mark.asyncio
async def test_build_chat_context_uses_active_boundary_projection(monkeypatch):
    history = [
        {"role": "user", "content": "old secret marker", "metadata": {"_db_id": "m1"}},
        {"role": "assistant", "content": "old reply", "metadata": {"_db_id": "m2"}},
        {"role": "user", "content": "tail marker", "metadata": {"_db_id": "m3"}},
        {"role": "assistant", "content": "tail reply", "metadata": {"_db_id": "m4"}},
    ]
    sess = SimpleNamespace(
        endpoint_url="http://local/v1",
        model="local-model",
        headers={},
        history=history,
        active_context_boundary_message_id="m3",
        active_context_summary="Earlier setup summarized without the old marker.",
    )
    sess.get_context_messages = lambda: sess.history

    async def fake_preprocess(chat_handler, message, att_ids, sess, **kwargs):
        return PreprocessedMessage(
            enhanced_message=message,
            user_content=message,
            text_for_context=message,
            youtube_transcripts=[],
            attachment_meta=[],
        )

    def fake_add_user_message(sess, chat_handler, preprocessed, incognito=False):
        sess.history.append({
            "role": "user",
            "content": preprocessed.user_content,
            "metadata": {"_db_id": "m5"},
        })

    def fake_extract_preset(chat_handler, preset_id):
        return PresetInfo(
            temperature=0.7,
            max_tokens=1024,
            system_prompt="You are Odysseus.",
            character_name=None,
        )

    async def fake_maybe_compact(sess, endpoint_url, model, messages, headers, owner=None):
        return messages, 8192, False

    monkeypatch.setattr("routes.chat_helpers.preprocess", fake_preprocess)
    monkeypatch.setattr("routes.chat_helpers.add_user_message", fake_add_user_message)
    monkeypatch.setattr("routes.chat_helpers.extract_preset", fake_extract_preset)
    monkeypatch.setattr("routes.chat_helpers.load_prefs_for_user", lambda user: {})
    monkeypatch.setattr("routes.chat_helpers.get_current_user", lambda request: "tester")
    monkeypatch.setattr("routes.chat_helpers.normalize_model_id", lambda *a, **k: None)
    monkeypatch.setattr("routes.chat_helpers.maybe_compact", fake_maybe_compact)
    monkeypatch.setattr("routes.chat_helpers.trim_for_context", lambda messages, context_length: messages)

    chat_processor = SimpleNamespace(
        build_context_preface=lambda **kwargs: ([{"role": "system", "content": kwargs["preset_system_prompt"]}], [], [])
    )

    ctx = await build_chat_context(
        sess=sess,
        request=SimpleNamespace(),
        chat_handler=SimpleNamespace(),
        chat_processor=chat_processor,
        message="latest question",
        session_id="s-active-boundary",
        agent_mode=True,
    )

    model_text = "\n".join(str(m.get("content") or "") for m in ctx.messages)
    assert "Earlier setup summarized without the old marker." in model_text
    assert "tail marker" in model_text
    assert "latest question" in model_text
    assert "old secret marker" not in model_text
    assert sess.history[0]["content"] == "old secret marker"
    assert ctx.context_projection["mode"] == "active_boundary"
    assert ctx.context_projection["active_boundary_used"] is True
    assert ctx.context_projection["history_messages_before"] == 5
    assert ctx.context_projection["history_messages_after"] == 4


def test_empty_or_missing_history():
    assert _session_is_research_spinoff(SimpleNamespace(history=[])) is False
    assert _session_is_research_spinoff(SimpleNamespace()) is False
