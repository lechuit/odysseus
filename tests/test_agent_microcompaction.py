"""Regression tests for per-round agent tool-history microcompaction."""

import json
import sys
from unittest.mock import MagicMock


for mod in [
    "sqlalchemy", "sqlalchemy.orm", "sqlalchemy.ext", "sqlalchemy.ext.declarative",
    "sqlalchemy.ext.hybrid", "sqlalchemy.sql", "sqlalchemy.sql.expression",
    "src.database",
    "core.models", "core.database",
]:
    if mod not in sys.modules:
        sys.modules[mod] = MagicMock()


from src.context_compactor import (  # noqa: E402
    MICROCOMPACT_CLEARED_MESSAGE,
    MICROCOMPACT_TRUNCATED_ARGS_KEY,
    microcompact_tool_history,
)
from src.model_context import estimate_tokens  # noqa: E402


def _native_pair(i, *, name="bash", result=None, args=None, extra_content=None):
    call_id = f"call_{i}"
    tc = {
        "id": call_id,
        "type": "function",
        "function": {
            "name": name,
            "arguments": args if args is not None else json.dumps({"cmd": "x" * 2000}),
        },
    }
    if extra_content:
        tc["extra_content"] = extra_content
    return [
        {"role": "assistant", "content": None, "tool_calls": [tc]},
        {
            "role": "tool",
            "tool_call_id": call_id,
            "content": result if result is not None else f"result-{i}\n" + ("x" * 2400),
        },
    ]


def test_microcompact_disabled_when_budget_is_zero():
    messages = [{"role": "tool", "tool_call_id": "c", "content": "x" * 5000}]

    compacted, stats = microcompact_tool_history(messages, input_budget=0)

    assert compacted is messages
    assert stats["passes"] == 0


def test_microcompact_native_history_preserves_recent_error_plan_and_signatures():
    messages = [{"role": "system", "content": "You are Odysseus."}]
    for i in range(12):
        if i == 0:
            messages.extend(_native_pair(
                i,
                extra_content={"google": {"thought_signature": "abc"}},
            ))
        elif i == 1:
            messages.extend(_native_pair(i, name="update_plan"))
        elif i == 2:
            messages.extend(_native_pair(i, result="ERROR: command failed\n" + ("e" * 2400)))
        else:
            messages.extend(_native_pair(i))

    before = estimate_tokens(messages)
    compacted, stats = microcompact_tool_history(messages, input_budget=6000, reserve_tokens=0)

    assert stats["passes"] == 1
    assert stats["results_cleared"] >= 1
    assert stats["arguments_compacted"] >= 1
    assert estimate_tokens(compacted) < before

    # Old normal result cleared; matching native args compacted without dropping
    # IDs, function name, or Gemini extra_content/thought signature.
    assert compacted[2]["content"] == MICROCOMPACT_CLEARED_MESSAGE
    first_tc = compacted[1]["tool_calls"][0]
    assert first_tc["id"] == "call_0"
    assert first_tc["function"]["name"] == "bash"
    assert first_tc["extra_content"] == {"google": {"thought_signature": "abc"}}
    compacted_args = json.loads(first_tc["function"]["arguments"])
    assert compacted_args[MICROCOMPACT_TRUNCATED_ARGS_KEY] is True

    # Protected plan output and most recent error remain complete.
    joined = "\n".join(str(m.get("content", "")) for m in compacted)
    assert "result-1" in joined  # update_plan
    assert "ERROR: command failed" in joined

    # The five most recent tool results and the latest batch remain complete.
    for i in range(7, 12):
        assert f"result-{i}" in joined
        assert any(
            m.get("role") == "tool"
            and m.get("tool_call_id") == f"call_{i}"
            and m.get("content", "").startswith(f"result-{i}")
            for m in compacted
        )


def test_microcompact_native_history_only_clears_allowlisted_tools():
    non_compactable_args = json.dumps({"uid": "email-1", "body_hint": "z" * 3000})
    messages = [{"role": "system", "content": "You are Odysseus."}]
    messages.extend(_native_pair(
        0,
        name="read_email",
        result="important email body\n" + ("e" * 2600),
        args=non_compactable_args,
    ))
    messages.extend(_native_pair(
        1,
        name="chat_with_model",
        result="teacher/model answer\n" + ("m" * 2600),
        args=json.dumps({"prompt": "z" * 3000}),
    ))
    for i in range(2, 11):
        messages.extend(_native_pair(i, name="bash"))

    compacted, stats = microcompact_tool_history(messages, input_budget=6000, reserve_tokens=0)

    assert stats["passes"] == 1
    assert "important email body" in "\n".join(str(m.get("content", "")) for m in compacted)
    assert "teacher/model answer" in "\n".join(str(m.get("content", "")) for m in compacted)
    assert compacted[1]["tool_calls"][0]["function"]["arguments"] == non_compactable_args
    assert any(
        m.get("role") == "tool"
        and m.get("content") == MICROCOMPACT_CLEARED_MESSAGE
        for m in compacted
    )


def test_microcompact_textual_tool_results_by_section_and_is_idempotent():
    def section(name, label):
        return f"### {name}\n{label}\n" + ("x" * 2400) + "\n\n"

    old_sections = [
        section("read_email", "old-email"),
        section("chat_with_model", "old-model"),
        section("bash", "old-0"),
        section("update_plan", "old-plan"),
        section("python", "ERROR: old failure"),
        section("bash", "old-3"),
        section("bash", "old-4"),
        section("bash", "old-5"),
        section("bash", "old-6"),
        section("bash", "old-7"),
    ]
    messages = [
        {"role": "system", "content": "You are Odysseus."},
        {"role": "user", "content": "[Tool execution results]\n\n" + "".join(old_sections)},
        {"role": "assistant", "content": "continuing"},
        {"role": "user", "content": "[Tool execution results]\n\n" + section("bash", "latest-batch")},
    ]

    compacted, stats = microcompact_tool_history(messages, input_budget=5000, reserve_tokens=0)

    assert stats["passes"] == 1
    text = compacted[1]["content"]
    assert "old-0" not in text
    assert "old-3" not in text
    assert "old-email" in text
    assert "old-model" in text
    assert text.count(MICROCOMPACT_CLEARED_MESSAGE) >= 2
    assert "old-plan" in text
    assert "ERROR: old failure" in text
    # Last five sections overall are old-4..old-7 plus latest-batch.
    for label in ("old-4", "old-5", "old-6", "old-7"):
        assert label in text
    assert "latest-batch" in compacted[-1]["content"]

    compacted_again, stats_again = microcompact_tool_history(compacted, input_budget=5000, reserve_tokens=0)
    assert compacted_again == compacted
    assert stats_again["passes"] == 0
