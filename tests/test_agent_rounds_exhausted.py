"""Regression: stream_agent_loop emits `rounds_exhausted` only when the round
cap is hit while still working, and NOT on a normal finish.

The decision is a `for/else` in the loop: the `else` runs only if no `break`
fired (break = done / budget / error). A refactor that adds a stray break or
return, or moves the done-break, could silently flip this. See PR #1999 / #1997.
"""

import asyncio
import json

import src.agent_loop as al

_STEP_LIMIT_PROMPT = (
    "You hit the step limit before finishing — the task is not complete. "
    "Continue from exactly where you left off and keep going until it is done. "
    "Do NOT repeat work already done."
)


def _collect(gen):
    async def _run():
        return [c async for c in gen]
    return asyncio.run(_run())


def _types(chunks):
    out = []
    for c in chunks:
        if c.startswith("data: ") and not c.startswith("data: [DONE]"):
            try:
                out.append(json.loads(c[6:]))
            except Exception:
                pass
    return out


def _patch_common(monkeypatch):
    # Skip RAG/tool-index, MCP, and settings lookups; keep the real loop body,
    # _resolve_tool_blocks, and parse_tool_blocks.
    monkeypatch.setattr(al, "get_setting", lambda key, default=None: default, raising=False)
    monkeypatch.setattr(al, "get_mcp_manager", lambda: None, raising=False)
    monkeypatch.setattr(al, "estimate_tokens", lambda *a, **k: 10, raising=False)

    async def _fake_exec(block, *a, **k):
        return ("bash", {"output": "ok", "exit_code": 0})
    monkeypatch.setattr(al, "execute_tool_block", _fake_exec, raising=False)


def _run_loop(monkeypatch, round_text, max_rounds=2):
    async def _fake_stream(_candidates, messages, **kwargs):
        yield f'data: {json.dumps({"delta": round_text})}\n\n'
        yield "data: [DONE]\n\n"
    monkeypatch.setattr(al, "stream_llm_with_fallback", _fake_stream, raising=False)

    gen = al.stream_agent_loop(
        "http://x/v1", "m",
        [{"role": "user", "content": "do a long multi-step task"}],
        max_rounds=max_rounds,
        relevant_tools={"bash"},
    )
    return _types(_collect(gen))


def test_emits_rounds_exhausted_when_cap_hit_mid_task(monkeypatch):
    _patch_common(monkeypatch)
    # Every round returns a tool block -> never "done" -> loop exhausts the cap.
    events = _run_loop(monkeypatch, "```bash\necho hi\n```", max_rounds=2)
    assert any(e.get("type") == "rounds_exhausted" for e in events), events


def test_rounds_exhausted_event_includes_continue_prompt(monkeypatch):
    _patch_common(monkeypatch)

    events = _run_loop(monkeypatch, "```bash\necho hi\n```", max_rounds=2)
    event = next(e for e in events if e.get("type") == "rounds_exhausted")

    assert event["rounds"] == 2
    assert "continue_prompt" in event
    assert "Continue from exactly where you left off" in event["continue_prompt"]
    assert "Original user request to continue:" in event["continue_prompt"]
    assert "do a long multi-step task" in event["continue_prompt"]


def test_no_rounds_exhausted_on_normal_finish(monkeypatch):
    _patch_common(monkeypatch)
    # A plain answer (no tool block) -> done-break on round 1 -> no event.
    events = _run_loop(monkeypatch, "All done, here is your answer.", max_rounds=2)
    assert not any(e.get("type") == "rounds_exhausted" for e in events), events


def test_round_limit_continue_inherits_previous_user_turn():
    messages = [
        {"role": "user", "content": "Corrige el fallo en este proyecto y verifica con bash."},
        {"role": "assistant", "content": "Estoy trabajando en ello."},
        {"role": "user", "content": _STEP_LIMIT_PROMPT},
    ]

    intent = al._classify_agent_request(messages, _STEP_LIMIT_PROMPT)

    assert intent["continuation"] is True
    assert "Corrige el fallo" in intent["retrieval_query"]
    assert "step limit" not in intent["retrieval_query"].lower()
    assert "files" in intent["domains"]
    assert al._looks_like_workspace_write_request(intent["retrieval_query"])


def test_round_limit_continue_can_use_embedded_original_request_without_history():
    prompt = al._build_round_limit_continue_prompt(
        "Corrige el fallo en este proyecto y verifica con bash.",
        "/tmp/slideshare-downloader",
        {"get_workspace", "ls", "glob", "grep", "read_file", "edit_file", "write_file", "bash", "python"},
    )
    messages = [{"role": "user", "content": prompt}]

    intent = al._classify_agent_request(messages, prompt)

    assert intent["continuation"] is True
    assert "Corrige el fallo" in intent["retrieval_query"]
    assert "files" in intent["domains"]
    assert al._looks_like_workspace_write_request(intent["retrieval_query"])


def test_round_limit_continue_does_not_trigger_admin_from_task_word():
    assert al._detect_admin_intent([{"role": "user", "content": _STEP_LIMIT_PROMPT}]) is False


def test_workspace_round_limit_continue_keeps_write_tools_and_suppresses_skills(monkeypatch):
    _patch_common(monkeypatch)

    import services.memory.skills as skills_mod
    import src.tool_index as tool_index

    class FakeSkillsManager:
        def __init__(self, *args, **kwargs):
            pass

        def index_for(self, *args, **kwargs):
            return [{
                "name": "debug-workflow",
                "category": "debug",
                "description": "Debug workflow",
                "requires_toolsets": [],
            }]

        def load(self, *args, **kwargs):
            return self.index_for()

        def get_relevant_skills(self, *args, **kwargs):
            return []

    monkeypatch.setattr(skills_mod, "SkillsManager", FakeSkillsManager, raising=False)
    monkeypatch.setattr(tool_index, "get_tool_index", lambda: None, raising=False)
    monkeypatch.setattr(al, "blocked_tools_for_owner", lambda owner: set(), raising=False)

    captured_tool_names = []

    async def fake_stream(_candidates, messages, **kwargs):
        captured_tool_names.append({
            t.get("function", {}).get("name")
            for t in (kwargs.get("tools") or [])
            if t.get("function")
        })
        yield f'data: {json.dumps({"delta": "Listo."})}\n\n'
        yield "data: [DONE]\n\n"

    monkeypatch.setattr(al, "stream_llm_with_fallback", fake_stream, raising=False)

    messages = [
        {"role": "user", "content": "Corrige el fallo en este proyecto y verifica con bash."},
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [{
                "id": "call_1",
                "type": "function",
                "function": {"name": "write_file", "arguments": "{}"},
            }],
        },
        {"role": "tool", "tool_call_id": "call_1", "content": "write_file: ok"},
        {"role": "user", "content": _STEP_LIMIT_PROMPT},
    ]

    _collect(al.stream_agent_loop(
        "http://localhost:8000/v1",
        "gemma4-v2-Q4_K_M.gguf",
        messages,
        max_rounds=1,
        workspace="/tmp/slideshare-downloader",
    ))

    assert captured_tool_names
    sent = captured_tool_names[0]
    assert {"get_workspace", "ls", "glob", "grep", "read_file"} <= sent
    assert {"edit_file", "write_file", "bash", "python"} <= sent
    assert "manage_skills" not in sent
