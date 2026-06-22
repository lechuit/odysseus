"""Issue #3229 — allow_bash / allow_web_search must work for JSON API callers
and admin users must get bash enabled by default.

Bug: allow_bash and allow_web_search were only read from form_data, so JSON
API callers (Content-Type: application/json) always had bash disabled.

Fix: (1) Read from JSON body as fallback.
     (2) Only add bash/web_search to disabled_tools when explicitly set to a
         falsy value; when unset (None), defer to per-user privilege checks.
"""

import ast
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_CHAT_ROUTES = _ROOT / "routes" / "chat_routes.py"


# ── Source-level guards ─────────────────────────────────────────


def test_allow_bash_reads_from_body_as_fallback():
    """chat_stream must read allow_bash from the JSON body, not just form_data."""
    source = _CHAT_ROUTES.read_text(encoding="utf-8")
    tree = ast.parse(source)

    # Find the chat_stream function
    chat_stream_func = None
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "chat_stream":
            chat_stream_func = node
            break
    assert chat_stream_func is not None, "chat_stream function not found"

    # Look for an assignment to allow_bash that references 'body'
    found_body_fallback = False
    for node in ast.walk(chat_stream_func):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "allow_bash":
                    # Check if 'body' appears in the value
                    src_segment = ast.get_source_segment(source, node)
                    if src_segment and "body" in src_segment:
                        found_body_fallback = True
    assert found_body_fallback, (
        "allow_bash assignment in chat_stream must fall back to JSON body"
    )


def test_allow_web_search_reads_from_body_as_fallback():
    """chat_stream must read allow_web_search from the JSON body, not just form_data."""
    source = _CHAT_ROUTES.read_text(encoding="utf-8")
    tree = ast.parse(source)

    chat_stream_func = None
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "chat_stream":
            chat_stream_func = node
            break
    assert chat_stream_func is not None

    found_body_fallback = False
    for node in ast.walk(chat_stream_func):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "allow_web_search":
                    src_segment = ast.get_source_segment(source, node)
                    if src_segment and "body" in src_segment:
                        found_body_fallback = True
    assert found_body_fallback, (
        "allow_web_search assignment in chat_stream must fall back to JSON body"
    )


def test_disabled_tools_does_not_bash_when_allow_bash_is_none():
    """When allow_bash is not set (None), bash must NOT be unconditionally
    added to disabled_tools.  The per-user privilege check handles it.
    """
    source = _CHAT_ROUTES.read_text(encoding="utf-8")

    # The fix changes:
    #   if str(allow_bash).lower() != "true":
    # to:
    #   if allow_bash is not None and str(allow_bash).lower() != "true":
    assert "allow_bash is not None" in source, (
        "disabled_tools check must guard against allow_bash being None"
    )
    assert "allow_web_search is not None" in source, (
        "disabled_tools check must guard against allow_web_search being None"
    )
    assert "_explicit_web_intent" in source and "not _explicit_web_intent" in source, (
        "explicit web-search requests must override an off web toggle for that turn"
    )


def test_operation_permission_deny_short_circuits_agent_loop():
    """A Denegar reply is a permission-control event, not a fresh task.

    The route should stream a terminal assistant message directly instead of
    sending the denial label through memory/RAG/model/tool selection again.
    """
    source = _CHAT_ROUTES.read_text(encoding="utf-8")

    assert 'permission_resume_decision == "deny"' in source
    assert "_operation_permission_denied_stream" in source
    assert "return StreamingResponse(_operation_permission_denied_stream()" in source
    assert "Do not pass the label \"Denegar\" through context building" in source


def test_permission_ask_turns_disable_skill_extraction():
    """Permission prompts are security-control turns, not reusable workflows."""
    source = _CHAT_ROUTES.read_text(encoding="utf-8")

    assert "_agent_permission_requested = False" in source
    assert "_agent_permission_requested = True" in source
    assert "permission_request" in source
    assert "extract_skills=user_requested_agent and not _agent_permission_requested" in source


def test_permission_resume_note_is_inserted_after_permission_label():
    """The resume directive must be the newest instruction after an approval.

    Small local models can otherwise answer the low-signal label ("Permitir una
    vez") directly and fail to replay the approved tool.
    """
    source = _CHAT_ROUTES.read_text(encoding="utf-8")

    assert "_insert_at = _idx + 1" in source
    assert "replaying the approved operation" in source


def test_permission_resume_suppresses_unrelated_local_context():
    """Approval labels should replay only the approved operation.

    The resume turn must not inject skills/memories or automatically expose
    loop tools such as ask_user/update_plan, because those gave small local
    models enough surface area to wander into unrelated remembered tasks after
    the approved operation completed.
    """
    route_source = _CHAT_ROUTES.read_text(encoding="utf-8")
    agent_source = (_ROOT / "src" / "agent_loop.py").read_text(encoding="utf-8")

    assert "allow_tool_preprocessing = False" in route_source
    assert "no_memory = True" in route_source
    assert "use_rag = \"false\"" in route_source
    assert "if _permission_resume_context:" in agent_source
    assert "suppress_local_context = True" in agent_source
    assert "if not suppress_local_context:" in agent_source
    assert "permission_resume_operation=permission_resume_operation" in route_source
    assert "_tool_block_from_permission_operation(permission_resume_operation)" in agent_source
    assert "deterministic replay of approved" in agent_source
    assert 'tool_names |= {"ask_user", "update_plan"}' in agent_source
    assert "_permission_resume_tool_replayed = False" in agent_source
    assert "permission_resume_batch_done = True" in agent_source
    assert "forcing tool-free final answer" in agent_source
    assert "The approved operation has now executed" in agent_source


def test_literal_tool_control_turn_suppresses_memory_preprocessing():
    """Exact command/path turns should not be polluted by recalled memory."""
    route_source = _CHAT_ROUTES.read_text(encoding="utf-8")
    agent_source = (_ROOT / "src" / "agent_loop.py").read_text(encoding="utf-8")

    assert "def _is_literal_tool_control_turn" in route_source
    assert "def _literal_tool_control_relevant_tools" in route_source
    assert "def _explicit_single_tool_control_relevant_tools" in route_source
    assert "literal_tool_control = _is_literal_tool_control_turn(message)" in route_source
    assert "literal_tool_control_tools = (" in route_source
    assert "explicit_tool_control_tools = _explicit_single_tool_control_relevant_tools(message)" in route_source
    assert "strict_tool_control = bool(literal_tool_control or explicit_tool_control_tools)" in route_source
    assert "if permission_context_note or strict_tool_control:" in route_source
    assert "Suppressing memory/RAG/skills for literal tool-control turn" in route_source
    assert "Suppressing memory/RAG/skills for explicit single-tool turn" in route_source
    assert "relevant_tools=permission_resume_tools or strict_tool_control_tools" in route_source
    assert "suppress_local_context=bool(permission_context_note or strict_tool_control)" in route_source
    assert "strict_tool_turn=bool(strict_tool_control and not permission_context_note)" in route_source
    assert "strict_tool_turn: bool = False" in agent_source
    assert "The requested literal tool operation has now executed" in agent_source


# ── Functional tests of the disabled-tools logic ───────────────


def _build_disabled_tools(
    allow_bash=None,
    allow_web_search=None,
    can_use_bash=True,
    can_use_browser=True,
    explicit_web_intent=False,
):
    """Replicate the disabled-tools logic from chat_stream for unit testing.

    Returns the set of tool names that would be disabled.
    """
    disabled_tools = set()

    # Issue #3229 fix: only disable when explicitly set to a falsy value.
    if allow_bash is not None and str(allow_bash).lower() != "true":
        disabled_tools.add("bash")
    if (
        allow_web_search is not None
        and str(allow_web_search).lower() != "true"
        and not explicit_web_intent
    ):
        disabled_tools.add("web_search")
        disabled_tools.add("web_fetch")

    # Enforce per-user privileges
    if not can_use_bash:
        disabled_tools.update({"bash", "python", "read_file", "write_file"})
    if not can_use_browser:
        disabled_tools.add("builtin_browser")

    return disabled_tools


def test_json_body_allow_bash_true_enables_bash():
    """API caller sending {"allow_bash": true} gets bash enabled."""
    disabled = _build_disabled_tools(allow_bash="true")
    assert "bash" not in disabled


def test_json_body_allow_bash_false_disables_bash():
    """API caller sending {"allow_bash": false} gets bash disabled."""
    disabled = _build_disabled_tools(allow_bash="false")
    assert "bash" in disabled


def test_json_body_allow_web_search_true_enables_web():
    """API caller sending {"allow_web_search": true} gets web tools enabled."""
    disabled = _build_disabled_tools(allow_web_search="true")
    assert "web_search" not in disabled
    assert "web_fetch" not in disabled


def test_json_body_allow_web_search_false_disables_web():
    """API caller sending {"allow_web_search": false} gets web tools disabled."""
    disabled = _build_disabled_tools(allow_web_search="false")
    assert "web_search" in disabled
    assert "web_fetch" in disabled


def test_explicit_web_intent_overrides_false_web_toggle_for_turn():
    """A stale/off web toggle must not remove web tools when the message
    explicitly asks to use web search."""
    disabled = _build_disabled_tools(
        allow_web_search="false",
        explicit_web_intent=True,
    )
    assert "web_search" not in disabled
    assert "web_fetch" not in disabled


def test_admin_user_gets_bash_enabled_by_default():
    """When allow_bash is not set and user has can_use_bash privilege,
    bash must NOT be disabled.
    """
    disabled = _build_disabled_tools(allow_bash=None, can_use_bash=True)
    assert "bash" not in disabled


def test_admin_user_gets_web_search_enabled_by_default():
    """When allow_web_search is not set and user has normal privileges,
    web_search must NOT be disabled.
    """
    disabled = _build_disabled_tools(allow_web_search=None)
    assert "web_search" not in disabled
    assert "web_fetch" not in disabled


def test_non_privileged_user_without_explicit_flag_still_disabled():
    """A user without can_use_bash privilege who doesn't send allow_bash
    should still have bash disabled via the privilege check.
    """
    disabled = _build_disabled_tools(allow_bash=None, can_use_bash=False)
    assert "bash" in disabled


def test_non_privileged_user_explicit_true_overridden_by_privilege():
    """Even if allow_bash=true is sent, a user without can_use_bash
    privilege still gets bash disabled by the privilege gate.
    """
    disabled = _build_disabled_tools(allow_bash="true", can_use_bash=False)
    assert "bash" in disabled


def test_form_data_none_body_true_works():
    """Simulates: form_data has no allow_bash, body has allow_bash=true.
    After the fallback (`form_data.get(...) or body.get(...)`), allow_bash
    should be "true".
    """
    # Simulate the fallback logic
    form_data_val = None  # not in form_data
    body_val = "true"     # from JSON body
    allow_bash = form_data_val or body_val
    assert str(allow_bash).lower() == "true"

    disabled = _build_disabled_tools(allow_bash=allow_bash)
    assert "bash" not in disabled


def test_explicit_false_disables_even_for_admin():
    """An admin who explicitly sends allow_bash=false should have bash disabled."""
    disabled = _build_disabled_tools(
        allow_bash="false", can_use_bash=True,
    )
    assert "bash" in disabled


# ── Frontend source-level guards ──────────────────────────────

_CHAT_JS = Path(__file__).resolve().parent.parent / "static" / "js" / "chat.js"


def test_frontend_always_sends_explicit_allow_bash():
    """chat.js must always send allow_bash (both true and false), not only on toggle ON."""
    source = _CHAT_JS.read_text(encoding="utf-8")
    # Must not only append 'true' — must also handle the false case
    assert "allow_bash', el('bash-toggle').checked ? 'true' : 'false'" in source or \
           "allow_bash', 'false'" in source, (
        "Frontend must send explicit allow_bash=false when toggle is off"
    )


def test_frontend_sends_explicit_allow_web_search_false_in_agent_mode():
    """chat.js must send allow_web_search=false when web toggle is off in agent mode."""
    source = _CHAT_JS.read_text(encoding="utf-8")
    assert "allow_web_search', 'false'" in source, (
        "Frontend must send explicit allow_web_search=false in agent mode when toggle is off"
    )
