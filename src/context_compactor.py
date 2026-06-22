"""
context_compactor.py

Auto-compacts conversation history when approaching context window limits.
Summarizes older messages via the same LLM, preserving key context.
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional

from src.model_context import get_context_length, estimate_tokens
from src.llm_core import llm_call_async
from src.endpoint_resolver import resolve_endpoint
from src.prompt_security import untrusted_context_message
from core.models import ChatMessage

logger = logging.getLogger(__name__)


def _content_as_text(content: Any) -> str:
    """Flatten a message's content to plain text.

    Handles the three shapes that flow through history: a plain string, a
    multimodal list of content blocks (vision/image attachments), and None
    (assistant turns that carried only native tool_calls persist content as
    None). Returns "" for anything without text so callers can safely slice
    the result.
    """
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(
            b.get("text", "") for b in content
            if isinstance(b, dict) and b.get("text")
        )
    return ""


COMPACT_THRESHOLD = 0.85  # Trigger compaction at 85% of context window
SUMMARY_MAX_TOKENS = 1024
SMALL_CONTEXT_LIMIT = 8192  # Models with context <= this get aggressive trimming

MICROCOMPACT_TRIGGER_RATIO = 0.70
MICROCOMPACT_TARGET_RATIO = 0.55
MICROCOMPACT_KEEP_RECENT_TOOL_RESULTS = 5
MICROCOMPACT_MIN_RESULT_TOKENS = 256
MICROCOMPACT_CLEARED_MESSAGE = "[Old tool result content cleared to preserve context]"
MICROCOMPACT_TRUNCATED_ARGS_KEY = "_microcompacted_for_context"
_TOOL_RESULTS_PREFIX = "[Tool execution results]"
_PROTECTED_MICROCOMPACT_TOOLS = {"update_plan", "ask_user"}
MICROCOMPACT_COMPACTABLE_TOOLS = {
    "bash",
    "python",
    "read_file",
    "write_file",
    "edit_file",
    "grep",
    "glob",
    "ls",
    "get_workspace",
    "web_search",
    "web_fetch",
}

# Cursor-style self-summarization prompt — produces structured, dense summaries
SELF_SUMMARY_SYSTEM_PROMPT = """You are summarizing a conversation to preserve context after compaction. Produce a structured summary that lets the conversation continue seamlessly.

Use this format:

## Conversation Summary
**Turns summarized:** {count}  |  **Compactions so far:** {n}

### User Goal
One sentence describing what the user is trying to accomplish.

### What Was Done
- Bullet points of completed actions, decisions made, and key outputs
- Include specific file paths, function names, variable names, URLs, and config values
- Note any errors encountered and how they were resolved

### Current State
What is the system/code/task state right now? What was the last thing discussed?

### Pending / Next Steps
- What remains to be done
- Any open questions or blockers

### Key Context
- Important constraints, preferences, or decisions that must not be forgotten
- Specific values: model names, ports, paths, credentials references, versions

Keep the summary under 1000 tokens. Be dense — every token should carry information. Do not include pleasantries or meta-commentary."""


def _sanitize_tool_messages(msgs: List[Dict]) -> List[Dict]:
    """Drop orphaned `tool` messages and dangling assistant `tool_calls`.

    OpenAI's API requires every `role:"tool"` message to immediately
    follow an assistant message that carries `tool_calls` (or another
    tool message in the same batch). Front-trimming the history can cut
    the assistant `tool_calls` parent while keeping its tool responses,
    which triggers: "messages with role 'tool' must be a response to a
    preceding message with 'tool_calls'". This pass repairs that:
      - drops `tool` messages with no valid preceding tool_calls
      - drops assistant `tool_calls` messages whose tool responses were
        all trimmed away (some providers reject unanswered tool_calls)
    """
    # Pass 1: drop orphan tool messages.
    cleaned: List[Dict] = []
    in_batch = False  # are we right after an assistant tool_calls (or mid-batch)?
    for m in msgs:
        role = m.get("role")
        if role == "tool":
            if in_batch:
                cleaned.append(m)
            # else: orphan — drop
            continue
        if role == "assistant" and m.get("tool_calls"):
            in_batch = True
        else:
            in_batch = False
        cleaned.append(m)

    # Pass 2: drop assistant tool_calls messages that have NO following
    # tool response (dangling) — walk backwards so we know what follows.
    out: List[Dict] = []
    for i, m in enumerate(cleaned):
        if m.get("role") == "assistant" and m.get("tool_calls"):
            nxt = cleaned[i + 1] if i + 1 < len(cleaned) else None
            if not (nxt and nxt.get("role") == "tool"):
                # Dangling tool_calls — keep the message but strip the
                # tool_calls so it's a plain assistant turn (preserves any
                # text content the model produced alongside the calls).
                m = {k: v for k, v in m.items() if k != "tool_calls"}
                if not (m.get("content") or "").strip():
                    continue  # nothing left worth keeping
        out.append(m)
    return out


def _message_text_token_estimate(text: str) -> int:
    if not isinstance(text, str):
        return 4
    return int(len(text) * 0.3) + 4


def _truncate_text_to_token_budget(text: str, token_budget: int) -> str:
    """Trim a too-large current user message instead of dropping it entirely."""
    if token_budget <= 32:
        return "[Current user message omitted: it exceeded the model context window.]"

    if not isinstance(text, str):
        # This helper is typed/used as text downstream, so return an empty
        # string rather than the raw non-string (which would move the crash
        # into the caller that concatenates/measures the result).
        return ""
    # Match src.model_context.estimate_tokens' rough chars * 0.3 estimate.
    max_chars = max(200, int((token_budget - 16) / 0.3))
    if len(text) <= max_chars:
        return text

    notice = (
        "\n\n[Notice: the pasted message was too large for this model's context "
        "window, so Odysseus kept the beginning and end.]"
    )
    keep_chars = max(200, max_chars - len(notice))
    head_len = max(100, int(keep_chars * 0.7))
    tail_len = max(80, keep_chars - head_len)
    return text[:head_len].rstrip() + notice + "\n\n" + text[-tail_len:].lstrip()


def _truncate_tool_call_args(msg: Dict[str, Any], token_budget: int) -> Dict[str, Any]:
    """Shrink oversized assistant ``tool_calls`` arguments to fit ``token_budget``.

    A tool-only turn persists ``content=None`` with its whole payload in
    ``tool_calls[].function.arguments`` (e.g. a large create_document body), which
    the text-content truncation can't reach — so the message could stay over
    budget and the upstream call would 400. Replace each argument string that
    overflows its share of the budget with a small valid-JSON placeholder,
    preserving ``id``/``type``/``function.name`` so tool/result pairing and
    provider validation are unaffected. Returns msg unchanged when there is
    nothing oversized.
    """
    tool_calls = msg.get("tool_calls")
    if not isinstance(tool_calls, list) or not tool_calls:
        return msg
    # Budget left after whatever content survived (estimate_tokens counts tool
    # arguments too, so measure content alone here).
    content_tokens = estimate_tokens([{"role": msg.get("role", "assistant"), "content": msg.get("content")}])
    per_call = max(16, (max(0, token_budget - content_tokens)) // len(tool_calls))
    new_calls = []
    changed = False
    for tc in tool_calls:
        fn = tc.get("function") if isinstance(tc, dict) else None
        args = fn.get("arguments") if isinstance(fn, dict) else None
        if isinstance(args, str) and int(len(args) * 0.3) > per_call:
            new_fn = dict(fn)
            new_fn["arguments"] = json.dumps({"_truncated_for_context": len(args)})
            new_tc = dict(tc)
            new_tc["function"] = new_fn
            new_calls.append(new_tc)
            changed = True
        else:
            new_calls.append(tc)
    if not changed:
        return msg
    out = dict(msg)
    out["tool_calls"] = new_calls
    return out


def _normalize_tool_name(name: Any) -> str:
    """Return a normalized tool-ish token from a formatter heading/name."""
    text = str(name or "").strip().lower().replace("-", "_")
    if text.startswith("mcp:"):
        text = text[4:].strip()
    tokens = re.findall(r"[a-z0-9_]+", text)
    return tokens[0] if tokens else ""


def _is_microcompact_protected_tool(name: Any) -> bool:
    return _normalize_tool_name(name) in _PROTECTED_MICROCOMPACT_TOOLS


def _is_microcompact_compactable_tool(name: Any) -> bool:
    return _normalize_tool_name(name) in MICROCOMPACT_COMPACTABLE_TOOLS


def _looks_like_tool_error(text: Any) -> bool:
    """Heuristic used only to keep the most recent error result complete."""
    if not isinstance(text, str) or not text:
        return False
    lower = text.lower()
    if re.search(r"\*\*exit_code:\*\*\s*(?!0\b)\d+", lower):
        return True
    return bool(re.search(r"\b(error|failed|failure|exception|traceback)\b", lower))


def _text_tool_sections(content: str) -> Optional[Dict[str, Any]]:
    """Split a synthetic ``[Tool execution results]`` message into sections.

    Non-native/tool-fence models receive tool output as a user message whose body
    is a concatenation of ``format_tool_result`` blocks headed by ``### name``.
    Splitting lets microcompaction preserve the newest/error/protected tool
    sections instead of treating the whole round as one indivisible blob.
    """
    if not isinstance(content, str) or not content.startswith(_TOOL_RESULTS_PREFIX):
        return None
    matches = list(re.finditer(r"(?m)^###\s+([^\n]+?)\s*$", content))
    if not matches:
        return None
    preamble = content[:matches[0].start()]
    sections = []
    for i, match in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(content)
        sections.append({
            "heading": match.group(1).strip(),
            "text": content[match.start():end],
        })
    return {"preamble": preamble, "sections": sections}


def _tool_result_token_estimate(text: Any) -> int:
    if isinstance(text, str):
        return _message_text_token_estimate(text)
    return _message_text_token_estimate(_content_as_text(text))


def _tool_arg_token_estimate(args: Any) -> int:
    if args is None:
        return 0
    if not isinstance(args, str):
        args = str(args)
    return int(len(args) * 0.3) + 4


def microcompact_tool_history(
    messages: List[Dict],
    input_budget: int,
    *,
    reserve_tokens: int = 512,
    trigger_ratio: float = MICROCOMPACT_TRIGGER_RATIO,
    target_ratio: float = MICROCOMPACT_TARGET_RATIO,
    keep_recent: int = MICROCOMPACT_KEEP_RECENT_TOOL_RESULTS,
    min_result_tokens: int = MICROCOMPACT_MIN_RESULT_TOKENS,
) -> tuple[List[Dict], Dict[str, int]]:
    """Clear old bulky tool payloads from the transient model context.

    This is intentionally cheaper and less destructive than full LLM
    compaction: it never summarizes, never drops messages, and never touches
    normal user/system content. It only replaces old tool result bodies (and
    matching old native tool-call arguments) with small placeholders while
    preserving message shape, IDs, tool names, Gemini ``extra_content`` fields,
    and assistant/tool pairing.

    Returns ``(messages, stats)``. If no compaction was needed, the original list
    is returned with zeroed stats.
    """
    stats = {
        "passes": 0,
        "results_cleared": 0,
        "arguments_compacted": 0,
        "tokens_saved": 0,
    }
    try:
        usable_budget = int(input_budget or 0) - int(reserve_tokens or 0)
    except (TypeError, ValueError):
        usable_budget = 0
    if usable_budget <= 0:
        return messages, stats

    before_tokens = estimate_tokens(messages)
    trigger_tokens = max(1, int(usable_budget * trigger_ratio))
    if before_tokens <= trigger_tokens:
        return messages, stats

    target_tokens = max(1, int(usable_budget * target_ratio))
    keep_recent = max(1, int(keep_recent or 1))
    min_result_tokens = max(1, int(min_result_tokens or 1))

    # First pass: discover native tool call metadata and every compactable result
    # in encounter order. Batch identity lets us keep the whole most recent round.
    call_info_by_id: Dict[str, Dict[str, Any]] = {}
    text_groups: Dict[int, Dict[str, Any]] = {}
    candidates: List[Dict[str, Any]] = []
    batch_seq = 0
    active_native_batch: Optional[int] = None

    for i, msg in enumerate(messages):
        role = msg.get("role")
        if role == "assistant" and isinstance(msg.get("tool_calls"), list) and msg.get("tool_calls"):
            batch_seq += 1
            active_native_batch = batch_seq
            for j, tc in enumerate(msg.get("tool_calls") or []):
                if not isinstance(tc, dict):
                    continue
                tc_id = tc.get("id")
                fn = tc.get("function") if isinstance(tc.get("function"), dict) else tc
                name = fn.get("name", "") if isinstance(fn, dict) else ""
                if tc_id:
                    call_info_by_id[str(tc_id)] = {
                        "assistant_index": i,
                        "call_index": j,
                        "name": name,
                        "batch": active_native_batch,
                    }
            continue

        if role == "tool":
            tc_id = msg.get("tool_call_id")
            info = call_info_by_id.get(str(tc_id)) if tc_id is not None else None
            batch = info.get("batch") if info else active_native_batch
            batch_seq = max(batch_seq, batch or batch_seq)
            candidates.append({
                "kind": "native",
                "order": len(candidates),
                "message_index": i,
                "tool_call_id": str(tc_id) if tc_id is not None else "",
                "assistant_index": info.get("assistant_index") if info else None,
                "call_index": info.get("call_index") if info else None,
                "name": info.get("name", "") if info else "",
                "batch": batch or batch_seq,
                "content": msg.get("content", ""),
            })
            continue

        active_native_batch = None
        if role == "user":
            parsed = _text_tool_sections(msg.get("content", ""))
            if parsed:
                batch_seq += 1
                text_groups[i] = parsed
                for section_index, section in enumerate(parsed["sections"]):
                    candidates.append({
                        "kind": "text",
                        "order": len(candidates),
                        "message_index": i,
                        "section_index": section_index,
                        "name": section["heading"],
                        "batch": batch_seq,
                        "content": section["text"],
                    })

    if not candidates:
        return messages, stats

    latest_batch = max(c["batch"] for c in candidates)
    keep_orders = {c["order"] for c in candidates[-keep_recent:]}
    error_candidates = [c for c in candidates if _looks_like_tool_error(c.get("content", ""))]
    if error_candidates:
        keep_orders.add(error_candidates[-1]["order"])

    eligible = [
        c for c in candidates
        if c["batch"] != latest_batch
        and c["order"] not in keep_orders
        and not _is_microcompact_protected_tool(c.get("name", ""))
        and _is_microcompact_compactable_tool(c.get("name", ""))
    ]
    if not eligible:
        return messages, stats

    compacted = list(messages)

    def _replace_native_result(candidate: Dict[str, Any]) -> bool:
        idx = candidate["message_index"]
        current = compacted[idx]
        if current.get("content") == MICROCOMPACT_CLEARED_MESSAGE:
            return False
        if _tool_result_token_estimate(current.get("content", "")) <= min_result_tokens:
            return False
        cloned = dict(current)
        cloned["content"] = MICROCOMPACT_CLEARED_MESSAGE
        compacted[idx] = cloned
        return True

    def _replace_text_section(candidate: Dict[str, Any]) -> bool:
        msg_index = candidate["message_index"]
        section_index = candidate["section_index"]
        parsed = text_groups.get(msg_index)
        if not parsed:
            return False
        section = parsed["sections"][section_index]
        if MICROCOMPACT_CLEARED_MESSAGE in section.get("text", ""):
            return False
        if _tool_result_token_estimate(section.get("text", "")) <= min_result_tokens:
            return False
        section["text"] = f"### {section['heading']}\n{MICROCOMPACT_CLEARED_MESSAGE}"
        cloned = dict(compacted[msg_index])
        cloned["content"] = parsed["preamble"] + "".join(s["text"] for s in parsed["sections"])
        compacted[msg_index] = cloned
        return True

    def _compact_native_args(candidate: Dict[str, Any]) -> bool:
        assistant_index = candidate.get("assistant_index")
        call_index = candidate.get("call_index")
        if assistant_index is None or call_index is None:
            return False
        assistant = compacted[assistant_index]
        tool_calls = assistant.get("tool_calls")
        if not isinstance(tool_calls, list) or call_index >= len(tool_calls):
            return False
        tc = tool_calls[call_index]
        if not isinstance(tc, dict):
            return False
        fn = tc.get("function") if isinstance(tc.get("function"), dict) else None
        if not isinstance(fn, dict):
            return False
        args = fn.get("arguments")
        if _tool_arg_token_estimate(args) <= min_result_tokens:
            return False
        if isinstance(args, str):
            try:
                parsed_args = json.loads(args)
            except Exception:
                parsed_args = None
            if isinstance(parsed_args, dict) and parsed_args.get(MICROCOMPACT_TRUNCATED_ARGS_KEY):
                return False
            original_chars = len(args)
        else:
            original_chars = len(str(args))
        new_fn = dict(fn)
        new_fn["arguments"] = json.dumps({
            MICROCOMPACT_TRUNCATED_ARGS_KEY: True,
            "original_chars": original_chars,
        })
        new_tc = dict(tc)
        new_tc["function"] = new_fn
        new_calls = list(tool_calls)
        new_calls[call_index] = new_tc
        new_assistant = dict(assistant)
        new_assistant["tool_calls"] = new_calls
        compacted[assistant_index] = new_assistant
        return True

    current_tokens = before_tokens
    for candidate in eligible:
        changed = False
        if candidate["kind"] == "native":
            if _replace_native_result(candidate):
                stats["results_cleared"] += 1
                changed = True
            if _compact_native_args(candidate):
                stats["arguments_compacted"] += 1
                changed = True
        elif candidate["kind"] == "text":
            if _replace_text_section(candidate):
                stats["results_cleared"] += 1
                changed = True
        if not changed:
            continue
        current_tokens = estimate_tokens(compacted)
        if current_tokens <= target_tokens:
            break

    after_tokens = estimate_tokens(compacted)
    saved = max(0, before_tokens - after_tokens)
    if saved <= 0:
        return messages, {
            "passes": 0,
            "results_cleared": 0,
            "arguments_compacted": 0,
            "tokens_saved": 0,
        }

    stats["passes"] = 1
    stats["tokens_saved"] = saved
    logger.info(
        "[microcompact] %s -> %s tokens; cleared=%s args=%s target=%s budget=%s",
        before_tokens,
        after_tokens,
        stats["results_cleared"],
        stats["arguments_compacted"],
        target_tokens,
        usable_budget,
    )
    return compacted, stats


def _truncate_message_to_token_budget(msg: Dict[str, Any], token_budget: int) -> Dict[str, Any]:
    """Return a copy of msg whose text content (and tool-call args) fit token_budget."""
    out = dict(msg)
    content = out.get("content", "")
    if isinstance(content, str):
        out["content"] = _truncate_text_to_token_budget(content, token_budget)
    elif isinstance(content, list):
        remaining = token_budget
        new_content = []
        for item in content:
            if not isinstance(item, dict) or item.get("type") != "text":
                new_content.append(item)
                continue
            text = item.get("text", "")
            truncated = _truncate_text_to_token_budget(text, remaining)
            cloned = dict(item)
            cloned["text"] = truncated
            new_content.append(cloned)
            remaining -= _message_text_token_estimate(truncated)
        out["content"] = new_content
    # A tool-only turn (content=None) carries its payload in tool_calls args,
    # which the branches above can't shrink — handle it so the message can fit.
    return _truncate_tool_call_args(out, token_budget)


def trim_for_context(messages: List[Dict], context_length: int, reserve_tokens: int = 512) -> List[Dict]:
    """Trim system messages to fit within context_length.

    For small-context models, progressively strips:
    1. RAG/memory system messages (keep preset system prompt)
    2. Older conversation turns
    Reserves space for the response.
    """
    budget = context_length - reserve_tokens
    used = estimate_tokens(messages)
    if used <= budget:
        return messages

    logger.info(f"Trimming messages: {used} tokens > {budget} budget (ctx={context_length})")

    # Separate system messages from conversation.
    # Messages marked _protected (e.g. active document) are never trimmed.
    system_msgs = []
    protected_msgs = []
    convo_msgs = []
    for msg in messages:
        if msg.get("_protected"):
            protected_msgs.append(msg)
        elif msg.get("role") == "system":
            system_msgs.append(msg)
        else:
            convo_msgs.append(msg)

    # Protected messages count toward budget but are never dropped
    protected_tokens = estimate_tokens(protected_msgs)
    budget -= protected_tokens

    # Priority: keep first system msg (preset prompt), drop others (memory, RAG, memo).
    # Exception: a research-spinoff primer (the seeded report that grounds a
    # "Discuss" chat) must never be dropped — it is the conversation's whole
    # knowledge base. Treat any system message carrying research_spinoff_from
    # metadata as essential alongside the leading system prompt.
    def _is_research_primer(m):
        return bool((m.get("metadata") or {}).get("research_spinoff_from"))
    _primers = [m for m in system_msgs if _is_research_primer(m)]
    _non_primer = [m for m in system_msgs if not _is_research_primer(m)]
    essential_system = (_non_primer[:1] if _non_primer else []) + _primers
    extra_system = _non_primer[1:]

    # Try dropping extra system messages one by one (from the end)
    trimmed = essential_system + convo_msgs
    if estimate_tokens(trimmed) <= budget:
        # Dropping extras was enough — try adding back some
        result = list(essential_system)
        for msg in extra_system:
            candidate = result + [msg] + convo_msgs
            if estimate_tokens(candidate) <= budget:
                result.append(msg)
            else:
                break
        return _sanitize_tool_messages(result + protected_msgs + convo_msgs)

    # Still too big — truncate the first system message (but keep more than 500 chars)
    if essential_system:
        sys_text = essential_system[0].get("content", "")
        if len(sys_text) > 2000:
            essential_system[0] = {"role": "system", "content": sys_text[:2000] + "\n[System prompt truncated for context limits]"}
            trimmed = essential_system + convo_msgs
            if estimate_tokens(trimmed) <= budget:
                return _sanitize_tool_messages(essential_system + protected_msgs + convo_msgs)

    # Still too big — drop older conversation turns BUT always keep the current
    # user turn. If a pasted message alone exceeds the model context, truncate
    # that message with a visible notice instead of dropping it; otherwise the
    # model appears to "ignore" large pastes because it never receives them.
    # Hermes-style: recent context matters more than old context.
    PROTECT_RECENT = 10
    current_msg = convo_msgs[-1:] if convo_msgs else []
    prior_convo = convo_msgs[:-1] if convo_msgs else []
    if len(prior_convo) >= PROTECT_RECENT:
        old_msgs = prior_convo[:-(PROTECT_RECENT - 1)]
        recent_msgs = prior_convo[-(PROTECT_RECENT - 1):] + current_msg
        while old_msgs and estimate_tokens(essential_system + old_msgs + recent_msgs) > budget:
            old_msgs.pop(0)
        convo_msgs = old_msgs + recent_msgs
    else:
        convo_msgs = prior_convo + current_msg
        while prior_convo and estimate_tokens(essential_system + prior_convo + current_msg) > budget:
            prior_convo.pop(0)
        convo_msgs = prior_convo + current_msg

    # If the current message itself is too large, shrink only that message.
    if current_msg and estimate_tokens(essential_system + protected_msgs + convo_msgs) > budget:
        prefix = essential_system + protected_msgs + convo_msgs[:-1]
        available_for_current = max(64, budget - estimate_tokens(prefix))
        convo_msgs[-1] = _truncate_message_to_token_budget(convo_msgs[-1], available_for_current)

    result = _sanitize_tool_messages(essential_system + protected_msgs + convo_msgs)
    logger.info(f"Trimmed to {estimate_tokens(result)} tokens ({len(result)} messages)")
    return result


async def maybe_compact(
    session,
    endpoint_url: str,
    model: str,
    messages: List[Dict],
    headers: Optional[Dict] = None,
    owner: Optional[str] = None,
) -> tuple:
    """Check context usage and compact the transient model-facing view.

    This intentionally does *not* rewrite ``session.history`` or the persisted
    chat rows.  The full transcript remains the source of truth for reload/UI,
    while this function returns a smaller projection for the next model call.
    That mirrors the safer transcript architecture used by code-source-main:
    persisted history and model-facing context are separate concerns.

    Returns (messages, context_length, was_compacted).
    """
    context_length = get_context_length(endpoint_url, model)
    used = estimate_tokens(messages)
    pct = (used / context_length) * 100 if context_length else 0

    if pct < COMPACT_THRESHOLD * 100:
        return messages, context_length, False

    logger.info(
        f"Context at {pct:.1f}% ({used}/{context_length} tokens) — compacting"
    )

    # Split into system preface and conversation
    system_msgs = []
    convo_msgs = []
    for msg in messages:
        if msg.get("role") == "system":
            system_msgs.append(msg)
        else:
            convo_msgs.append(msg)

    if len(convo_msgs) < 4:
        return messages, context_length, False

    # Split conversation: summarize older half, keep recent half
    split_point = len(convo_msgs) // 2
    older = convo_msgs[:split_point]
    recent = convo_msgs[split_point:]

    # Build the text to summarize
    convo_text = "\n".join(
        f"{msg.get('role', 'user').upper()}: {_content_as_text(msg.get('content'))[:2000]}"
        for msg in older
    )

    # Count prior compactions from existing summary messages
    compaction_count = sum(
        1 for m in system_msgs
        if "[Conversation summary" in m.get("content", "")
    )

    # Use utility model if configured, otherwise fall back to session model
    util_url, util_model, util_headers = resolve_endpoint("utility", owner=owner)
    compact_url = util_url or endpoint_url
    compact_model = util_model or model
    compact_headers = util_headers if util_url else headers

    prompt = SELF_SUMMARY_SYSTEM_PROMPT.replace(
        "{count}", str(len(older))
    ).replace(
        "{n}", str(compaction_count + 1)
    )
    summary_messages = [
        {"role": "system", "content": prompt},
        {"role": "user", "content": convo_text},
    ]

    try:
        summary = await llm_call_async(
            compact_url,
            compact_model,
            summary_messages,
            temperature=0.2,
            max_tokens=SUMMARY_MAX_TOKENS,
            headers=compact_headers,
            timeout=30,
        )
    except Exception as e:
        logger.error(f"Compaction summary failed: {e}")
        # Degrade gracefully: keep the conversation intact rather than
        # silently dropping the older half. was_compacted=False signals the
        # caller nothing was summarized; trim_for_context handles length.
        return messages, context_length, False

    # Treat the generated summary as conversation data, not a new system
    # instruction.  The summary may include user/tool text; wrapping it as
    # untrusted user-role context avoids elevating that text above the real
    # preset/system prompt while still letting the model use it as reference.
    summary_msg = untrusted_context_message(
        "conversation summary — earlier messages were compacted",
        f"[Conversation summary — earlier messages were compacted]\n{summary}",
    )

    compacted = _sanitize_tool_messages(system_msgs + [summary_msg] + recent)

    new_used = estimate_tokens(compacted)
    logger.info(
        f"Compacted model context projection: {used} -> {new_used} tokens "
        f"({len(older)} messages summarized, {len(recent)} kept; persisted history unchanged)"
    )

    return compacted, context_length, True


def _update_session_history(session, split_point: int, summary: str,
                            system_msg_count: int = 0):
    """Deprecated destructive compaction helper.

    Automatic context compaction must not call this: it is kept only for
    backward compatibility with old tests/imports and possible manual flows.
    Prefer returning a model-facing projection from ``maybe_compact`` while
    leaving ``session.history`` untouched.

    `split_point` is the index in `convo_msgs` (system-stripped). The
    in-memory `session.history` includes leading system messages, so the
    actual recent-history slice starts at `system_msg_count + split_point`.
    Prepending `session.history[:system_msg_count]` to the new history
    preserves persona, preset, and RAG system messages that would
    otherwise be dropped.
    """
    if not session or not hasattr(session, "history"):
        return

    effective_split = system_msg_count + split_point
    if effective_split >= len(session.history):
        return

    # Keep the recent messages, prepend summary AND the leading system
    # messages so the system prompt survives compaction.
    system_prefix = list(session.history[:system_msg_count])
    recent_history = session.history[effective_split:]
    summary_msg = ChatMessage(
        role="system",
        content=f"[Conversation summary]\n{summary}",
        metadata={"compacted": True, "summarized_count": split_point},
    )
    new_history = system_prefix + [summary_msg] + recent_history
    try:
        from core.models import get_session_manager_instance
        manager = get_session_manager_instance()
    except Exception:
        manager = None
    if manager and getattr(session, "id", None):
        if manager.replace_messages(session.id, new_history):
            return
    session.history = new_history
