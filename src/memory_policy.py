"""Conservative gates for persistent memory and personal-document RAG.

Odysseus used to treat memory and RAG as ambient context: if the caller did
not explicitly opt out, saved memories and personal documents could be injected
into the next prompt.  That is convenient, but it is also exactly how a local
agent starts feeling like it is mixing unrelated chats.

The policy here is intentionally boring and deterministic:

* memory context is off unless the user's preference explicitly enables it;
* auto-extraction is off unless both memory and auto-memory are enabled;
* personal-document RAG is off unless the current request or prefs opt in;
* explicit memory-management requests may still expose the memory tool, but
  recalled memories are guidance only and should be verified against current
  state when they mention files, functions, flags, dates, or project state.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any


TRUE_VALUES = {"1", "true", "yes", "y", "on", "enabled", "enable"}
FALSE_VALUES = {"0", "false", "no", "n", "off", "disabled", "disable"}


MEMORY_TYPES = ("user", "feedback", "project", "reference")


MEMORY_POLICY_PROMPT = """Memory is explicit, scoped, and fallible.
- Use manage_memory only when the user explicitly asks to remember/save/forget/list/search memories, or when they ask what you remember.
- Do not silently save ordinary task details, code discoveries, file paths, debug recipes, architecture snapshots, git history, temporary plans, secrets, credentials, or content from other people's contact records.
- If the user says to ignore memory, behave as if memory were empty.
- Treat recalled memory as a hint from the time it was saved. Before recommending a file, function, flag, dependency, date, or project-state claim from memory, verify it against the current workspace or current source of truth.
- If current evidence conflicts with memory, trust current evidence and offer to update or remove the stale memory."""


_EXPLICIT_MEMORY_PATTERNS = (
    re.compile(r"\bremember\s+(?:this|that|it|me|to|que|the following)\b", re.I),
    re.compile(r"\bsave\s+(?:this|that|it|the following)\s+(?:to|in|as)\s+(?:memory|memories)\b", re.I),
    re.compile(r"\bforget\s+(?:this|that|it|memory|memories|what you remember)\b", re.I),
    re.compile(r"\b(?:list|show|search|delete|update|edit)\s+(?:my\s+|the\s+)?(?:memory|memories)\b", re.I),
    re.compile(r"\bwhat\s+do\s+you\s+remember\b", re.I),
    re.compile(r"\brecuerda(?:me)?\s+(?:esto|eso|que|lo siguiente)\b", re.I),
    re.compile(r"\bguarda(?:r)?\s+(?:esto|eso|que|lo siguiente).{0,40}\bmemoria(?:s)?\b", re.I),
    re.compile(r"\bolvida(?:r|te)?\s+(?:esto|eso|memoria(?:s)?|lo que recuerdas)\b", re.I),
    re.compile(r"\b(?:lista|muestra|busca|borra|actualiza|edita)\s+(?:mi\s+|la\s+|las\s+)?memoria(?:s)?\b", re.I),
    re.compile(r"\bqu[eé]\s+recuerdas\b", re.I),
)


def coerce_bool(value: Any, *, default: bool = False) -> bool:
    """Parse common user/config booleans without making missing values truthy."""

    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in TRUE_VALUES:
        return True
    if text in FALSE_VALUES:
        return False
    return default


def memory_enabled_from_prefs(
    prefs: Mapping[str, Any] | None,
    *,
    incognito: bool = False,
    no_memory: bool = False,
    allow_tool_preprocessing: bool = True,
    is_research_spinoff: bool = False,
) -> bool:
    """Return whether saved memories may be injected into this prompt."""

    if incognito or no_memory or not allow_tool_preprocessing or is_research_spinoff:
        return False
    return coerce_bool((prefs or {}).get("memory_enabled"), default=False)


def auto_memory_enabled_from_prefs(
    prefs: Mapping[str, Any] | None,
    *,
    incognito: bool = False,
    compare_mode: bool = False,
    allow_background_extraction: bool = True,
) -> bool:
    """Return whether a completed response may trigger memory extraction."""

    if incognito or compare_mode or not allow_background_extraction:
        return False
    prefs = prefs or {}
    return (
        coerce_bool(prefs.get("memory_enabled"), default=False)
        and coerce_bool(prefs.get("auto_memory"), default=False)
    )


def rag_enabled_from_request_and_prefs(
    use_rag: Any,
    prefs: Mapping[str, Any] | None,
    *,
    incognito: bool = False,
    allow_tool_preprocessing: bool = True,
    is_research_spinoff: bool = False,
) -> bool:
    """Return whether personal-document RAG may be injected into this prompt."""

    if incognito or not allow_tool_preprocessing or is_research_spinoff:
        return False
    if use_rag is not None:
        return coerce_bool(use_rag, default=False)
    prefs = prefs or {}
    return coerce_bool(
        prefs.get("rag_enabled", prefs.get("personal_rag_enabled")),
        default=False,
    )


def explicit_memory_requested(message: Any) -> bool:
    """Heuristic for turns that are directly about managing saved memory."""

    if not isinstance(message, str) or not message.strip():
        return False
    return any(pattern.search(message) for pattern in _EXPLICIT_MEMORY_PATTERNS)


def should_expose_manage_memory_tool(
    prefs: Mapping[str, Any] | None,
    message: Any,
    *,
    incognito: bool = False,
    no_memory: bool = False,
    allow_tool_preprocessing: bool = True,
    is_research_spinoff: bool = False,
) -> bool:
    """Return whether the agent should see the manage_memory tool this turn."""

    if incognito or not allow_tool_preprocessing or is_research_spinoff:
        return False
    return memory_enabled_from_prefs(
        prefs,
        incognito=incognito,
        no_memory=no_memory,
        allow_tool_preprocessing=allow_tool_preprocessing,
        is_research_spinoff=is_research_spinoff,
    ) or explicit_memory_requested(message)
