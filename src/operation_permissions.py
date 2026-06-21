"""Operation-level permission engine for agent tools.

This module is intentionally deterministic: no model/classifier calls happen
while deciding whether an operation may run.  It complements the existing
tool-level gates (admin/public/disabled/plan/guide-only) with narrower rules
such as "allow `git status`", "ask for `git push`", or "deny edits under
`.git/**`".
"""

from __future__ import annotations

import fnmatch
import json
import logging
import os
import re
import shlex
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

BEHAVIORS = {"allow", "deny", "ask"}
RULE_SCOPES = {"persistent", "session", "once", "builtin"}

PERMISSION_RESPONSE_LABELS = {
    "allow_once": "Permitir una vez",
    "allow_session": "Permitir esta sesión",
    "allow_always": "Permitir siempre",
    "deny": "Denegar",
}

_SESSION_RULES: Dict[str, List[Dict[str, Any]]] = {}
_ONE_SHOT_RULES: Dict[str, List[Dict[str, Any]]] = {}
_PENDING_APPROVALS: Dict[str, Dict[str, Any]] = {}
_METRICS: Dict[str, int] = {
    "allowed": 0,
    "denied": 0,
    "asked": 0,
    "approved": 0,
    "sandboxed": 0,
    "unsandboxed": 0,
}


@dataclass(frozen=True)
class Operation:
    tool: str
    content: str = ""
    value: str = ""
    kind: str = "tool"
    description: str = ""
    command: str = ""
    path: str = ""
    domain: str = ""
    url: str = ""
    mcp_server: str = ""
    mcp_tool: str = ""
    args: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PermissionDecision:
    behavior: str
    reason: str = ""
    source: str = "default"
    rule: Optional[Mapping[str, Any]] = None
    operation: Optional[Operation] = None
    suggested_rule: Optional[Mapping[str, Any]] = None
    severity: str = "normal"

    @property
    def is_terminal(self) -> bool:
        return self.behavior in {"allow", "deny", "ask"}


def _setting(name: str, default: Any = None) -> Any:
    try:
        from src.settings import get_setting

        return get_setting(name, default)
    except Exception:
        return default


def operation_permissions_enabled() -> bool:
    return bool(_setting("operation_permissions_enabled", True))


def builtin_permissions_enabled() -> bool:
    return bool(_setting("operation_permissions_builtin_policy", True))


def interactive_permissions_enabled() -> bool:
    return bool(_setting("operation_permissions_interactive_ask", True))


def sandbox_settings() -> Dict[str, Any]:
    value = _setting("operation_permissions_sandbox", {}) or {}
    return value if isinstance(value, dict) else {}


def _norm_tool(tool: str) -> str:
    return (tool or "").strip()


def _norm_behavior(value: Any) -> str:
    behavior = str(value or "").strip().lower()
    if behavior not in BEHAVIORS:
        raise ValueError("behavior must be one of: allow, deny, ask")
    return behavior


def _new_rule_id() -> str:
    return "opr_" + uuid.uuid4().hex[:12]


def normalize_rule(raw: Mapping[str, Any], *, scope: str = "persistent") -> Dict[str, Any]:
    """Normalize a user/persisted rule into the internal shape."""

    if not isinstance(raw, Mapping):
        raise ValueError("permission rule must be an object")
    behavior = _norm_behavior(raw.get("behavior"))
    tool = _norm_tool(str(raw.get("tool") or raw.get("tool_name") or raw.get("name") or ""))
    if not tool:
        raise ValueError("permission rule needs a tool")
    match = str(raw.get("match") or raw.get("matcher") or "").strip().lower()
    pattern = str(
        raw.get("pattern")
        or raw.get("rule")
        or raw.get("ruleContent")
        or raw.get("content")
        or ""
    ).strip()
    if not match:
        if tool == "bash":
            match = "glob" if any(ch in pattern for ch in "*?[") else "prefix"
        elif tool == "web_fetch":
            match = "domain"
        elif tool.startswith("mcp__"):
            match = "tool"
        elif tool in {"read_file", "write_file", "edit_file", "grep", "glob", "ls"}:
            match = "path"
        else:
            match = "tool"
    if match not in {"tool", "exact", "prefix", "glob", "path", "domain", "mcp"}:
        raise ValueError("match must be one of: tool, exact, prefix, glob, path, domain, mcp")
    if match != "tool" and not pattern:
        raise ValueError(f"{match} rules need a pattern")
    rule_scope = str(raw.get("scope") or scope or "persistent").strip().lower()
    if rule_scope not in RULE_SCOPES:
        rule_scope = scope
    return {
        "id": str(raw.get("id") or _new_rule_id()),
        "behavior": behavior,
        "tool": tool,
        "match": match,
        "pattern": pattern,
        "scope": rule_scope,
        "description": str(raw.get("description") or raw.get("reason") or "").strip(),
        "created_at": float(raw.get("created_at") or time.time()),
    }


def get_persistent_rules() -> List[Dict[str, Any]]:
    raw = _setting("operation_permission_rules", []) or []
    if not isinstance(raw, list):
        return []
    out: List[Dict[str, Any]] = []
    for item in raw:
        try:
            out.append(normalize_rule(item, scope="persistent"))
        except Exception as exc:
            logger.warning("Ignoring malformed operation permission rule: %s", exc)
    return out


def save_persistent_rules(rules: Iterable[Mapping[str, Any]]) -> None:
    from src.settings import load_settings, save_settings

    normalized = [normalize_rule(rule, scope="persistent") for rule in rules]
    settings = load_settings()
    settings["operation_permission_rules"] = normalized
    save_settings(settings)


def add_persistent_rule(rule: Mapping[str, Any]) -> Dict[str, Any]:
    normalized = normalize_rule(rule, scope="persistent")
    rules = get_persistent_rules()
    rules.append(normalized)
    save_persistent_rules(rules)
    return normalized


def delete_persistent_rule(rule_id: str) -> bool:
    wanted = str(rule_id or "").strip()
    if not wanted:
        return False
    rules = get_persistent_rules()
    kept = [rule for rule in rules if str(rule.get("id")) != wanted]
    if len(kept) == len(rules):
        return False
    save_persistent_rules(kept)
    return True


def clear_persistent_rules() -> int:
    rules = get_persistent_rules()
    save_persistent_rules([])
    return len(rules)


def get_session_rules(session_id: Optional[str]) -> List[Dict[str, Any]]:
    if not session_id:
        return []
    return list(_SESSION_RULES.get(str(session_id), []))


def add_session_rule(session_id: str, rule: Mapping[str, Any], *, once: bool = False) -> Dict[str, Any]:
    normalized = normalize_rule(rule, scope="once" if once else "session")
    bucket = _ONE_SHOT_RULES if once else _SESSION_RULES
    bucket.setdefault(str(session_id), []).append(normalized)
    return normalized


def clear_session_rules(session_id: str) -> None:
    _SESSION_RULES.pop(str(session_id), None)
    _ONE_SHOT_RULES.pop(str(session_id), None)
    _PENDING_APPROVALS.pop(str(session_id), None)


def metrics_snapshot() -> Dict[str, int]:
    return dict(_METRICS)


def record_sandbox_run(*, sandboxed: bool) -> None:
    _METRICS["sandboxed" if sandboxed else "unsandboxed"] += 1


def _loads_args(content: str) -> Dict[str, Any]:
    raw = (content or "").strip()
    if not raw.startswith("{"):
        return {}
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _first_line(content: str) -> str:
    return (content or "").split("\n", 1)[0].strip()


def _write_path(content: str) -> str:
    args = _loads_args(content)
    if args.get("path"):
        return str(args.get("path") or "").strip()
    return _first_line(content)


def _edit_path(content: str) -> str:
    args = _loads_args(content)
    return str(args.get("path") or "").strip()


def _search_path(content: str) -> str:
    args = _loads_args(content)
    if args:
        return str(args.get("path") or "").strip()
    return _first_line(content)


def _extract_url(content: str) -> str:
    args = _loads_args(content)
    url = str(args.get("url") or "").strip() if args else ""
    if not url:
        url = _first_line(content)
    if url and "://" not in url:
        url = "https://" + url
    return url


def _domain_for_url(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower().strip(".")
    except Exception:
        return ""


def operation_from_tool(tool: str, content: str) -> Operation:
    tool = _norm_tool(tool)
    content = content or ""
    if tool == "bash":
        command = content.strip()
        return Operation(
            tool=tool,
            content=content,
            value=command,
            kind="command",
            command=command,
            description=f"bash: {command.splitlines()[0][:120] if command else '(empty command)'}",
        )
    if tool == "python":
        code = content.strip()
        return Operation(
            tool=tool,
            content=content,
            value=code,
            kind="code",
            command=code,
            description=f"python: {code.splitlines()[0][:120] if code else '(empty code)'}",
        )
    if tool in {"read_file", "write_file"}:
        path = _write_path(content)
        return Operation(tool=tool, content=content, value=path, kind="path", path=path, description=f"{tool}: {path}")
    if tool == "edit_file":
        path = _edit_path(content)
        return Operation(tool=tool, content=content, value=path, kind="path", path=path, description=f"edit_file: {path}")
    if tool in {"grep", "glob", "ls"}:
        path = _search_path(content)
        return Operation(tool=tool, content=content, value=path, kind="path", path=path, description=f"{tool}: {path or '(workspace/default root)'}")
    if tool == "web_fetch":
        url = _extract_url(content)
        domain = _domain_for_url(url)
        return Operation(tool=tool, content=content, value=domain or url, kind="domain", url=url, domain=domain, description=f"web_fetch: {domain or url}")
    if tool.startswith("mcp__"):
        parts = tool.split("__", 2)
        server = parts[1] if len(parts) > 1 else ""
        mcp_tool = parts[2] if len(parts) > 2 else ""
        return Operation(
            tool=tool,
            content=content,
            value=tool,
            kind="mcp",
            mcp_server=server,
            mcp_tool=mcp_tool,
            args=_loads_args(content),
            description=f"MCP: {tool}",
        )
    return Operation(tool=tool, content=content, value=tool, kind="tool", description=tool)


def _path_candidates(path: str) -> List[str]:
    raw = (path or "").strip()
    values = [raw]
    if raw:
        expanded = os.path.expanduser(raw)
        values.append(expanded)
        try:
            values.append(os.path.realpath(expanded))
        except OSError:
            pass
    out: List[str] = []
    for value in values:
        if not value:
            continue
        normalized = value.replace(os.sep, "/")
        out.append(normalized)
        if normalized.startswith("./"):
            out.append(normalized[2:])
    return list(dict.fromkeys(out))


def _domain_matches(pattern: str, domain: str) -> bool:
    pattern = (pattern or "").lower().strip()
    domain = (domain or "").lower().strip(".")
    if pattern.startswith("domain:"):
        pattern = pattern[len("domain:") :].strip()
    if not pattern or not domain:
        return False
    if fnmatch.fnmatch(domain, pattern):
        return True
    return domain == pattern or domain.endswith("." + pattern)


def _tool_matches(rule_tool: str, op: Operation) -> bool:
    rule_tool = _norm_tool(rule_tool)
    if rule_tool in {"*", op.tool}:
        return True
    if rule_tool.startswith("mcp__") and op.tool.startswith("mcp__"):
        return fnmatch.fnmatch(op.tool, rule_tool)
    return False


def _rule_matches(rule: Mapping[str, Any], op: Operation) -> bool:
    if not _tool_matches(str(rule.get("tool") or ""), op):
        return False
    match = str(rule.get("match") or "tool").lower()
    pattern = str(rule.get("pattern") or "")
    if match == "tool":
        return True
    if match == "exact":
        return op.value == pattern
    if match == "prefix":
        return op.value.strip().startswith(pattern.strip())
    if match == "glob":
        return fnmatch.fnmatch(op.value, pattern)
    if match == "domain":
        return _domain_matches(pattern, op.domain or op.value)
    if match == "mcp":
        return fnmatch.fnmatch(op.tool, pattern) or fnmatch.fnmatch(op.mcp_tool, pattern)
    if match == "path":
        candidates = _path_candidates(op.path or op.value)
        pat = pattern.replace(os.sep, "/")
        for candidate in candidates:
            if fnmatch.fnmatch(candidate, pat):
                return True
            if not any(ch in pat for ch in "*?["):
                if candidate == pat or candidate.startswith(pat.rstrip("/") + "/"):
                    return True
        return False
    return False


def _first_rule_decision(rules: Iterable[Mapping[str, Any]], op: Operation, behavior: str) -> Optional[PermissionDecision]:
    for rule in rules:
        if str(rule.get("behavior")) != behavior:
            continue
        if _rule_matches(rule, op):
            return PermissionDecision(
                behavior=behavior,
                reason=str(rule.get("description") or f"Matched {behavior} permission rule"),
                source=str(rule.get("scope") or "rule"),
                rule=rule,
                operation=op,
            )
    return None


def _consume_matching_one_shot(session_id: Optional[str], op: Operation, behavior: str) -> Optional[PermissionDecision]:
    if not session_id:
        return None
    rules = _ONE_SHOT_RULES.get(str(session_id), [])
    for idx, rule in enumerate(list(rules)):
        if str(rule.get("behavior")) == behavior and _rule_matches(rule, op):
            try:
                del rules[idx]
            except Exception:
                pass
            return PermissionDecision(
                behavior=behavior,
                reason=str(rule.get("description") or "Matched one-shot permission rule"),
                source="once",
                rule=rule,
                operation=op,
            )
    return None


_DANGEROUS_PATH_PARTS = {
    ".git",
    ".vscode",
    ".idea",
}
_DANGEROUS_PATH_PATTERNS = (
    "*/.github/workflows/*",
    "*/data/settings.json",
    "*/settings.json",
    "*/settings.local.json",
    "*/odysseus/data/settings.json",
)


def _path_safety_decision(op: Operation) -> Optional[PermissionDecision]:
    if op.tool not in {"read_file", "write_file", "edit_file", "grep", "glob", "ls"}:
        return None
    path = op.path or op.value
    if not path:
        return None
    candidates = _path_candidates(path)
    mutating = op.tool in {"write_file", "edit_file"}
    for candidate in candidates:
        parts = {part for part in candidate.split("/") if part}
        if mutating and parts.intersection(_DANGEROUS_PATH_PARTS):
            return PermissionDecision(
                behavior="ask",
                reason=f"{op.tool} targets a protected project/control directory",
                source="builtin",
                operation=op,
                suggested_rule=_rule_for_operation(op, "allow"),
                severity="high",
            )
        if mutating and any(fnmatch.fnmatch(candidate, pat) for pat in _DANGEROUS_PATH_PATTERNS):
            return PermissionDecision(
                behavior="ask",
                reason=f"{op.tool} targets a protected configuration/workflow path",
                source="builtin",
                operation=op,
                suggested_rule=_rule_for_operation(op, "allow"),
                severity="high",
            )
    return None


_BASH_READONLY_COMMANDS = {
    "pwd",
    "ls",
    "cat",
    "head",
    "tail",
    "grep",
    "rg",
    "find",
    "wc",
    "sed",
    "awk",
    "sort",
    "uniq",
    "cut",
    "tr",
    "date",
    "whoami",
    "id",
    "uname",
    "git",
}
_BASH_MUTATING_COMMANDS = {
    "git",
    "npm",
    "pnpm",
    "yarn",
    "pip",
    "pip3",
    "python",
    "python3",
    "node",
    "make",
    "cargo",
    "go",
    "docker",
    "kubectl",
    "touch",
    "mkdir",
    "cp",
    "mv",
    "rm",
    "rmdir",
    "chmod",
    "chown",
    "chgrp",
    "ln",
}
_BASH_DANGEROUS_COMMANDS = {
    "sudo",
    "su",
    "ssh",
    "scp",
    "rsync",
    "dd",
    "mkfs",
    "mount",
    "umount",
    "kill",
    "killall",
    "pkill",
    "launchctl",
    "crontab",
}
_SHELL_WRAPPERS = {
    "sh",
    "bash",
    "zsh",
    "fish",
    "dash",
    "env",
    "xargs",
    "nohup",
    "timeout",
    "nice",
    "stdbuf",
}


def _split_shell_segments(command: str) -> List[str]:
    return [seg.strip() for seg in re.split(r"\s*(?:&&|\|\||;|\n)\s*", command or "") if seg.strip()]


def _first_token(segment: str) -> Tuple[str, List[str]]:
    try:
        parts = shlex.split(segment, posix=True)
    except ValueError:
        return "", []
    while parts and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", parts[0]):
        parts = parts[1:]
    token = os.path.basename(parts[0]) if parts else ""
    return token, parts


def classify_bash_command(command: str) -> Tuple[str, str]:
    """Return (classification, reason) for a shell command.

    classification is one of: read_only, mutating, dangerous, ambiguous.
    """

    cmd = (command or "").strip()
    if not cmd:
        return "ambiguous", "empty command"
    low = cmd.lower()
    if re.search(r"\brm\s+(-[^\n;|&]*r[^\n;|&]*f|-[^\n;|&]*f[^\n;|&]*r)\s+(/|\$home|~)(?:\s|$)", low):
        return "dangerous", "recursive forced removal of a root/home path"
    if re.search(r"\bcurl\b.+\|\s*(?:sh|bash|zsh)\b", low) or re.search(r"\bwget\b.+\|\s*(?:sh|bash|zsh)\b", low):
        return "dangerous", "download-and-execute pipeline"
    if re.search(r">\s*(?:~?/|/).*(?:\.ssh|\.gnupg|\.env|authorized_keys|id_rsa|id_ed25519)", low):
        return "dangerous", "redirection targets a sensitive path"

    classifications: List[str] = []
    for segment in _split_shell_segments(cmd):
        base, parts = _first_token(segment)
        if not base:
            classifications.append("ambiguous")
            continue
        if base in _BASH_DANGEROUS_COMMANDS:
            classifications.append("dangerous")
            continue
        if base in _SHELL_WRAPPERS and any(part in {"-c", "-lc", "-ic"} for part in parts[1:3]):
            classifications.append("dangerous")
            continue
        if base == "git":
            sub = parts[1] if len(parts) > 1 else ""
            if sub in {"status", "diff", "log", "show", "branch", "rev-parse", "ls-files"}:
                classifications.append("read_only")
            elif sub in {"push", "commit", "merge", "rebase", "reset", "checkout", "switch", "clean", "tag"}:
                classifications.append("mutating")
            else:
                classifications.append("ambiguous")
            continue
        if base in {"npm", "pnpm", "yarn"}:
            sub = parts[1] if len(parts) > 1 else ""
            classifications.append("mutating" if sub in {"install", "add", "remove", "publish", "run"} else "ambiguous")
            continue
        if base in {"pip", "pip3"}:
            sub = parts[1] if len(parts) > 1 else ""
            classifications.append("mutating" if sub in {"install", "uninstall"} else "ambiguous")
            continue
        if base in _BASH_MUTATING_COMMANDS:
            classifications.append("mutating")
            continue
        if base in _BASH_READONLY_COMMANDS and not re.search(r"(?<![<>])>(?!&)|>>|\btee\b", segment):
            classifications.append("read_only")
            continue
        classifications.append("ambiguous")

    if "dangerous" in classifications:
        return "dangerous", "command contains a high-risk shell operation"
    if "mutating" in classifications:
        return "mutating", "command may change local state"
    if "ambiguous" in classifications:
        return "ambiguous", "command is not recognized as safely read-only"
    return "read_only", "command appears read-only"


def _bash_policy_decision(op: Operation) -> Optional[PermissionDecision]:
    if op.tool != "bash":
        return None
    classification, reason = classify_bash_command(op.command)
    if classification == "read_only":
        return None
    if classification == "dangerous":
        # The obviously catastrophic forms are denied; other dangerous commands
        # ask in interactive contexts and deny in headless contexts.
        if "root/home" in reason:
            return PermissionDecision(
                behavior="deny",
                reason=reason,
                source="builtin",
                operation=op,
                severity="critical",
            )
        return PermissionDecision(
            behavior="ask",
            reason=reason,
            source="builtin",
            operation=op,
            suggested_rule=_rule_for_operation(op, "allow"),
            severity="high",
        )
    if classification == "mutating":
        return PermissionDecision(
            behavior="ask",
            reason=reason,
            source="builtin",
            operation=op,
            suggested_rule=_rule_for_operation(op, "allow"),
            severity="normal",
        )
    if bool(_setting("operation_permissions_ask_ambiguous_bash", False)):
        return PermissionDecision(
            behavior="ask",
            reason=reason,
            source="builtin",
            operation=op,
            suggested_rule=_rule_for_operation(op, "allow"),
            severity="normal",
        )
    return None


def _builtin_decision(op: Operation) -> Optional[PermissionDecision]:
    if not builtin_permissions_enabled():
        return None
    return _path_safety_decision(op) or _bash_policy_decision(op)


def _rule_for_operation(op: Operation, behavior: str) -> Dict[str, Any]:
    if op.tool == "bash":
        return normalize_rule(
            {
                "behavior": behavior,
                "tool": "bash",
                "match": "exact",
                "pattern": op.command,
                "description": f"User-approved Bash command: {op.command[:120]}",
            },
            scope="session",
        )
    if op.tool == "web_fetch":
        return normalize_rule(
            {
                "behavior": behavior,
                "tool": "web_fetch",
                "match": "domain",
                "pattern": op.domain or op.value,
                "description": f"User-approved domain: {op.domain or op.value}",
            },
            scope="session",
        )
    if op.kind == "path":
        return normalize_rule(
            {
                "behavior": behavior,
                "tool": op.tool,
                "match": "path",
                "pattern": op.path or op.value,
                "description": f"User-approved path for {op.tool}: {op.path or op.value}",
            },
            scope="session",
        )
    if op.tool.startswith("mcp__"):
        return normalize_rule(
            {
                "behavior": behavior,
                "tool": op.tool,
                "match": "tool",
                "description": f"User-approved MCP tool: {op.tool}",
            },
            scope="session",
        )
    return normalize_rule({"behavior": behavior, "tool": op.tool, "match": "tool"}, scope="session")


def evaluate_tool_permission(
    tool: str,
    content: str,
    *,
    session_id: Optional[str] = None,
    owner: Optional[str] = None,
) -> PermissionDecision:
    if not operation_permissions_enabled():
        return PermissionDecision("passthrough", "operation permissions disabled")

    op = operation_from_tool(tool, content)

    rules: List[Mapping[str, Any]] = []
    rules.extend(get_session_rules(session_id))
    rules.extend(get_persistent_rules())

    # One-shot deny/ask is rare but keep the same precedence semantics.
    for behavior in ("deny", "ask", "allow"):
        one = _consume_matching_one_shot(session_id, op, behavior)
        if one:
            _METRICS["allowed" if behavior == "allow" else ("denied" if behavior == "deny" else "asked")] += 1
            return one
        match = _first_rule_decision(rules, op, behavior)
        if match:
            _METRICS["allowed" if behavior == "allow" else ("denied" if behavior == "deny" else "asked")] += 1
            return match

    built_in = _builtin_decision(op)
    if built_in:
        _METRICS["denied" if built_in.behavior == "deny" else "asked"] += 1
        return built_in

    return PermissionDecision("passthrough", "no matching operation permission", operation=op)


def register_pending_approval(session_id: str, decision: PermissionDecision) -> None:
    if not session_id or not decision.operation:
        return
    rule = decision.suggested_rule or _rule_for_operation(decision.operation, "allow")
    _PENDING_APPROVALS[str(session_id)] = {
        "operation": {
            "tool": decision.operation.tool,
            "value": decision.operation.value,
            "kind": decision.operation.kind,
            "description": decision.operation.description,
        },
        "rule": dict(rule),
        "reason": decision.reason,
        "created_at": time.time(),
    }


def permission_ask_payload(decision: PermissionDecision) -> Dict[str, Any]:
    op = decision.operation or Operation(tool="unknown")
    question = (
        "Esta operación requiere aprobación antes de ejecutarse:\n\n"
        f"{op.description or op.tool}\n\n"
        f"Motivo: {decision.reason or 'regla de permisos'}"
    )
    return {
        "question": question,
        "options": [
            {
                "label": PERMISSION_RESPONSE_LABELS["allow_once"],
                "description": "Ejecuta solo esta operación una vez.",
            },
            {
                "label": PERMISSION_RESPONSE_LABELS["allow_session"],
                "description": "Permite esta misma operación durante esta sesión.",
            },
            {
                "label": PERMISSION_RESPONSE_LABELS["allow_always"],
                "description": "Guarda una regla persistente para esta operación exacta.",
            },
            {
                "label": PERMISSION_RESPONSE_LABELS["deny"],
                "description": "No ejecutar esta operación.",
            },
        ],
        "multi": False,
        "permission_request": True,
    }


def consume_pending_permission_response(
    session_id: Optional[str],
    message: Any,
    *,
    owner: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    sid = str(session_id or "")
    if not sid:
        return None
    pending = _PENDING_APPROVALS.get(sid)
    if not pending:
        return None
    text = str(message or "").strip().lower()
    if not text:
        return None
    label_to_action = {label.lower(): action for action, label in PERMISSION_RESPONSE_LABELS.items()}
    action = label_to_action.get(text)
    if not action:
        return None
    _PENDING_APPROVALS.pop(sid, None)
    op = pending.get("operation") or {}
    rule = dict(pending.get("rule") or {})
    if action == "deny":
        return {
            "decision": "deny",
            "message": f"Permiso denegado para: {op.get('description') or op.get('tool')}",
        }
    if action == "allow_once":
        add_session_rule(sid, rule, once=True)
        _METRICS["approved"] += 1
        return {
            "decision": "allow_once",
            "message": f"Permiso de una vez registrado para: {op.get('description') or op.get('tool')}",
        }
    if action == "allow_session":
        add_session_rule(sid, rule, once=False)
        _METRICS["approved"] += 1
        return {
            "decision": "allow_session",
            "message": f"Permiso de sesión registrado para: {op.get('description') or op.get('tool')}",
        }
    if action == "allow_always":
        persistent = normalize_rule({**rule, "scope": "persistent"}, scope="persistent")
        add_persistent_rule(persistent)
        _METRICS["approved"] += 1
        return {
            "decision": "allow_always",
            "message": f"Permiso persistente guardado para: {op.get('description') or op.get('tool')}",
            "rule": persistent,
        }
    return None


def deny_result(decision: PermissionDecision) -> Dict[str, Any]:
    op = decision.operation
    target = f" ({op.description})" if op and op.description else ""
    return {
        "error": f"Operation permission denied{target}: {decision.reason}",
        "exit_code": 1,
        "blocked": True,
        "permission_decision": {
            "behavior": "deny",
            "source": decision.source,
            "reason": decision.reason,
            "rule": dict(decision.rule) if decision.rule else None,
        },
    }


def ask_result(decision: PermissionDecision, *, session_id: Optional[str]) -> Dict[str, Any]:
    if not session_id or not interactive_permissions_enabled():
        return deny_result(
            PermissionDecision(
                "deny",
                reason=f"{decision.reason}; interactive approval is not available",
                source=decision.source,
                rule=decision.rule,
                operation=decision.operation,
            )
        )
    register_pending_approval(session_id, decision)
    payload = permission_ask_payload(decision)
    return {
        "ask_user": payload,
        "output": "Awaiting user approval for operation permission.",
        "exit_code": 0,
        "permission_decision": {
            "behavior": "ask",
            "source": decision.source,
            "reason": decision.reason,
        },
    }

