"""Best-effort OS sandbox wrapper for local subprocess tools.

The operation-permissions gate is the primary safety boundary.  This runner is
an additional layer: when a supported backend is available it constrains Bash /
Python processes; when unavailable it can either fail closed or run unsandboxed
depending on settings.
"""

from __future__ import annotations

import logging
import json
import os
import platform
import shutil
import tempfile
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SandboxPlan:
    enabled: bool
    backend: str = ""
    command: Tuple[str, ...] = ()
    reason: str = ""
    sandboxed: bool = False


def _settings() -> Dict:
    try:
        from src.operation_permissions import sandbox_settings

        return sandbox_settings()
    except Exception:
        return {}


def sandbox_enabled() -> bool:
    return _boolish(_settings().get("enabled", False))


def fail_if_unavailable() -> bool:
    return _boolish(_settings().get("fail_if_unavailable", False))


def _boolish(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on", "enable", "enabled"}


def _listish(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, (list, tuple, set)):
        return [str(v) for v in value if str(v or "").strip()]
    return []


def normalize_sandbox_settings(raw: Mapping[str, Any] | None, base: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    """Validate and normalize the public sandbox settings shape.

    This is intentionally conservative: unknown keys are ignored rather than
    persisted, and all filesystem lists are converted to string lists.
    """

    raw = raw or {}
    base = base or {}
    network_raw = raw.get("network") if isinstance(raw.get("network"), Mapping) else {}
    base_network = base.get("network") if isinstance(base.get("network"), Mapping) else {}
    fs_raw = raw.get("filesystem") if isinstance(raw.get("filesystem"), Mapping) else {}
    base_fs = base.get("filesystem") if isinstance(base.get("filesystem"), Mapping) else {}

    def _value(*names: str, default: Any = None) -> Any:
        for name in names:
            if name in raw:
                return raw[name]
        return default

    normalized = {
        "enabled": _boolish(_value("enabled", default=base.get("enabled", False))),
        "fail_if_unavailable": _boolish(
            _value("fail_if_unavailable", "failIfUnavailable", default=base.get("fail_if_unavailable", False))
        ),
        "network": {
            "deny": _boolish(raw.get("network_deny", network_raw.get("deny", base_network.get("deny", False)))),
        },
        "filesystem": {},
    }
    for key in ("allow_read", "allow_write", "deny", "deny_read", "deny_write"):
        camel = "".join([key.split("_")[0], key.split("_")[1].title()]) if "_" in key else key
        value = fs_raw.get(key, fs_raw.get(camel, raw.get(key, raw.get(camel, base_fs.get(key, [])))))
        normalized["filesystem"][key] = _listish(value)
    return normalized


def _network_denied() -> bool:
    return bool(normalize_sandbox_settings(_settings())["network"]["deny"])


def _real(path: str) -> str:
    return os.path.realpath(os.path.expanduser(str(path)))


def _unique_real(paths: Sequence[str]) -> List[str]:
    out: List[str] = []
    seen: set[str] = set()
    for path in paths:
        if not path:
            continue
        try:
            real = _real(path)
        except OSError:
            continue
        if real in seen:
            continue
        seen.add(real)
        out.append(real)
    return out


def _odysseus_sensitive_paths() -> Tuple[List[str], List[str]]:
    """Return default read/write deny paths for app-owned sensitive data."""

    try:
        from src.constants import (
            APP_KEY_FILE,
            AUTH_FILE,
            INTEGRATIONS_FILE,
            MCP_OAUTH_DIR,
            SETTINGS_FILE,
            SKILLS_DIR,
            USER_PREFS_FILE,
            VAULT_FILE,
        )
    except Exception:
        return [], []

    deny_read = [APP_KEY_FILE, AUTH_FILE, INTEGRATIONS_FILE, MCP_OAUTH_DIR, VAULT_FILE]
    deny_write = [
        APP_KEY_FILE,
        AUTH_FILE,
        INTEGRATIONS_FILE,
        MCP_OAUTH_DIR,
        SETTINGS_FILE,
        SKILLS_DIR,
        USER_PREFS_FILE,
        VAULT_FILE,
    ]
    return deny_read, deny_write


def _default_deny_paths(cwd: str) -> Tuple[List[str], List[str]]:
    home = os.path.expanduser("~")
    deny_read = [
        os.path.join(home, ".ssh"),
        os.path.join(home, ".gnupg"),
        os.path.join(home, ".aws"),
        os.path.join(home, ".azure"),
        os.path.join(home, ".kube"),
        os.path.join(home, ".docker"),
        os.path.join(home, ".config", "gh"),
        os.path.join(home, ".config", "gcloud"),
        os.path.join(home, ".config", "op"),
        os.path.join(home, ".netrc"),
    ]
    deny_write = list(deny_read)
    cwd = _real(cwd or os.getcwd())
    deny_read.extend(
        [
            os.path.join(cwd, ".env"),
            os.path.join(cwd, ".npmrc"),
            os.path.join(cwd, ".pypirc"),
            os.path.join(cwd, ".mcp.json"),
            os.path.join(cwd, ".claude.json"),
        ]
    )
    deny_write.extend(
        [
            os.path.join(cwd, ".git"),
            os.path.join(cwd, ".vscode"),
            os.path.join(cwd, ".idea"),
            os.path.join(cwd, ".github", "workflows"),
            os.path.join(cwd, ".claude"),
            os.path.join(cwd, ".env"),
            os.path.join(cwd, ".npmrc"),
            os.path.join(cwd, ".pypirc"),
            os.path.join(cwd, ".mcp.json"),
            os.path.join(cwd, ".claude.json"),
            os.path.join(cwd, "settings.json"),
            os.path.join(cwd, "settings.local.json"),
            os.path.join(cwd, "data", "settings.json"),
        ]
    )
    app_deny_read, app_deny_write = _odysseus_sensitive_paths()
    deny_read.extend(app_deny_read)
    deny_write.extend(app_deny_write)
    return _unique_real(deny_read), _unique_real(deny_write)


def _workspace_paths(cwd: str) -> Tuple[List[str], List[str], List[str], List[str]]:
    settings = normalize_sandbox_settings(_settings())
    fs = settings.get("filesystem") if isinstance(settings.get("filesystem"), dict) else {}
    allow_read = [cwd, "/tmp"]
    allow_write = [cwd, "/tmp"]
    default_deny_read, default_deny_write = _default_deny_paths(cwd)
    deny_read = list(default_deny_read)
    deny_write = list(default_deny_write)
    deny_both = _listish(fs.get("deny"))
    deny_read.extend(deny_both)
    deny_write.extend(deny_both)
    deny_read.extend(_listish(fs.get("deny_read")))
    deny_write.extend(_listish(fs.get("deny_write")))
    allow_read.extend(_listish(fs.get("allow_read")))
    allow_write.extend(_listish(fs.get("allow_write")))
    return (_unique_real(allow_read), _unique_real(allow_write), _unique_real(deny_read), _unique_real(deny_write))


def _sbpl_target(path: str) -> str:
    encoded = json.dumps(path)
    return encoded


def _macos_sandbox_profile(cwd: str) -> str:
    allow_read, allow_write, deny_read, deny_write = _workspace_paths(cwd)
    lines = [
        "(version 1)",
        "(deny default)",
        "(allow process*)",
        "(allow sysctl*)",
        "(allow signal)",
        "(allow file-read-metadata)",
        "(allow file-read-data (literal \"/dev/null\"))",
        "(allow file-read-data (literal \"/dev/urandom\"))",
        "(allow file-read-data (literal \"/dev/random\"))",
        "(allow file-read* (subpath \"/System\"))",
        "(allow file-read* (subpath \"/usr\"))",
        "(allow file-read* (subpath \"/bin\"))",
        "(allow file-read* (subpath \"/sbin\"))",
        "(allow file-read* (subpath \"/Library\"))",
        "(allow file-read* (subpath \"/opt/homebrew\"))",
        "(allow file-read* (subpath \"/opt/local\"))",
        "(allow file-read* (literal \"/etc\"))",
        "(allow file-read* (subpath \"/etc\"))",
        "(allow file-read* (subpath \"/private/etc\"))",
    ]
    if not _network_denied():
        lines.extend(["(allow network-outbound)", "(allow network-bind)"])
    for path in allow_read:
        lines.append(f"(allow file-read* (subpath {json.dumps(path)}))")
    for path in allow_write:
        lines.append(f"(allow file-write* (subpath {json.dumps(path)}))")
    for path in deny_read:
        encoded = _sbpl_target(path)
        lines.append(f"(deny file-read* (literal {encoded}))")
        lines.append(f"(deny file-read* (subpath {encoded}))")
    for path in deny_write:
        encoded = _sbpl_target(path)
        lines.append(f"(deny file-write* (literal {encoded}))")
        lines.append(f"(deny file-write* (subpath {encoded}))")
    return "\n".join(lines)


def _macos_plan(command: Sequence[str], cwd: str) -> Optional[SandboxPlan]:
    sandbox_exec = shutil.which("sandbox-exec")
    if not sandbox_exec:
        return None
    profile = _macos_sandbox_profile(cwd)
    fd, profile_path = tempfile.mkstemp(prefix="odysseus-sandbox-", suffix=".sb")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(profile)
    wrapped = (sandbox_exec, "-f", profile_path, *command)
    return SandboxPlan(enabled=True, backend="sandbox-exec", command=wrapped, reason=profile_path, sandboxed=True)


def _linux_bwrap_plan(command: Sequence[str], cwd: str) -> Optional[SandboxPlan]:
    bwrap = shutil.which("bwrap")
    if not bwrap:
        return None
    allow_read, allow_write, deny_read, deny_write = _workspace_paths(cwd)
    args: List[str] = [
        bwrap,
        "--die-with-parent",
        "--dev-bind", "/dev", "/dev",
        "--proc", "/proc",
        "--ro-bind", "/usr", "/usr",
        "--ro-bind", "/bin", "/bin",
        "--ro-bind", "/lib", "/lib",
        "--ro-bind", "/lib64", "/lib64",
        "--ro-bind", "/etc", "/etc",
        "--tmpfs", "/tmp",
    ]
    if _network_denied():
        args.insert(2, "--unshare-net")
    allow_write_set = set(allow_write)
    for path in allow_read:
        if path in allow_write_set:
            continue
        if os.path.exists(path):
            args.extend(["--ro-bind", path, path])
    for path in allow_write:
        if os.path.exists(path):
            args.extend(["--bind", path, path])
    for path in deny_write:
        if os.path.exists(path):
            args.extend(["--ro-bind", path, path])
    for path in deny_read:
        if os.path.exists(path):
            if os.path.isdir(path):
                args.extend(["--tmpfs", path])
            else:
                null_device = "/dev/null"
                if os.path.exists(null_device):
                    args.extend(["--ro-bind", null_device, path])
    args.extend(["--chdir", cwd, *command])
    return SandboxPlan(enabled=True, backend="bubblewrap", command=tuple(args), sandboxed=True)


def _linux_firejail_plan(command: Sequence[str], cwd: str) -> Optional[SandboxPlan]:
    firejail = shutil.which("firejail")
    if not firejail:
        return None
    _, allow_write, deny_read, deny_write = _workspace_paths(cwd)
    private = allow_write[0] if allow_write else cwd
    args_list = [firejail, "--quiet", f"--private={private}", "--noprofile"]
    if _network_denied():
        args_list.append("--net=none")
    for path in deny_read:
        if os.path.exists(path):
            args_list.append(f"--blacklist={path}")
    for path in deny_write:
        if os.path.exists(path):
            args_list.append(f"--read-only={path}")
    args = (*args_list, "--", *command)
    return SandboxPlan(enabled=True, backend="firejail", command=args, sandboxed=True)


def build_sandbox_plan(command: Sequence[str], *, cwd: str) -> SandboxPlan:
    if not sandbox_enabled():
        return SandboxPlan(enabled=False, command=tuple(command), reason="sandbox disabled", sandboxed=False)
    cwd = os.path.realpath(cwd or os.getcwd())
    system = platform.system().lower()
    plan: Optional[SandboxPlan] = None
    try:
        if system == "darwin":
            plan = _macos_plan(command, cwd)
        elif system == "linux":
            plan = _linux_bwrap_plan(command, cwd) or _linux_firejail_plan(command, cwd)
    except Exception as exc:
        logger.warning("Failed to build sandbox plan: %s", exc)
        plan = None
    if plan:
        return plan
    if fail_if_unavailable():
        return SandboxPlan(
            enabled=True,
            command=tuple(command),
            reason="sandbox requested but no supported backend is available",
            sandboxed=False,
        )
    return SandboxPlan(
        enabled=True,
        command=tuple(command),
        reason="sandbox backend unavailable; running unsandboxed because fail_if_unavailable=false",
        sandboxed=False,
    )


def available_backends() -> Dict[str, bool]:
    system = platform.system().lower()
    return {
        "platform": system,
        "sandbox-exec": system == "darwin" and bool(shutil.which("sandbox-exec")),
        "bubblewrap": system == "linux" and bool(shutil.which("bwrap")),
        "firejail": system == "linux" and bool(shutil.which("firejail")),
    }


def sandbox_status(*, cwd: Optional[str] = None) -> Dict[str, Any]:
    """Return a user/tool friendly sandbox readiness report."""

    cwd = _real(cwd or os.getcwd())
    settings = normalize_sandbox_settings(_settings())
    allow_read, allow_write, deny_read, deny_write = _workspace_paths(cwd)
    plan = build_sandbox_plan(("true",), cwd=cwd)
    if plan.backend == "sandbox-exec" and plan.reason:
        try:
            os.unlink(plan.reason)
        except OSError:
            pass
    backends = available_backends()
    warnings: List[str] = []
    if settings["enabled"] and not plan.sandboxed:
        warnings.append(plan.reason or "sandbox requested but no backend is available")
    if not settings["enabled"]:
        warnings.append("sandbox is disabled; operation permissions still run before Bash/Python")
    return {
        "enabled": settings["enabled"],
        "fail_if_unavailable": settings["fail_if_unavailable"],
        "network_deny": settings["network"]["deny"],
        "cwd": cwd,
        "platform": backends["platform"],
        "available_backends": {k: v for k, v in backends.items() if k != "platform"},
        "selected_backend": plan.backend,
        "sandboxed": plan.sandboxed,
        "reason": plan.reason,
        "filesystem": {
            "allow_read": allow_read,
            "allow_write": allow_write,
            "deny_read": deny_read,
            "deny_write": deny_write,
            "allow_read_count": len(allow_read),
            "allow_write_count": len(allow_write),
            "deny_read_count": len(deny_read),
            "deny_write_count": len(deny_write),
        },
        "warnings": warnings,
    }
