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
from typing import Dict, List, Optional, Sequence, Tuple

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
    return bool(_settings().get("enabled", False))


def fail_if_unavailable() -> bool:
    return bool(_settings().get("fail_if_unavailable", False))


def _workspace_paths(cwd: str) -> Tuple[List[str], List[str], List[str]]:
    settings = _settings()
    fs = settings.get("filesystem") if isinstance(settings.get("filesystem"), dict) else {}
    allow_read = [cwd, "/tmp"]
    allow_write = [cwd, "/tmp"]
    deny = [
        os.path.expanduser("~/.ssh"),
        os.path.expanduser("~/.gnupg"),
        os.path.expanduser("~/.aws"),
        os.path.expanduser("~/.config/gh"),
    ]
    for key, target in (("allow_read", allow_read), ("allow_write", allow_write), ("deny", deny)):
        extra = fs.get(key) or []
        if isinstance(extra, list):
            target.extend(str(p) for p in extra if p)
    return (
        list(dict.fromkeys(os.path.realpath(os.path.expanduser(p)) for p in allow_read if p)),
        list(dict.fromkeys(os.path.realpath(os.path.expanduser(p)) for p in allow_write if p)),
        list(dict.fromkeys(os.path.realpath(os.path.expanduser(p)) for p in deny if p)),
    )


def _macos_sandbox_profile(cwd: str) -> str:
    allow_read, allow_write, deny = _workspace_paths(cwd)
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
    if not bool(_settings().get("network", {}).get("deny", False)):
        lines.extend(["(allow network-outbound)", "(allow network-bind)"])
    for path in allow_read:
        lines.append(f"(allow file-read* (subpath {json.dumps(path)}))")
    for path in allow_write:
        lines.append(f"(allow file-write* (subpath {json.dumps(path)}))")
    for path in deny:
        lines.append(f"(deny file-read* file-write* (subpath {json.dumps(path)}))")
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
    allow_read, allow_write, deny = _workspace_paths(cwd)
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
    if bool(_settings().get("network", {}).get("deny", False)):
        args.insert(2, "--unshare-net")
    for path in allow_read:
        if os.path.exists(path):
            args.extend(["--ro-bind", path, path])
    for path in allow_write:
        if os.path.exists(path):
            args.extend(["--bind", path, path])
    for path in deny:
        if os.path.exists(path):
            args.extend(["--tmpfs", path])
    args.extend(["--chdir", cwd, *command])
    return SandboxPlan(enabled=True, backend="bubblewrap", command=tuple(args), sandboxed=True)


def _linux_firejail_plan(command: Sequence[str], cwd: str) -> Optional[SandboxPlan]:
    firejail = shutil.which("firejail")
    if not firejail:
        return None
    _, allow_write, _ = _workspace_paths(cwd)
    private = allow_write[0] if allow_write else cwd
    args_list = [firejail, "--quiet", f"--private={private}", "--noprofile"]
    if bool(_settings().get("network", {}).get("deny", False)):
        args_list.append("--net=none")
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
