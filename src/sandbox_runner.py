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
_BARE_GIT_GUARD_NAMES = ("HEAD", "objects", "refs", "hooks", "config")
_SANDBOX_GLOB_CHARS = "*?[]{}"


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


def sandbox_preset_settings(preset: str, base: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    """Return a normalized sandbox configuration for a named local preset.

    Presets are intentionally small and deterministic so the agent can enable a
    safer mode without hand-writing nested settings JSON.  Filesystem allow/deny
    lists are inherited from *base*; the preset only changes the execution
    policy knobs.
    """

    name = str(preset or "").strip().lower().replace("-", "_").replace(" ", "_")
    current = normalize_sandbox_settings(base or {})
    raw: Dict[str, Any]
    if name in {"off", "disabled", "disable"}:
        raw = {
            "enabled": False,
            "fail_if_unavailable": current["fail_if_unavailable"],
            "network": {"deny": current["network"]["deny"]},
            "filesystem": current["filesystem"],
        }
    elif name in {"local", "standard", "best_effort", "best_effort_local"}:
        raw = {
            "enabled": True,
            "fail_if_unavailable": False,
            "network": {"deny": current["network"]["deny"]},
            "filesystem": current["filesystem"],
        }
    elif name in {"network_deny", "no_network", "local_no_network"}:
        raw = {
            "enabled": True,
            "fail_if_unavailable": False,
            "network": {"deny": True},
            "filesystem": current["filesystem"],
        }
    elif name in {"strict", "strict_local", "fail_closed", "local_strict"}:
        raw = {
            "enabled": True,
            "fail_if_unavailable": True,
            "network": {"deny": True},
            "filesystem": current["filesystem"],
        }
    else:
        raise ValueError(
            "unknown sandbox preset "
            f"{preset!r}; expected one of: off, local, network_deny, strict_local"
        )
    return normalize_sandbox_settings(raw, current)


def _network_denied() -> bool:
    return bool(normalize_sandbox_settings(_settings())["network"]["deny"])


def _real(path: str) -> str:
    return os.path.realpath(os.path.expanduser(str(path)))


def _abs_no_follow(path: str) -> str:
    return os.path.abspath(os.path.expanduser(str(path)))


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


def _existing_bare_git_guard_paths(cwd: str) -> List[str]:
    """Return bare-repo sentinel paths that already exist at workspace root.

    Git treats a directory with top-level ``HEAD`` + ``objects`` + ``refs`` as
    a bare repository.  Existing sentinel paths are made read-only in the
    sandbox so a sandboxed process cannot modify them into an escape gadget.
    Non-existent sentinels are handled by post-command scrubbing instead of
    bind-mounting placeholders, because doing so can leave host-side stubs or
    break normal Git commands.
    """

    root = _real(cwd or os.getcwd())
    out: List[str] = []
    for name in _BARE_GIT_GUARD_NAMES:
        path = os.path.join(root, name)
        if os.path.lexists(path):
            out.append(path)
    return out


def bare_git_scrub_candidates(cwd: str) -> List[str]:
    """Capture bare-repo sentinel paths absent before a sandboxed command."""

    root = _real(cwd or os.getcwd())
    out: List[str] = []
    for name in _BARE_GIT_GUARD_NAMES:
        path = os.path.join(root, name)
        if not os.path.lexists(path):
            out.append(path)
    return out


def scrub_planted_bare_git_files(cwd: str, candidates: Sequence[str]) -> List[str]:
    """Remove bare-repo sentinels planted by a sandboxed command.

    The sandbox allows normal writes inside the workspace.  A malicious command
    could exploit that by planting top-level bare-repo files and waiting for a
    later unsandboxed Git call to interpret the workspace as a bare repo.  Only
    paths that were absent in ``bare_git_scrub_candidates`` are eligible here,
    so pre-existing user files are preserved.
    """

    root = _real(cwd or os.getcwd())
    allowed = {os.path.normcase(os.path.join(root, name)) for name in _BARE_GIT_GUARD_NAMES}
    removed: List[str] = []
    for raw in candidates or []:
        path = _abs_no_follow(raw)
        if os.path.normcase(path) not in allowed or not os.path.lexists(path):
            continue
        try:
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path)
            else:
                os.unlink(path)
            removed.append(path)
            logger.info("[sandbox] scrubbed planted bare-repo sentinel: %s", path)
        except OSError as exc:
            logger.warning("[sandbox] failed to scrub planted bare-repo sentinel %s: %s", path, exc)
    return removed


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
    deny_write.extend(_existing_bare_git_guard_paths(cwd))
    return _unique_real(deny_read), _unique_real(deny_write)


def _filesystem_setting_paths(key: str) -> List[str]:
    settings = normalize_sandbox_settings(_settings())
    fs = settings.get("filesystem") if isinstance(settings.get("filesystem"), dict) else {}
    return _unique_real(_listish(fs.get(key)))


def _filesystem_glob_warnings(settings: Mapping[str, Any]) -> List[str]:
    """Return warnings for glob-like sandbox filesystem settings.

    The sandbox backends receive concrete mount/mask destinations.  Treating a
    pattern such as ``/secrets/**`` as a literal path is almost certainly not
    what the user meant, so surface it in ``sandbox_status`` instead of letting
    the configuration silently miss.
    """

    fs = settings.get("filesystem") if isinstance(settings.get("filesystem"), Mapping) else {}
    warnings: List[str] = []
    for key in ("allow_read", "allow_write", "deny", "deny_read", "deny_write"):
        for path in _listish(fs.get(key)):
            if any(ch in path for ch in _SANDBOX_GLOB_CHARS):
                warnings.append(
                    f"sandbox filesystem.{key} contains glob-like path {path!r}; "
                    "sandbox filesystem settings require concrete paths"
                )
    return warnings


def _workspace_paths(cwd: str, *, include_read_overrides: bool = True) -> Tuple[List[str], List[str], List[str], List[str]]:
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
    if include_read_overrides:
        allow_read.extend(_listish(fs.get("allow_read")))
    allow_write.extend(_listish(fs.get("allow_write")))
    return (_unique_real(allow_read), _unique_real(allow_write), _unique_real(deny_read), _unique_real(deny_write))


def _extra_paths(paths: Optional[Sequence[str]]) -> List[str]:
    return _unique_real([str(path) for path in (paths or []) if str(path or "").strip()])


def _sbpl_target(path: str) -> str:
    encoded = json.dumps(path)
    return encoded


def _sbpl_allow_lines(kind: str, path: str) -> List[str]:
    encoded = _sbpl_target(path)
    return [
        f"(allow {kind} (literal {encoded}))",
        f"(allow {kind} (subpath {encoded}))",
    ]


def _macos_sandbox_profile(
    cwd: str,
    *,
    extra_allow_read: Optional[Sequence[str]] = None,
    extra_allow_write: Optional[Sequence[str]] = None,
    extra_allow_network: bool = False,
) -> str:
    allow_read, allow_write, deny_read, deny_write = _workspace_paths(cwd, include_read_overrides=False)
    # Persistent filesystem.allow_read has the same precedence contract as a
    # one-shot approved read: it intentionally reopens a narrow path after
    # deny_read masks. Keep it out of baseline mounts and append it below.
    extra_read = _unique_real([*_filesystem_setting_paths("allow_read"), *_extra_paths(extra_allow_read)])
    extra_write = _extra_paths(extra_allow_write)
    lines = [
        "(version 1)",
        "(deny default)",
        "(allow process*)",
        "(allow sysctl*)",
        "(allow signal)",
        # Modern macOS processes often abort under sandbox-exec when launched
        # with a narrow read profile. Keep reads broadly available for runtime
        # startup, then apply explicit sensitive-path read denies below. Writes
        # remain confined to the workspace/tmp unless per-operation approval
        # grants a narrow extra write allowance.
        "(allow file-read*)",
    ]
    if extra_allow_network or not _network_denied():
        lines.extend(["(allow network-outbound)", "(allow network-bind)"])
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
    # sandbox-exec applies later rules after earlier matching rules. These
    # operation-scoped allowances are intentionally appended after default
    # sensitive denies so a user-approved exact operation can read/write the
    # reviewed path without making that exception persistent.
    for path in extra_read:
        lines.extend(_sbpl_allow_lines("file-read*", path))
    for path in extra_write:
        lines.extend(_sbpl_allow_lines("file-write*", path))
    return "\n".join(lines)


def _macos_plan(
    command: Sequence[str],
    cwd: str,
    *,
    extra_allow_read: Optional[Sequence[str]] = None,
    extra_allow_write: Optional[Sequence[str]] = None,
    extra_allow_network: bool = False,
) -> Optional[SandboxPlan]:
    sandbox_exec = shutil.which("sandbox-exec")
    if not sandbox_exec:
        return None
    profile = _macos_sandbox_profile(
        cwd,
        extra_allow_read=extra_allow_read,
        extra_allow_write=extra_allow_write,
        extra_allow_network=extra_allow_network,
    )
    fd, profile_path = tempfile.mkstemp(prefix="odysseus-sandbox-", suffix=".sb")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(profile)
    wrapped = (sandbox_exec, "-f", profile_path, *command)
    return SandboxPlan(enabled=True, backend="sandbox-exec", command=wrapped, reason=profile_path, sandboxed=True)


def _linux_bwrap_plan(
    command: Sequence[str],
    cwd: str,
    *,
    extra_allow_read: Optional[Sequence[str]] = None,
    extra_allow_write: Optional[Sequence[str]] = None,
    extra_allow_network: bool = False,
) -> Optional[SandboxPlan]:
    bwrap = shutil.which("bwrap")
    if not bwrap:
        return None
    allow_read, allow_write, deny_read, deny_write = _workspace_paths(cwd, include_read_overrides=False)
    # Keep operation-scoped approvals separate from the baseline workspace
    # mounts.  The default profile intentionally masks sensitive paths after
    # mounting the workspace; approved one-shot paths must therefore be mounted
    # again at the end so the reviewed exception wins, mirroring the macOS SBPL
    # profile ordering.
    extra_read = _unique_real([*_filesystem_setting_paths("allow_read"), *_extra_paths(extra_allow_read)])
    extra_write = _extra_paths(extra_allow_write)
    args: List[str] = [
        bwrap,
        "--die-with-parent",
    ]
    if _network_denied() and not extra_allow_network:
        args.append("--unshare-net")
    args.extend(
        [
            "--dev-bind", "/dev", "/dev",
            "--proc", "/proc",
            "--ro-bind", "/usr", "/usr",
            "--ro-bind", "/bin", "/bin",
            "--ro-bind", "/lib", "/lib",
            "--ro-bind", "/lib64", "/lib64",
            "--ro-bind", "/etc", "/etc",
            "--tmpfs", "/tmp",
        ]
    )
    all_mounts = [*allow_read, *allow_write, *deny_read, *deny_write, *extra_read, *extra_write]
    for path in _linux_parent_dirs_for_mounts(all_mounts):
        args.extend(["--dir", path])
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
    for path in _linux_parent_dirs_after_masks([*extra_read, *extra_write], [*deny_read, *deny_write]):
        args.extend(["--dir", path])
    extra_write_set = set(extra_write)
    for path in extra_read:
        if path in extra_write_set:
            continue
        if os.path.exists(path):
            args.extend(["--ro-bind", path, path])
    for path in extra_write:
        if os.path.exists(path):
            args.extend(["--bind", path, path])
    args.extend(["--chdir", cwd, *command])
    return SandboxPlan(enabled=True, backend="bubblewrap", command=tuple(args), sandboxed=True)


_LINUX_PREMOUNTED_DESTS = ("/dev", "/proc", "/usr", "/bin", "/lib", "/lib64", "/etc")


def _linux_parent_dirs_for_mounts(paths: Sequence[str]) -> List[str]:
    """Return destination parent directories bubblewrap must create.

    Bubblewrap starts from an almost-empty root.  Binding a workspace such as
    ``/home/me/project`` or an approved outside file like
    ``/home/me/secret.txt`` can fail unless ``/home`` and ``/home/me`` exist
    inside the namespace first.  System paths that are already mounted read-only
    are intentionally skipped, while nested temp dirs are recreated after the
    ``/tmp`` tmpfs is mounted.
    """

    out: List[str] = []
    seen: set[str] = set()

    def _skip_dir(path: str) -> bool:
        if path in {"", "/", "/tmp"}:
            return True
        for mounted in _LINUX_PREMOUNTED_DESTS:
            if path == mounted or path.startswith(mounted.rstrip("/") + "/"):
                return True
        return False

    for raw in paths:
        if not raw:
            continue
        path = _real(raw)
        if os.path.isdir(path):
            parent = os.path.dirname(path.rstrip("/")) or "/"
        else:
            parent = os.path.dirname(path) or "/"
        pieces: List[str] = []
        cursor = parent
        while cursor and cursor != "/":
            if not _skip_dir(cursor):
                pieces.append(cursor)
            next_cursor = os.path.dirname(cursor.rstrip("/")) or "/"
            if next_cursor == cursor:
                break
            cursor = next_cursor
        for directory in reversed(pieces):
            if directory not in seen:
                seen.add(directory)
                out.append(directory)
    return out


def _is_same_or_child(path: str, parent: str) -> bool:
    try:
        path_norm = os.path.normcase(_real(path))
        parent_norm = os.path.normcase(_real(parent))
        if path_norm == parent_norm:
            return True
        return os.path.commonpath([path_norm, parent_norm]) == parent_norm
    except (OSError, ValueError):
        return False


def _linux_parent_dirs_after_masks(paths: Sequence[str], mask_paths: Sequence[str]) -> List[str]:
    """Return dirs that must be recreated after a deny mask is mounted.

    A bubblewrap ``--tmpfs /home/me/.ssh`` deny hides any parent directories
    that were created below ``.ssh`` before the mask.  When the user approves
    a narrow child such as ``/home/me/.ssh/config`` or
    ``/home/me/.ssh/nested/key``, recreate just the in-mask parent dirs before
    appending the operation-scoped bind.
    """

    mask_dirs = [_real(path) for path in mask_paths if path and os.path.isdir(_real(path))]
    out: List[str] = []
    seen: set[str] = set()
    for raw in paths:
        if not raw:
            continue
        path = _real(raw)
        parent = path if os.path.isdir(path) else (os.path.dirname(path) or "/")
        for mask in mask_dirs:
            if parent == mask or not _is_same_or_child(parent, mask):
                continue
            pieces: List[str] = []
            cursor = parent
            while cursor and cursor != "/" and cursor != mask:
                pieces.append(cursor)
                next_cursor = os.path.dirname(cursor.rstrip("/")) or "/"
                if next_cursor == cursor:
                    break
                cursor = next_cursor
            for directory in reversed(pieces):
                if directory not in seen:
                    seen.add(directory)
                    out.append(directory)
    return out


def _linux_firejail_plan(
    command: Sequence[str],
    cwd: str,
    *,
    extra_allow_read: Optional[Sequence[str]] = None,
    extra_allow_write: Optional[Sequence[str]] = None,
    extra_allow_network: bool = False,
) -> Optional[SandboxPlan]:
    firejail = shutil.which("firejail")
    if not firejail:
        return None
    allow_read, allow_write, deny_read, deny_write = _workspace_paths(cwd, include_read_overrides=False)
    # Firejail accepts all constraints up front, but keeping approved one-shot
    # overrides after blacklists/read-only rules makes the generated command
    # reflect the same precedence contract as macOS and bubblewrap.
    extra_read = _unique_real([*_filesystem_setting_paths("allow_read"), *_extra_paths(extra_allow_read)])
    extra_write = _extra_paths(extra_allow_write)
    private = cwd
    args_list = [firejail, "--quiet", f"--private={private}", "--noprofile"]
    if _network_denied() and not extra_allow_network:
        args_list.append("--net=none")
    writable = set(allow_write)
    for path in allow_read:
        if os.path.exists(path) and path != private:
            args_list.append(f"--whitelist={path}")
    for path in allow_write:
        if os.path.exists(path):
            if path != private:
                args_list.append(f"--whitelist={path}")
            args_list.append(f"--read-write={path}")
    for path in deny_read:
        if os.path.exists(path):
            args_list.append(f"--blacklist={path}")
    for path in deny_write:
        if os.path.exists(path) and path not in writable:
            args_list.append(f"--read-only={path}")
    for path in extra_read:
        if os.path.exists(path) and path != private:
            args_list.append(f"--whitelist={path}")
    for path in extra_write:
        if os.path.exists(path):
            if path != private:
                args_list.append(f"--whitelist={path}")
            args_list.append(f"--read-write={path}")
    args = (*args_list, "--", *command)
    return SandboxPlan(enabled=True, backend="firejail", command=args, sandboxed=True)


def build_sandbox_plan(
    command: Sequence[str],
    *,
    cwd: str,
    extra_allow_read: Optional[Sequence[str]] = None,
    extra_allow_write: Optional[Sequence[str]] = None,
    extra_allow_network: bool = False,
) -> SandboxPlan:
    if not sandbox_enabled():
        return SandboxPlan(enabled=False, command=tuple(command), reason="sandbox disabled", sandboxed=False)
    cwd = os.path.realpath(cwd or os.getcwd())
    system = platform.system().lower()
    plan: Optional[SandboxPlan] = None
    try:
        if system == "darwin":
            plan = _macos_plan(
                command,
                cwd,
                extra_allow_read=extra_allow_read,
                extra_allow_write=extra_allow_write,
                extra_allow_network=extra_allow_network,
            )
        elif system == "linux":
            plan = _linux_bwrap_plan(
                command,
                cwd,
                extra_allow_read=extra_allow_read,
                extra_allow_write=extra_allow_write,
                extra_allow_network=extra_allow_network,
            ) or _linux_firejail_plan(
                command,
                cwd,
                extra_allow_read=extra_allow_read,
                extra_allow_write=extra_allow_write,
                extra_allow_network=extra_allow_network,
            )
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


def sandbox_dependency_report() -> Dict[str, Any]:
    """Return dependency diagnostics for the currently supported OS backends."""

    backends = available_backends()
    system = str(backends.get("platform") or "")
    errors: List[str] = []
    warnings: List[str] = []
    install_hint = ""

    if system == "darwin":
        if not backends.get("sandbox-exec"):
            errors.append("macOS sandbox-exec is not available")
            install_hint = "sandbox-exec is provided by macOS; check the OS installation or disable fail_if_unavailable"
    elif system == "linux":
        has_bwrap = bool(backends.get("bubblewrap"))
        has_firejail = bool(backends.get("firejail"))
        if not has_bwrap and not has_firejail:
            errors.append("Linux sandbox requires bubblewrap or firejail")
            install_hint = "install bubblewrap or firejail, for example: apt install bubblewrap firejail"
        elif not has_bwrap:
            warnings.append("bubblewrap is unavailable; firejail fallback will be used")
            install_hint = "install bubblewrap for the preferred Linux sandbox backend"
    else:
        errors.append(f"sandbox is not supported on platform {system or 'unknown'}")
        install_hint = "use macOS sandbox-exec or Linux bubblewrap/firejail"

    return {
        "platform": system,
        "available_backends": {k: v for k, v in backends.items() if k != "platform"},
        "errors": errors,
        "warnings": warnings,
        "install_hint": install_hint,
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
    dependencies = sandbox_dependency_report()
    warnings: List[str] = []
    if settings["enabled"] and not plan.sandboxed:
        warnings.append(plan.reason or "sandbox requested but no backend is available")
    if settings["enabled"]:
        warnings.extend(dependencies.get("errors") or [])
        warnings.extend(dependencies.get("warnings") or [])
        warnings.extend(_filesystem_glob_warnings(settings))
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
        "dependencies": dependencies,
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
