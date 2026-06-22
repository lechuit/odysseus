#!/usr/bin/env bash
# Shared helpers for local Odysseus development scripts.
#
# These scripts are intentionally macOS-friendly because the desktop app keeps
# its runnable copy under ~/Library/Application Support/Odysseus.

set -euo pipefail

odysseus_script_dir() {
    local source_path="${BASH_SOURCE[0]}"
    local lib_dir
    lib_dir="$(cd "$(dirname "$source_path")" && pwd)"
    cd "$lib_dir/../.." && pwd
}

ODYSSEUS_REPO_DIR="${ODYSSEUS_REPO_DIR:-$(odysseus_script_dir)}"
ODYSSEUS_LOCAL_DIR="${ODYSSEUS_LOCAL_DIR:-$HOME/Library/Application Support/Odysseus}"
ODYSSEUS_LOCAL_HOST="${ODYSSEUS_LOCAL_HOST:-${ODYSSEUS_HOST:-127.0.0.1}}"
ODYSSEUS_LOCAL_PORT="${ODYSSEUS_LOCAL_PORT:-${ODYSSEUS_PORT:-7860}}"
ODYSSEUS_LOCAL_PROBE_HOST="$ODYSSEUS_LOCAL_HOST"
if [ "$ODYSSEUS_LOCAL_PROBE_HOST" = "0.0.0.0" ] || [ "$ODYSSEUS_LOCAL_PROBE_HOST" = "::" ]; then
    ODYSSEUS_LOCAL_PROBE_HOST="127.0.0.1"
fi
ODYSSEUS_LOCAL_LOG_DIR="${ODYSSEUS_LOCAL_LOG_DIR:-$HOME/Library/Logs/Odysseus}"
ODYSSEUS_LOCAL_LOG="${ODYSSEUS_LOCAL_LOG:-$ODYSSEUS_LOCAL_LOG_DIR/odysseus-local.log}"
ODYSSEUS_LOCAL_PIDFILE="${ODYSSEUS_LOCAL_PIDFILE:-$ODYSSEUS_LOCAL_DIR/.odysseus-local.pid}"
ODYSSEUS_LOCAL_URL="http://$ODYSSEUS_LOCAL_PROBE_HOST:$ODYSSEUS_LOCAL_PORT"
ODYSSEUS_LOCAL_TMUX_SESSION="${ODYSSEUS_LOCAL_TMUX_SESSION:-odysseus-local-$ODYSSEUS_LOCAL_PORT}"

odysseus_note() {
    printf '▶ %s\n' "$*"
}

odysseus_warn() {
    printf '⚠ %s\n' "$*" >&2
}

odysseus_fail() {
    printf '✗ %s\n' "$*" >&2
    exit 1
}

odysseus_have_cmd() {
    command -v "$1" >/dev/null 2>&1
}

odysseus_port_pids() {
    lsof -tiTCP:"$ODYSSEUS_LOCAL_PORT" -sTCP:LISTEN 2>/dev/null || true
}

odysseus_pid_cwd() {
    local pid="$1"
    lsof -a -p "$pid" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p' | head -n 1
}

odysseus_pid_descendants() {
    local parent="$1"
    local child children
    children="$(pgrep -P "$parent" 2>/dev/null || true)"
    for child in $children; do
        [ -n "$child" ] || continue
        printf '%s\n' "$child"
        odysseus_pid_descendants "$child"
    done
    return 0
}

odysseus_wait_for_port_down() {
    local attempts="${1:-50}"
    local i
    for i in $(seq 1 "$attempts"); do
        if ! odysseus_port_pids | grep -q .; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

odysseus_wait_for_http() {
    local attempts="${1:-90}"
    local i
    for i in $(seq 1 "$attempts"); do
        if curl -fsS "$ODYSSEUS_LOCAL_URL/api/auth/features" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

odysseus_python_for_venv() {
    if [ -n "${ODYSSEUS_LOCAL_PYTHON:-}" ]; then
        printf '%s\n' "$ODYSSEUS_LOCAL_PYTHON"
        return 0
    fi

    local cand path
    for cand in /opt/homebrew/bin/python3.13 /opt/homebrew/bin/python3.12 /opt/homebrew/bin/python3.11 python3.13 python3.12 python3.11 python3; do
        path="$(command -v "$cand" 2>/dev/null || true)"
        [ -n "$path" ] || continue
        if "$path" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3, 11) else 1)' 2>/dev/null; then
            printf '%s\n' "$path"
            return 0
        fi
    done
    return 1
}

odysseus_file_hash() {
    local file="$1"
    if odysseus_have_cmd md5; then
        md5 -q "$file"
    elif odysseus_have_cmd md5sum; then
        md5sum "$file" | awk '{print $1}'
    else
        python3 - "$file" <<'PY'
import hashlib
import pathlib
import sys

print(hashlib.md5(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())
PY
    fi
}
