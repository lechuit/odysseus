#!/usr/bin/env bash
# Sync and restart the local desktop Odysseus server.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_lib/local_runtime.sh"

RUN_INSTALL=1
WAIT_FOR_READY=1
FORCE_STOP="${ODYSSEUS_FORCE_STOP:-0}"

usage() {
    cat <<'USAGE'
Usage: scripts/restart_local.sh [--no-install] [--no-wait] [--force]

By default this script:
  1. syncs the repo into ~/Library/Application Support/Odysseus,
  2. stops the local uvicorn process on the configured port,
  3. starts Odysseus in the background,
  4. waits until /api/auth/features responds.

Environment:
  ODYSSEUS_LOCAL_DIR     Local install directory.
  ODYSSEUS_LOCAL_HOST    Host to bind. Default: 127.0.0.1
  ODYSSEUS_LOCAL_PORT    Port to bind. Default: 7860
  ODYSSEUS_LOCAL_LOG     Log file. Default: ~/Library/Logs/Odysseus/odysseus-local.log
  ODYSSEUS_LOCAL_RUNNER  auto|tmux|nohup. Default: auto (tmux when available).
  ODYSSEUS_LOCAL_TMUX_SESSION  tmux session name when using tmux.
  ODYSSEUS_FORCE_STOP=1  Stop any process on the port even if cwd is unexpected.
USAGE
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --no-install) RUN_INSTALL=0 ;;
        --no-wait) WAIT_FOR_READY=0 ;;
        --force) FORCE_STOP=1 ;;
        -h|--help) usage; exit 0 ;;
        *) odysseus_fail "Unknown option: $1" ;;
    esac
    shift
done

if [ "$RUN_INSTALL" -eq 1 ]; then
    "$SCRIPT_DIR/install_local.sh"
fi

VENV_PY="$ODYSSEUS_LOCAL_DIR/venv/bin/python"
[ -x "$VENV_PY" ] || odysseus_fail "Local venv missing: $VENV_PY"

RUNNER="${ODYSSEUS_LOCAL_RUNNER:-auto}"
if [ "$RUNNER" = "auto" ]; then
    if odysseus_have_cmd tmux; then
        RUNNER="tmux"
    else
        RUNNER="nohup"
    fi
fi
case "$RUNNER" in
    tmux|nohup) ;;
    *) odysseus_fail "Invalid ODYSSEUS_LOCAL_RUNNER=$RUNNER (expected auto, tmux, or nohup)" ;;
esac

if [ "$RUNNER" = "tmux" ] && odysseus_have_cmd tmux; then
    if tmux has-session -t "$ODYSSEUS_LOCAL_TMUX_SESSION" 2>/dev/null; then
        odysseus_note "Stopping tmux session $ODYSSEUS_LOCAL_TMUX_SESSION"
        tmux kill-session -t "$ODYSSEUS_LOCAL_TMUX_SESSION" 2>/dev/null || true
        sleep 0.3
    fi
elif [ "$RUNNER" = "tmux" ]; then
    odysseus_fail "tmux runner requested but tmux is not installed"
fi

PIDS="$(odysseus_port_pids)"
if [ -n "$PIDS" ]; then
    odysseus_note "Stopping existing Odysseus process on port $ODYSSEUS_LOCAL_PORT"
    for pid in $PIDS; do
        CWD="$(odysseus_pid_cwd "$pid")"
        if [ "$FORCE_STOP" != "1" ] && [ "$CWD" != "$ODYSSEUS_LOCAL_DIR" ]; then
            odysseus_fail "Port $ODYSSEUS_LOCAL_PORT is owned by pid $pid with cwd '$CWD'. Re-run with --force to stop it."
        fi
        DESCENDANTS="$(odysseus_pid_descendants "$pid" | sort -rn | tr '\n' ' ')"
        kill -TERM $DESCENDANTS "$pid" 2>/dev/null || true
    done

    if ! odysseus_wait_for_port_down 50; then
        odysseus_warn "Process did not stop gracefully; forcing shutdown"
        for pid in $(odysseus_port_pids); do
            DESCENDANTS="$(odysseus_pid_descendants "$pid" | sort -rn | tr '\n' ' ')"
            kill -KILL $DESCENDANTS "$pid" 2>/dev/null || true
        done
        odysseus_wait_for_port_down 25 || odysseus_fail "Port $ODYSSEUS_LOCAL_PORT is still busy"
    fi
else
    odysseus_note "No local Odysseus process is listening on port $ODYSSEUS_LOCAL_PORT"
fi

mkdir -p "$ODYSSEUS_LOCAL_LOG_DIR"
rm -f "$ODYSSEUS_LOCAL_PIDFILE"
: > "$ODYSSEUS_LOCAL_LOG"

odysseus_note "Starting Odysseus at $ODYSSEUS_LOCAL_URL"
printf '  log: %s\n' "$ODYSSEUS_LOCAL_LOG"
if [ "$RUNNER" = "tmux" ]; then
    printf '  runner: tmux session %s\n' "$ODYSSEUS_LOCAL_TMUX_SESSION"
    _q_local_dir="$(printf '%q' "$ODYSSEUS_LOCAL_DIR")"
    _q_pidfile="$(printf '%q' "$ODYSSEUS_LOCAL_PIDFILE")"
    _q_venv_py="$(printf '%q' "$VENV_PY")"
    _q_host="$(printf '%q' "$ODYSSEUS_LOCAL_HOST")"
    _q_port="$(printf '%q' "$ODYSSEUS_LOCAL_PORT")"
    _q_log="$(printf '%q' "$ODYSSEUS_LOCAL_LOG")"
    _tmux_cmd="cd $_q_local_dir && printf '%s\n' \\\$\\\$ > $_q_pidfile && exec $_q_venv_py -m uvicorn app:app --host $_q_host --port $_q_port >> $_q_log 2>&1"
    tmux new-session -d -s "$ODYSSEUS_LOCAL_TMUX_SESSION" "$_tmux_cmd"
else
    printf '  runner: nohup\n'
    (
        cd "$ODYSSEUS_LOCAL_DIR"
        nohup "$VENV_PY" -m uvicorn app:app --host "$ODYSSEUS_LOCAL_HOST" --port "$ODYSSEUS_LOCAL_PORT" > "$ODYSSEUS_LOCAL_LOG" 2>&1 &
        printf '%s\n' "$!" > "$ODYSSEUS_LOCAL_PIDFILE"
    )
fi

if [ "$WAIT_FOR_READY" -eq 1 ]; then
    if odysseus_wait_for_http 120; then
        odysseus_note "Odysseus is ready"
        "$SCRIPT_DIR/healthcheck_local.sh"
    else
        odysseus_warn "Odysseus did not become ready in time"
        tail -n 80 "$ODYSSEUS_LOCAL_LOG" >&2 || true
        exit 1
    fi
else
    odysseus_note "Started without waiting"
fi
