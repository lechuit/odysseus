#!/usr/bin/env bash
# Synchronize the repository into the local desktop Odysseus install.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_lib/local_runtime.sh"

INSTALL_DEPS=1
RUN_SETUP=1
RUN_COMPILE=1

usage() {
    cat <<'USAGE'
Usage: scripts/install_local.sh [--no-deps] [--no-setup] [--no-compile]

Environment:
  ODYSSEUS_LOCAL_DIR      Destination install directory.
                           Default: ~/Library/Application Support/Odysseus
  ODYSSEUS_LOCAL_PYTHON   Python 3.11+ used to create the local venv when absent.
USAGE
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --no-deps) INSTALL_DEPS=0 ;;
        --no-setup) RUN_SETUP=0 ;;
        --no-compile) RUN_COMPILE=0 ;;
        -h|--help) usage; exit 0 ;;
        *) odysseus_fail "Unknown option: $1" ;;
    esac
    shift
done

[ -d "$ODYSSEUS_REPO_DIR" ] || odysseus_fail "Repo directory not found: $ODYSSEUS_REPO_DIR"
[ -f "$ODYSSEUS_REPO_DIR/app.py" ] || odysseus_fail "app.py not found in repo: $ODYSSEUS_REPO_DIR"
odysseus_have_cmd rsync || odysseus_fail "rsync is required"

odysseus_note "Syncing repo to local install"
printf '  source: %s\n' "$ODYSSEUS_REPO_DIR"
printf '  target: %s\n' "$ODYSSEUS_LOCAL_DIR"
mkdir -p "$ODYSSEUS_LOCAL_DIR"

EXCLUDES="$(mktemp)"
cleanup_excludes() {
    rm -f "$EXCLUDES"
}
trap cleanup_excludes EXIT

cat > "$EXCLUDES" <<'EOF'
.git/
.pytest_cache/
.ruff_cache/
.mypy_cache/
.DS_Store
__pycache__/
*.pyc
*.pyo
*.log
.env
.env.*
secrets.env.*
venv/
.venv/
data/
logs/
node_modules/
services/node_modules/
services/data/
reports/
tasks/
research_data/
_scratch/
EOF

rsync -a --delete --exclude-from="$EXCLUDES" "$ODYSSEUS_REPO_DIR/" "$ODYSSEUS_LOCAL_DIR/"

VENV_PY="$ODYSSEUS_LOCAL_DIR/venv/bin/python"
if [ "$INSTALL_DEPS" -eq 1 ]; then
    if [ ! -x "$VENV_PY" ]; then
        PY="$(odysseus_python_for_venv)" || odysseus_fail "Could not find Python 3.11+"
        odysseus_note "Creating local venv with $PY"
        "$PY" -m venv "$ODYSSEUS_LOCAL_DIR/venv"
    fi

    REQ_FILE="$ODYSSEUS_LOCAL_DIR/requirements.txt"
    REQ_HASH_FILE="$ODYSSEUS_LOCAL_DIR/venv/.requirements_hash"
    if [ -f "$REQ_FILE" ]; then
        REQ_HASH="$(odysseus_file_hash "$REQ_FILE")"
        if [ ! -f "$REQ_HASH_FILE" ] || [ "$REQ_HASH" != "$(cat "$REQ_HASH_FILE" 2>/dev/null)" ]; then
            odysseus_note "Installing/updating local Python requirements"
            "$VENV_PY" -m pip install --quiet --upgrade pip
            "$VENV_PY" -m pip install -r "$REQ_FILE"
            printf '%s\n' "$REQ_HASH" > "$REQ_HASH_FILE"
        else
            odysseus_note "Python requirements already up to date"
        fi
    fi
else
    odysseus_note "Skipping dependency check"
fi

if [ "$RUN_SETUP" -eq 1 ]; then
    [ -x "$VENV_PY" ] || odysseus_fail "Local venv missing: $VENV_PY"
    odysseus_note "Running setup.py idempotently"
    (cd "$ODYSSEUS_LOCAL_DIR" && ODYSSEUS_SKIP_RUN_HINT=1 "$VENV_PY" setup.py)
fi

if [ "$RUN_COMPILE" -eq 1 ]; then
    [ -x "$VENV_PY" ] || odysseus_fail "Local venv missing: $VENV_PY"
    odysseus_note "Compiling changed Python sources"
    (cd "$ODYSSEUS_LOCAL_DIR" && "$VENV_PY" -m compileall -q app.py routes src mcp_servers)
fi

odysseus_note "Local install is synchronized"
