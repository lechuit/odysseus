#!/usr/bin/env bash
# Check the local desktop Odysseus install.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/_lib/local_runtime.sh"

JSON=0

usage() {
    cat <<'USAGE'
Usage: scripts/healthcheck_local.sh [--json]

Environment:
  ODYSSEUS_LOCAL_HOST   Host to probe. Default: 127.0.0.1
  ODYSSEUS_LOCAL_PORT   Port to probe. Default: 7860
USAGE
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --json) JSON=1 ;;
        -h|--help) usage; exit 0 ;;
        *) odysseus_fail "Unknown option: $1" ;;
    esac
    shift
done

PIDS="$(odysseus_port_pids | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
FEATURES=""
MODELS_STATUS="unreachable"
OK=0

if FEATURES="$(curl -fsS "$ODYSSEUS_LOCAL_URL/api/auth/features" 2>/dev/null)"; then
    OK=1
fi

MODELS_HTTP_CODE="$(curl -sS -o /dev/null -w '%{http_code}' "$ODYSSEUS_LOCAL_URL/api/model-endpoints" 2>/dev/null || true)"
if [ "$MODELS_HTTP_CODE" = "200" ]; then
    MODELS_STATUS="ok"
elif [ "$MODELS_HTTP_CODE" = "401" ] || [ "$MODELS_HTTP_CODE" = "403" ]; then
    MODELS_STATUS="auth_required"
elif [ -n "$MODELS_HTTP_CODE" ] && [ "$MODELS_HTTP_CODE" != "000" ]; then
    MODELS_STATUS="http_$MODELS_HTTP_CODE"
fi

if [ "$JSON" -eq 1 ]; then
    python3 - "$OK" "$ODYSSEUS_LOCAL_URL" "$PIDS" "$MODELS_STATUS" "$FEATURES" <<'PY'
import json
import sys

ok = sys.argv[1] == "1"
url = sys.argv[2]
pids = [p for p in sys.argv[3].split() if p]
models_status = sys.argv[4]
features_raw = sys.argv[5] if len(sys.argv) > 5 else ""
try:
    features = json.loads(features_raw) if features_raw else None
except json.JSONDecodeError:
    features = features_raw
print(json.dumps({
    "ok": ok,
    "url": url,
    "pids": pids,
    "features": features,
    "model_endpoints": models_status,
}, ensure_ascii=False))
PY
else
    if [ "$OK" -eq 1 ]; then
        odysseus_note "Odysseus is healthy at $ODYSSEUS_LOCAL_URL"
        [ -n "$PIDS" ] && printf '  pid(s): %s\n' "$PIDS"
        printf '  features: %s\n' "$FEATURES"
        printf '  model endpoints: %s\n' "$MODELS_STATUS"
    else
        odysseus_warn "Odysseus is not responding at $ODYSSEUS_LOCAL_URL"
        [ -n "$PIDS" ] && printf '  listening pid(s): %s\n' "$PIDS" >&2
    fi
fi

[ "$OK" -eq 1 ]
