#!/bin/bash
#
# StrikeHound ZAP auth verification (Kali / Debian / general Linux).
#
# Boots ZAP as a daemon (or uses one you already run), then exercises the
# exact REST/context/auth calls StrikeHound makes at scan time:
#   context creation -> target scoping -> form/header auth -> user creation
#
# Usage:
#   ./scripts/verify_zap_auth.sh                                  # unauthenticated check
#   ./scripts/verify_zap_auth.sh \
#       --target https://app.example.com \
#       --username svc-audit --password 's3cret' \
#       --login-url https://app.example.com/login
#
# Exit 0 = OK, non-zero = a check failed (the script prints which step).
#
set -euo pipefail

ZAP_URL="${ZAP_URL:-http://localhost:8080}"
ZAP_PORT="${ZAP_PORT:-8080}"
ZAP_PATH="${ZAP_PATH:-$(command -v zap.sh || command -v zaproxy || echo '')}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="${VENV:-$SCRIPT_DIR/../venv}"
if [ -x "$VENV/bin/python" ]; then
  PYTHON="$VENV/bin/python"
else
  PYTHON="$(command -v python3 || echo python)"
fi

EXTRA_ARGS=(--url "$ZAP_URL")
STARTED_ZAP=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)      EXTRA_ARGS+=(--target "$2"); shift 2 ;;
    --username)    EXTRA_ARGS+=(--username "$2"); shift 2 ;;
    --password)    EXTRA_ARGS+=(--password "$2"); shift 2 ;;
    --login-url)   EXTRA_ARGS+=(--login-url "$2"); shift 2 ;;
    --url)         ZAP_URL="$2"; EXTRA_ARGS=(--url "$ZAP_URL"); shift 2 ;;
    --zap-path)    ZAP_PATH="$2"; shift 2 ;;
    *) echo "[!] Unknown argument: $1" >&2; exit 2 ;;
  esac
done

echo "=== StrikeHound ZAP auth verification ==="
echo "ZAP URL: $ZAP_URL"

if curl -fsS "$ZAP_URL/JSON/core/view/version/" >/dev/null 2>&1; then
  echo "[+] ZAP already running."
elif [ -n "$ZAP_PATH" ]; then
  echo "[*] Starting ZAP daemon: $ZAP_PATH -daemon -port $ZAP_PORT -config api.disablekey=true"
  "$ZAP_PATH" -daemon -port "$ZAP_PORT" -config "api.disablekey=true" >/dev/null 2>&1 &
  STARTED_ZAP=1
  for _ in $(seq 1 60); do
    if curl -fsS "$ZAP_URL/JSON/core/view/version/" >/dev/null 2>&1; then
      break
    fi
    sleep 2
  done
else
  echo "[!] ZAP is not running and no zap.sh/zaproxy found on PATH."
  echo "    Install it (sudo apt install -y zaproxy) or export ZAP_PATH=/path/to/zap.sh"
  exit 1
fi

set +e
cd "$SCRIPT_DIR/.."
"$PYTHON" scripts/zap_env_check.py "${EXTRA_ARGS[@]}"
RESULT=$?
set -e

if [ "$STARTED_ZAP" -eq 1 ]; then
  echo "[*] Shutting down the ZAP daemon we started..."
  curl -fsS "$ZAP_URL/JSON/core/action/shutdown/" >/dev/null 2>&1 || true
fi

echo
if [ "$RESULT" -eq 0 ]; then
  echo "[+] ZAP auth verification passed."
else
  echo "[!] ZAP auth verification FAILED (see above)."
fi
exit "$RESULT"