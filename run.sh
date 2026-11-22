#!/usr/bin/env bash
# One-command launcher (macOS / Linux).
#   ./run.sh                       start CodeBridge AI (generation stays disabled)
#   ./run.sh --enable-generation   also turn on controlled generation, then start
# First run creates a .venv and installs requirements.txt (needs internet once).
set -euo pipefail
cd "$(dirname "$0")"

PYTHON_BIN="${PYTHON:-python3}"
if [ ! -d .venv ]; then
  "$PYTHON_BIN" -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install -q -r requirements.txt

if [ "${1:-}" = "--enable-generation" ]; then
  python scripts/enable_generation.py
fi

echo "Open http://127.0.0.1:8000  (Ctrl+C to stop)"
exec python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
