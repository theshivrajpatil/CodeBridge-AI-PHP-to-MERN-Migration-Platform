"""Turn controlled MERN generation on or off by setting BOTH required switches.

    python scripts/enable_generation.py            # enable
    python scripts/enable_generation.py --disable  # back to the safe default

It edits only two git-ignored files inside this project folder (the tracked config is never touched):
  1. config/models.local.json  ->  {"generation_enabled": true}
  2. .env                      ->  CODEBRIDGE_GENERATION_ENABLED=1
Restart the server afterwards. Human approval is still required for every generation.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config" / "models.local.json"
ENV = ROOT / ".env"
KEY = "CODEBRIDGE_GENERATION_ENABLED"


def main(argv: list[str]) -> int:
    enable = "--disable" not in argv
    CONFIG.write_text(json.dumps({"generation_enabled": enable}, indent=2) + "\n", encoding="utf-8")

    lines = ENV.read_text(encoding="utf-8").splitlines() if ENV.exists() else []
    lines = [line for line in lines if not line.strip().lstrip("#").strip().startswith(KEY + "=")]
    lines.append(f"{KEY}=1" if enable else f"# {KEY}=1")
    ENV.write_text("\n".join(lines) + "\n", encoding="utf-8")

    state = "ENABLED" if enable else "DISABLED"
    print(f"Controlled generation {state}.")
    print(f"  {CONFIG.relative_to(ROOT)}: generation_enabled = {str(enable).lower()}")
    print(f"  {ENV.name}: {KEY}{'=1' if enable else ' not set'}")
    print("Restart the server for the change to take effect.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
