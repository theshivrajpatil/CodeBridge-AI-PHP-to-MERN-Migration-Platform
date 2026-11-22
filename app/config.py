from pathlib import Path
import os
PROJECT_ROOT = Path(__file__).resolve().parent.parent
WORKSPACE = PROJECT_ROOT / "workspace"
WORKSPACE.mkdir(exist_ok=True)
DEFAULT_MODEL = os.getenv("CODEBRIDGE_MODEL", "qwen2.5-coder:3b")
DEFAULT_OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")
MAX_FILE_BYTES = 256_000
MAX_FILES = 20_000
SKIP_DIRS = {".git", ".svn", ".hg", "node_modules", "vendor", "dist", "build", ".next", ".venv", "venv", "__pycache__", "coverage", "storage", "cache", "logs", "tmp"}
