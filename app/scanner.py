from pathlib import Path
from collections import Counter
import os
from app.config import SKIP_DIRS, MAX_FILES

def scan_repository(root_path: str) -> dict:
    root = Path(root_path).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Repository path must be a directory.")
    files, errors, php_files = [], [], []
    extensions = Counter()
    total_bytes = 0
    truncated = False
    for current, dirs, names in os.walk(root, followlinks=False):
        base = Path(current)
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not (base / d).is_symlink())
        for name in sorted(names):
            path = base / name
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                rel, size = path.relative_to(root).as_posix(), path.stat().st_size
                ext = path.suffix.lower() or "[no extension]"
                extensions[ext] += 1
                total_bytes += size
                item = {"path": rel, "extension": ext, "size_bytes": size}
                files.append(item)
                if ext in {".php", ".phtml", ".inc"}: php_files.append(item)
                if len(files) >= MAX_FILES:
                    errors.append(f"File limit reached ({MAX_FILES}); scan truncated.")
                    truncated = True
                    break
            except OSError as exc:
                errors.append(f"{name}: {type(exc).__name__}")
        if truncated: break
    names = {Path(x["path"]).name.lower() for x in files}
    paths = {x["path"].lower() for x in files}
    hints = []
    if "composer.json" in names: hints.append("Composer dependency manifest found")
    if any(p.endswith("/routes/web.php") or p == "routes/web.php" for p in paths): hints.append("Route-file convention detected")
    if any("controller" in Path(p).name.lower() for p in paths): hints.append("Controller naming convention detected")
    if any("model" in Path(p).name.lower() for p in paths): hints.append("Model naming convention detected")
    if not hints and php_files: hints.append("PHP application detected; framework not assumed")
    return {"root": str(root), "file_count": len(files), "php_file_count": len(php_files),
            "total_bytes": total_bytes, "extensions": dict(extensions.most_common()),
            "php_files": php_files[:500], "framework_hints": hints, "warnings": errors, "files": files}
