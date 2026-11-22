"""Framework detection/classification through optional adapters.

Universal PHP parsing is independent of this registry. Adapters add conventions only.
"""
from pathlib import PurePosixPath
from app.framework_adapters import ADAPTERS


def detect_framework(scan: dict) -> dict:
    paths = {str(x.get("path", "")).replace("\\", "/").lower().lstrip("./") for x in scan.get("files", [])}
    for adapter in ADAPTERS:
        detection = adapter.detect(paths)
        if detection and detection.name not in {"Core PHP / Unknown", "PHP (framework not confirmed)"}:
            return {"name": detection.name, "confidence": detection.confidence,
                    "evidence": detection.evidence, "adapter_id": detection.adapter_id,
                    "analysis_scope": "UNIVERSAL_PHP_CORE_WITH_FRAMEWORK_ADAPTER"}
    generic = ADAPTERS[-1].detect(paths)
    return {"name": generic.name, "confidence": generic.confidence, "evidence": generic.evidence,
            "adapter_id": generic.adapter_id, "analysis_scope": "UNIVERSAL_PHP_CORE"}


def classify_php_path(path: str, framework: str = "") -> dict:
    normalized = PurePosixPath(path.replace("\\", "/")).as_posix().lower().strip("/")
    for adapter in ADAPTERS:
        if framework and adapter.display_name.lower() == framework.lower():
            result = adapter.classify(normalized)
            if result: return result
    # When framework is unknown, generic path conventions may provide low-confidence hints.
    generic = next(a for a in ADAPTERS if a.adapter_id == "generic_php")
    result = generic.classify("/" + normalized)
    if result: return result
    name = PurePosixPath(normalized).name
    if name.endswith(("test.php", "tests.php")):
        return {"group": "Tests", "confidence": "LOW", "reason": "Filename convention only"}
    if normalized.startswith(("public/", "www/")):
        return {"group": "Public entrypoints / assets", "confidence": "LOW", "reason": "Public web-root convention"}
    return {"group": "Unclassified PHP", "confidence": "LOW", "reason": "No reliable framework or path convention detected"}
