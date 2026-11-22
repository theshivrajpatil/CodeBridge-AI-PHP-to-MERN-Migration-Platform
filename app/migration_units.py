"""Evidence-backed migration units and durable, tamper-evident human approvals.

Approval is deliberately separate from code generation authorization.
"""
from __future__ import annotations

from collections import deque
from contextlib import contextmanager
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Iterator
import fcntl
import json
import os
import tempfile
import uuid

DECISIONS = {"APPROVED", "REJECTED", "CHANGES_REQUESTED"}
STORE_VERSION = 2


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")


def _stable_id(paths: list[str]) -> str:
    return "unit-" + sha256("\n".join(sorted(paths)).encode()).hexdigest()[:12]


def _file_digest(root: Path, relative_path: str) -> str | None:
    try:
        base = root.resolve(strict=True)
        raw = base / relative_path
        if raw.is_symlink():
            return None
        candidate = raw.resolve(strict=True)
        candidate.relative_to(base)
        if not candidate.is_file():
            return None
        digest = sha256()
        with candidate.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, ValueError, RuntimeError):
        return None


def _target_area(group: str) -> str:
    mapping = {
        "Routes": "backend/routes", "HTTP / routing candidates": "backend/routes",
        "Controllers": "backend/controllers", "Services": "backend/services",
        "Repositories": "backend/data-access", "Models": "backend/data-access/contracts",
        "Models / entities": "backend/data-access/contracts", "Middleware": "backend/middleware",
        "Templates": "frontend/components-after-contract-review", "Views / templates": "frontend/components-after-contract-review",
        "Database migrations": "database/review-only", "Database seeders": "database/review-only",
        "Test data factories": "database/test-fixtures-review-only", "Tests": "tests/characterization-and-parity",
        "Configuration": "config/review-and-map", "Bootstrap": "runtime/startup-review",
        "Public entrypoints / assets": "runtime/entrypoints-and-assets-review",
    }
    return mapping.get(group, "migration-review/unclassified")


def build_migration_units(scan: dict, analysis: dict, plan: dict) -> list[dict]:
    files = analysis.get("files", [])
    by_path = {item.get("path"): item for item in files if item.get("path")}
    paths = sorted(by_path)
    graph = analysis.get("dependency_graph", {})
    edges = graph.get("edges", analysis.get("dependency_edges", []))
    adjacency = {path: set() for path in paths}
    valid_edges = []
    for edge in edges:
        source, target = edge.get("from"), edge.get("to")
        if source in adjacency and target in adjacency and source != target:
            adjacency[source].add(target)
            adjacency[target].add(source)
            valid_edges.append(edge)

    components, seen = [], set()
    for start in paths:
        if start in seen:
            continue
        queue, component = deque([start]), []
        seen.add(start)
        while queue:
            current = queue.popleft()
            component.append(current)
            for neighbour in sorted(adjacency[current]):
                if neighbour not in seen:
                    seen.add(neighbour)
                    queue.append(neighbour)
        components.append(sorted(component))

    group_for = {path: group for group, members in plan.get("php_file_groups", {}).items() for path in members}
    behaviour = analysis.get("behavior_report", {})
    dependency = analysis.get("dependency_intelligence", {})
    routes = behaviour.get("route_contracts", [])
    callables = behaviour.get("callable_contracts", [])
    schema_ops = dependency.get("database_schema_operations", [])
    schema_catalog = dependency.get("database_schema_catalog", [])
    root = Path(scan.get("root", "."))
    units = []

    for component in components:
        members = set(component)
        unit_edges = [edge for edge in valid_edges if edge.get("from") in members and edge.get("to") in members]
        unit_routes = [route for route in routes if route.get("source_path") in members]
        unit_callables = [callable_item for callable_item in callables if callable_item.get("source_path") in members]
        groups = sorted({group_for.get(path, by_path[path].get("classification", {}).get("group", "Other PHP")) for path in component})
        risks = []
        for path in component:
            item = by_path[path]
            if item.get("status") != "ANALYZED":
                risks.append(f"{path}: source was not fully analysed")
            if item.get("analysis_mode") != "TREE_SITTER_AST":
                risks.append(f"{path}: lexical/fallback analysis requires review")
            if item.get("database_signals"):
                risks.append(f"{path}: database behaviour requires parity tests")
            if item.get("route_candidates"):
                risks.append(f"{path}: route contract requires verification")
            if any("Dynamic" in str(signal) for signal in item.get("signals", [])):
                risks.append(f"{path}: dynamic execution/dispatch limits static confidence")
        if unit_routes:
            risks.append("Route authentication, authorization, validation and response semantics must be reviewed")
        operations = [item for item in schema_ops if item.get("source_path") in members]
        catalog = [item for item in schema_catalog if item.get("source_path") in members]
        if operations or catalog:
            risks.append("Schema evidence is static/history-based; deployed schema is not verified")

        digests = {path: _file_digest(root, path) for path in component}
        confidence = "LOW" if any(by_path[path].get("status") != "ANALYZED" or by_path[path].get("analysis_mode") != "TREE_SITTER_AST" for path in component) else "MEDIUM"
        symbols = {path: {key: by_path[path].get(key, []) for key in ("classes", "interfaces", "traits", "functions", "methods")} for path in component}
        target_areas = sorted({_target_area(group) for group in groups})
        # Bind approval to every reviewed decision input, not only source bytes.
        # A changed classification, confidence, risk or target mapping must
        # invalidate an earlier approval even when PHP files are unchanged.
        fingerprint_payload = {
            "paths": component, "edges": unit_edges, "digests": digests,
            "routes": unit_routes, "callables": unit_callables,
            "schema_operations": operations, "schema_catalog": catalog,
            "migration_groups": groups, "symbols": symbols,
            "proposed_target_areas": target_areas,
            "confidence": confidence, "risks": sorted(set(risks)),
        }
        fingerprint = sha256(_canonical(fingerprint_payload)).hexdigest()
        units.append({
            "unit_id": _stable_id(component), "status": "PENDING_REVIEW", "source_paths": component,
            "source_file_count": len(component), "migration_groups": groups,
            "proposed_target_areas": target_areas,
            "symbols": symbols,
            "dependency_edges": unit_edges, "dependency_edge_count": len(unit_edges),
            "route_contracts": unit_routes, "callable_contracts": unit_callables,
            "database_schema_operations": operations, "database_schema_candidates": catalog,
            "file_fingerprints": digests, "spec_fingerprint": fingerprint,
            "confidence": confidence,
            "risks": sorted(set(risks)) or ["No high-level static risk signal detected; manual review remains required"],
            "approval_required": True, "generation_authorized": False,
        })
    return sorted(units, key=lambda unit: unit["unit_id"])


def approval_store_path(workspace: Path, project_root: str) -> Path:
    key = sha256(str(Path(project_root).resolve()).encode()).hexdigest()[:16]
    return Path(workspace) / f"migration_approvals_{key}.json"


@contextmanager
def approval_store_lock(path: Path) -> Iterator[None]:
    """Serialize read-modify-write across threads and local processes."""
    lock_path = Path(str(path) + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _verify_audit_chain(data: dict) -> None:
    previous = "GENESIS"
    latest_decisions = {}
    for event in data.get("audit_log", []):
        if event.get("legacy_imported"):
            latest_decisions[f"{event.get('unit_id')}:{event.get('spec_fingerprint') or 'unfingerprinted'}"] = {
                key: value for key, value in event.items() if key != "legacy_imported"
            }
            continue
        claimed_previous = event.get("previous_event_hash")
        claimed_hash = event.get("event_hash")
        if claimed_previous != previous or not claimed_hash:
            raise ValueError("Approval audit integrity check failed: broken event chain")
        payload = {key: value for key, value in event.items() if key != "event_hash"}
        expected = sha256(previous.encode() + _canonical(payload)).hexdigest()
        if claimed_hash != expected:
            raise ValueError("Approval audit integrity check failed: event content was modified")
        previous = claimed_hash
        latest_decisions[f"{event.get('unit_id')}:{event.get('spec_fingerprint') or 'unfingerprinted'}"] = dict(event)
    # The lookup index is checked against the append-only history, so changing
    # only the current-decision map cannot silently change the displayed state.
    if _canonical(data.get("decisions", {})) != _canonical(latest_decisions):
        raise ValueError("Approval audit integrity check failed: decision index does not match audit history")


def load_approval_store(path: Path) -> dict:
    path = Path(path)
    if not path.exists():
        return {"store_version": STORE_VERSION, "decisions": {}, "audit_log": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("decisions"), dict) or not isinstance(data.get("audit_log"), list):
            raise ValueError("Invalid approval store structure")
        # V1 decisions are retained as historical records, but their audit events
        # are explicitly marked as legacy because they predate hash chaining.
        for event in data["audit_log"]:
            if "event_hash" not in event:
                event["legacy_imported"] = True
        data["store_version"] = STORE_VERSION
        _verify_audit_chain(data)
        return data
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read approval store safely: {exc}") from exc


def save_approval_store(path: Path, data: dict) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, indent=2, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        # Persist directory entry on filesystems that support directory fsync.
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def apply_decision(unit: dict, store: dict, decision: str, actor: str, reason: str) -> dict:
    decision = decision.strip().upper()
    actor = actor.strip()
    reason = reason.strip()
    if decision not in DECISIONS:
        raise ValueError("Decision must be APPROVED, REJECTED, or CHANGES_REQUESTED")
    if not actor or len(actor) > 120:
        raise ValueError("Reviewer identifier is required (1-120 characters)")
    if not reason or len(reason) > 2000:
        raise ValueError("Review reason is required (1-2000 characters)")
    if unit.get("source_validation", {}).get("valid") is False:
        raise ValueError("Source files changed after analysis; regenerate the specification before deciding")

    fingerprint = unit.get("spec_fingerprint")
    if not fingerprint:
        raise ValueError("Migration unit has no specification fingerprint")
    decision_key = f"{unit['unit_id']}:{fingerprint}"
    record = {
        "event_id": str(uuid.uuid4()), "unit_id": unit["unit_id"], "decision": decision,
        "actor": actor, "reason": reason, "decided_at": datetime.now(timezone.utc).isoformat(),
        "spec_fingerprint": fingerprint, "file_fingerprints": unit.get("file_fingerprints", {}),
        "generation_authorized": False,
    }
    previous = next((event.get("event_hash") for event in reversed(store.get("audit_log", [])) if event.get("event_hash")), "GENESIS")
    record["previous_event_hash"] = previous
    record["event_hash"] = sha256(previous.encode() + _canonical(record)).hexdigest()
    store.setdefault("decisions", {})[decision_key] = record
    store.setdefault("audit_log", []).append(dict(record))
    unit["status"] = decision
    unit["approval"] = record
    unit["generation_authorized"] = False
    return record


def validate_unit_sources(unit: dict, project_root: str) -> tuple[bool, list[str]]:
    """Confirm every reviewed source file has a captured digest and still matches it."""
    expected_digests = unit.get("file_fingerprints")
    source_paths = set(unit.get("source_paths") or [])
    if not isinstance(expected_digests, dict) or not source_paths or set(expected_digests) != source_paths:
        missing = sorted(source_paths.symmetric_difference(set(expected_digests or {})))
        return False, missing or sorted(source_paths)
    changed = []
    for relative_path, expected in expected_digests.items():
        current = _file_digest(Path(project_root), relative_path)
        if not isinstance(expected, str) or current is None or current != expected:
            changed.append(relative_path)
    return not changed, changed
