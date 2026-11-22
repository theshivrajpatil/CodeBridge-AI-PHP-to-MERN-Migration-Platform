"""Framework-neutral architecture views derived only from static source evidence.

Edges are directed from a dependent/source file to the file it references.
This module never executes PHP or claims runtime call order.
"""
from __future__ import annotations
from collections import Counter, defaultdict, deque
import re

ROLE_ALIASES = {
    "routes": "Routes", "route": "Routes", "controllers": "Controllers", "controller": "Controllers",
    "services": "Services", "service": "Services", "repositories": "Repositories",
    "repository": "Repositories", "models": "Models", "model": "Models", "entities": "Models",
    "database": "Database access", "migrations": "Schema / migrations", "tests": "Tests",
    "views": "Views", "templates": "Views", "config": "Configuration",
}


def _role(node: dict) -> str:
    if node.get("kind") == "DATABASE_BOUNDARY":
        return "Database access"
    raw = str(node.get("role") or node.get("classification", {}).get("group") or "Other")
    key = raw.strip().lower()
    return next((value for alias, value in ROLE_ALIASES.items()
                 if key == alias or key.startswith(alias + " ")), raw or "Other")


def _evidence_records(edge: dict) -> list[dict]:
    """Normalize edge evidence into explicit source-location records."""
    records = edge.get("evidence_records") or []
    normalized = []
    for record in records:
        if not isinstance(record, dict):
            continue
        normalized.append({
            "source_path": record.get("source_path") or edge.get("from"),
            "line": record.get("line") if isinstance(record.get("line"), int) else None,
            "declaration": str(record.get("declaration") or record.get("evidence") or "Static relationship"),
            "evidence_type": str(record.get("evidence_type") or edge.get("type") or "static_reference"),
        })
    for evidence in edge.get("evidence", []) or []:
        text = str(evidence)
        match = re.search(r"\bline\s+(\d+)\s*:\s*(.*)", text, re.I)
        record = {
            "source_path": edge.get("from"),
            "line": int(match.group(1)) if match else None,
            "declaration": match.group(2) if match else text,
            "evidence_type": str(edge.get("type") or "static_reference"),
        }
        if record not in normalized:
            normalized.append(record)
    return normalized


def _shortest_impact_paths(target: str, reverse: dict[str, set[str]]) -> dict[str, list[str]]:
    """Return dependent -> ... -> selected target paths, using shortest known paths."""
    result: dict[str, list[str]] = {}
    queue = deque([(target, [target])])
    visited = {target}
    while queue:
        current, path_to_target = queue.popleft()
        for dependent in sorted(reverse[current]):
            if dependent in visited:
                continue
            visited.add(dependent)
            result[dependent] = [dependent] + path_to_target
            queue.append((dependent, [dependent] + path_to_target))
    return result


def enrich_dependency_intelligence(dependency: dict, analysis: dict) -> dict:
    nodes = dependency.get("nodes", [])
    edges = dependency.get("edges", [])
    # Route dispatch: link only a uniquely resolved controller symbol.
    symbol_index: dict[str, list[str]] = defaultdict(list)
    for node in nodes:
        for symbol in node.get("symbols", []) or []:
            symbol_index[str(symbol).split("\\")[-1].lower()].append(node.get("id"))
    for route in (analysis.get("behavior_report") or {}).get("route_contracts", []):
        controller = route.get("controller")
        if not controller:
            continue
        short = str(controller).split("@")[0].split("::")[0].split("\\")[-1].lower()
        candidates = list(dict.fromkeys(symbol_index.get(short, [])))
        source = route.get("source_path")
        if source and len(candidates) == 1 and source != candidates[0]:
            edges.append({"from": source, "to": candidates[0], "type": "route_dispatches_to",
                          "evidence": [f"line {route.get('source_line')}: route controller {controller}"],
                          "confidence": route.get("confidence", "MEDIUM"),
                          "status": "STATIC_ROUTE_CONTRACT_REQUIRES_REVIEW"})

    # Database boundary edges are evidence signals, not live connection proof.
    if any(node.get("id") == "DATABASE:EXISTING_SYSTEM" for node in nodes):
        db_sources: dict[str, list[int]] = defaultdict(list)
        for collection in ("database_operations", "database_configuration_evidence", "database_schema_evidence"):
            for item in dependency.get(collection, []) or []:
                if item.get("source_path"):
                    db_sources[item["source_path"]].append(item.get("source_line"))
        node_ids = {node.get("id") for node in nodes}
        for source, lines in db_sources.items():
            if source in node_ids:
                line = next((value for value in lines if isinstance(value, int)), None)
                evidence = f"line {line}: static database/schema evidence" if line else "Static database/configuration evidence"
                edges.append({"from": source, "to": "DATABASE:EXISTING_SYSTEM", "type": "database_boundary_signal",
                              "evidence": [evidence], "confidence": "MEDIUM",
                              "status": "STATIC_DATABASE_BOUNDARY_REQUIRES_REVIEW"})

    by_id = {node.get("id"): node for node in nodes if node.get("id")}
    # Canonicalize duplicate edges and merge their evidence instead of silently
    # dropping evidence or allowing duplicate graph lines.
    canonical: dict[tuple, dict] = {}
    for edge in edges:
        src, dst, relation = edge.get("from"), edge.get("to"), edge.get("type") or "references"
        if not src or not dst or src == dst:
            continue
        key = (src, dst, relation)
        if key not in canonical:
            canonical[key] = {**edge, "from": src, "to": dst, "type": relation,
                              "evidence": list(edge.get("evidence") or []), "evidence_records": []}
        else:
            current = canonical[key]
            current["evidence"].extend(x for x in (edge.get("evidence") or []) if x not in current["evidence"])
            if current.get("confidence") != edge.get("confidence"):
                current["confidence"] = "MIXED"
        current = canonical[key]
        for record in _evidence_records(edge):
            if record not in current["evidence_records"]:
                current["evidence_records"].append(record)
    canonical_edges = list(canonical.values())

    adjacency: dict[str, set[str]] = defaultdict(set)
    reverse: dict[str, set[str]] = defaultdict(set)
    for edge in canonical_edges:
        src, dst = edge["from"], edge["to"]
        if src in by_id and dst in by_id:
            adjacency[src].add(dst)
            reverse[dst].add(src)

    # Connected components provide conservative subsystem clusters. Singletons
    # remain visible so unconnected source files are not silently discarded.
    unseen = set(by_id)
    subsystems = []
    while unseen:
        seed = min(unseen)
        queue, component = deque([seed]), set()
        unseen.remove(seed)
        while queue:
            current = queue.popleft()
            component.add(current)
            for neighbour in adjacency[current] | reverse[current]:
                if neighbour in unseen:
                    unseen.remove(neighbour)
                    queue.append(neighbour)
        members = sorted(component)
        role_counts = Counter(_role(by_id[path]) for path in members)
        roots = [path.split("/")[0] for path in members if "/" in path and not path.startswith("DATABASE:")]
        common = Counter(roots).most_common(1)[0][0] if roots else "repository"
        subsystems.append({"id": f"subsystem-{len(subsystems)+1:03d}",
                           "name": f"{common} · {', '.join(sorted(role_counts)[:3])}",
                           "files": members, "file_count": len(members),
                           "relationship_count": sum(1 for edge in canonical_edges
                                                      if edge["from"] in component and edge["to"] in component),
                           "roles": dict(sorted(role_counts.items())),
                           "status": "STATIC_CLUSTER_REQUIRES_REVIEW"})
    subsystems.sort(key=lambda item: (-item["file_count"], item["name"]))

    impact_index, impact_paths = {}, {}
    for target in by_id:
        paths = _shortest_impact_paths(target, reverse)
        impact_paths[target] = paths
        impact_index[target] = sorted(paths)

    # Paths are only shown where every directed edge was observed. This can
    # surface Route -> Controller -> Service -> Repository -> DB when present.
    architecture_paths = []
    for source in by_id:
        if _role(by_id[source]) not in {"Routes", "Controllers"}:
            continue
        queue = deque([(source, [source])])
        visited = {source}
        while queue:
            current, path = queue.popleft()
            if len(path) > 1 and _role(by_id[current]) in {"Database access", "Models"}:
                architecture_paths.append({"start": source, "end": current, "files": path,
                                           "roles": [_role(by_id[item]) for item in path],
                                           "evidence_edge_count": len(path) - 1,
                                           "status": "STATIC_PATH_REQUIRES_REVIEW"})
                continue
            for neighbour in sorted(adjacency[current]):
                if neighbour not in visited:
                    visited.add(neighbour)
                    queue.append((neighbour, path + [neighbour]))

    dependency["edges"] = canonical_edges
    dependency["edge_count"] = len(canonical_edges)
    dependency["subsystems"] = subsystems
    dependency["impact_index"] = impact_index
    dependency["impact_paths"] = impact_paths
    dependency["architecture_paths"] = architecture_paths
    dependency["architecture_summary"] = {
        "subsystem_count": len(subsystems),
        "files_in_subsystems": sum(item["file_count"] for item in subsystems),
        "evidence_path_count": len(architecture_paths),
        "edge_evidence_records": sum(len(edge.get("evidence_records", [])) for edge in canonical_edges),
        "framework_adapter": (analysis.get("framework_detection") or {}).get("adapter_id", "generic_php"),
        "framework_neutral_core": True,
    }
    return dependency
