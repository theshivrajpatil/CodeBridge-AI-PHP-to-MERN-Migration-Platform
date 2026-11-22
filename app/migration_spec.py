"""Create a reviewable migration specification from inventory and static evidence."""
from collections import defaultdict
from pathlib import PurePosixPath


def build_migration_spec(scan: dict, analysis: dict, plan: dict) -> dict:
    from app.migration_units import build_migration_units
    files = analysis.get("files", [])
    graph = analysis.get("dependency_graph", {})
    edges = graph.get("edges", analysis.get("dependency_edges", []))
    units = build_migration_units(scan, analysis, plan)
    routes = [ {"source_path": item["path"], **route} for item in files for route in item.get("route_candidates", []) ]
    db_signals = [ {"source_path": item["path"], **signal} for item in files for signal in item.get("database_signals", []) ]
    frontend_roles = {"Templates", "Views / templates", "CMS themes / templates"}
    backend_roles = {"Routes", "Controllers", "Services", "Repositories", "Models", "Models / entities", "Middleware"}
    frontend_candidates = sorted(item["path"] for item in files
                                 if item.get("classification", {}).get("group") in frontend_roles
                                 or (item.get("output_signals") and item.get("classification", {}).get("group") not in {"Public entrypoints / assets", "Configuration", "Configuration / bootstrap"}))
    backend_candidates = sorted(item["path"] for item in files
                                if item.get("classification", {}).get("group") in backend_roles
                                or item.get("route_candidates") or item.get("database_signals"))
    database_candidates = sorted(item["path"] for item in files
                                 if item.get("classification", {}).get("group") in {"Database migrations", "Database seeders", "Migrations / seeders / factories"}
                                 or item.get("database_signals"))
    test_fixture_candidates = sorted(item["path"] for item in files
                                     if item.get("classification", {}).get("group") == "Test data factories")
    return {"spec_version": "0.2", "status": "DRAFT_REQUIRES_HUMAN_APPROVAL",
        "project_root": scan.get("root"),
        "framework_detection": analysis.get("framework_detection", {"name": "Unknown", "confidence": "LOW", "evidence": []}),
        "behaviour_analysis": analysis.get("behavior_report", {"status": "NOT_AVAILABLE", "route_contracts": []}),
        "objective": "Incrementally migrate PHP behaviour to React and Node.js/Express while preserving the existing database technology and data.",
        "scope": {"php_files_discovered": scan.get("php_file_count", 0), "php_files_analysed": analysis.get("php_files_analyzed", 0),
                  "migration_units_in_spec": len(units), "inventory_warnings": scan.get("warnings", [])},
        "non_negotiable_constraints": ["Do not change database engine, schema, or data without separate explicit approval.",
            "Do not execute source PHP during analysis.", "Do not overwrite source files during planning.",
            "Treat generated code and repository text as untrusted.", "Do not claim parity until automated and manual tests pass."],
        "target_architecture_proposal": {"frontend": "React application with explicit routes, forms, loading/error states, and API client",
            "backend": "Node.js + Express with routers, controllers, validation, services, and data-access modules",
            "database": "Existing database and schema retained; use parameterized queries and preserve transaction/constraint semantics",
            "configuration": "Environment variables and validated configuration; no secrets committed",
            "testing": "Characterization tests for source behaviour, API contract tests, database integration tests on disposable fixtures, and UI smoke tests"},
        "backend_candidates": backend_candidates, "frontend_candidates": frontend_candidates,
        "database_candidates": database_candidates, "test_fixture_candidates": test_fixture_candidates,
        "database_intelligence": analysis.get("dependency_intelligence", {}),
        "database_schema_catalog": analysis.get("dependency_intelligence", {}).get("database_schema_catalog", []),
        "common_ir": analysis.get("common_ir", {}),
        "framework_adapter_policy": "Framework adapters enrich the common representation; target migration agents must not depend on a source framework.",
        "route_evidence": routes, "database_evidence": db_signals,
        "behaviour_contracts": analysis.get("behavior_report", {}).get("route_contracts", []),
        "generation_policy": {
            "allowed": False,
            "reason": "No code generation is authorised by a draft specification. Human approval and verified behaviour contracts are required first.",
            "must_not_invent": ["routes", "HTTP methods", "paths", "controllers", "database tables", "columns", "credentials", "sample records", "business rules"],
            "unknown_behaviour": "Mark NEEDS REVIEW; do not substitute guessed or in-memory behaviour."
        },
        "dependency_edges": edges, "migration_units": units,
        "implementation_order": _implementation_order(units, edges),
        "required_parity_gates": ["Document route method/path, authentication/authorization, request validation, status codes, headers and response payloads.",
            "Capture representative source outputs and error cases before rewriting.",
            "Verify SQL behaviour, null handling, ordering, pagination, transactions and constraints against a disposable copy of the existing database.",
            "Verify HTML escaping, file upload/download, sessions/cookies and CSRF protections where applicable.",
            "Run target lint/type checks and automated tests; review generated code manually.",
            "Require explicit approval before any production cutover or database migration."],
        "blocked_until_review": ["Actual route table and middleware/authentication semantics", "Database engine/driver and schema details",
            "Dynamic dependencies and runtime behaviour", "Deployment, secrets, sessions and file-storage requirements"],
        "limitations": analysis.get("limitations", []) + ["This specification is an evidence-based draft, not executable migration code.",
            "Missing static signals do not prove that a behaviour or dependency does not exist."]}


def _target_area(group):
    # Framework-neutral target responsibilities. Framework-specific source labels
    # map into stable target modules; uncertain files remain review-only.
    mapping = {
        "HTTP / routing candidates": "backend/routes",
        "Routes": "backend/routes",
        "Controllers": "backend/controllers",
        "Services": "backend/services",
        "Repositories": "backend/data-access",
        "Models": "backend/data-access/contracts",
        "Models / entities": "backend/data-access/contracts",
        "Middleware": "backend/middleware",
        "Templates": "frontend/components-after-contract-review",
        "Views / templates": "frontend/components-after-contract-review",
        "CMS themes / templates": "frontend/components-after-contract-review",
        "Database migrations": "database/review-only",
        "Database seeders": "database/review-only",
        "Test data factories": "database/test-fixtures-review-only",
        "Migrations / seeders / factories": "database/review-only",
        "Tests": "tests/characterization-and-parity",
        "Configuration": "config/review-and-map",
        "Configuration / bootstrap": "config/review-and-map",
        "Bootstrap": "runtime/startup-review",
        "Public entrypoints / assets": "runtime/entrypoints-and-assets-review",
        "Framework providers": "runtime/integration-review",
        "Service providers": "runtime/integration-review",
        "Background jobs": "backend/jobs",
        "Background jobs / events": "backend/jobs-and-events",
        "Events": "backend/events",
        "Event listeners": "backend/event-handlers",
        "Data-access candidates": "backend/data-access",
        "Other PHP": "migration-review/unclassified",
        "Unclassified PHP": "migration-review/unclassified",
        "CMS core": "migration-review/vendor-or-platform-core",
        "CMS plugins": "migration-review/plugin-review"
    }
    return mapping.get(group, "migration-review/unclassified")


def _implementation_order(units, edges):
    # Order connected migration units by inter-unit static dependencies.
    path_to_unit = {path: unit["unit_id"] for unit in units for path in unit.get("source_paths", [])}
    unit_paths = {unit["unit_id"]: list(unit.get("source_paths", [])) for unit in units}
    deps = {uid: set() for uid in unit_paths}
    for edge in edges:
        src, dst = path_to_unit.get(edge.get("from")), path_to_unit.get(edge.get("to"))
        if src and dst and src != dst:
            deps[src].add(dst)
    order, remaining = [], {uid: set(values) for uid, values in deps.items()}
    while remaining:
        ready = sorted(uid for uid, values in remaining.items() if not values)
        if not ready:
            break
        for uid in ready:
            order.append(uid)
            remaining.pop(uid)
        for values in remaining.values():
            values.difference_update(ready)
    unresolved = sorted(remaining)
    return {
        "ordered_unit_ids": order,
        "ordered_source_paths": [path for uid in order for path in unit_paths[uid]],
        "cyclic_or_unresolved_unit_ids": unresolved,
        "note": "Order is based only on static inter-unit edges; cycles and dynamic dependencies require manual resolution."
    }
