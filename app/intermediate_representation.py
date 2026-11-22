"""Framework-neutral Common Application Representation (CAR) for PHP projects.

The representation contains source-backed facts and explicit unknowns. Framework adapters
may enrich framework-specific fields, but target migration agents consume only this schema.
"""
from __future__ import annotations
from collections import Counter

SCHEMA_VERSION = "1.0"


def build_common_ir(scan: dict, analysis: dict) -> dict:
    files = analysis.get("files", [])
    components = {k: [] for k in (
        "routes", "controllers", "services", "models", "repositories", "middleware",
        "views", "templates", "database_access", "database_schema", "database_seeders", "test_fixtures", "configuration",
        "entrypoints", "background_tasks", "events", "tests", "other")}
    role_map = {
        "Routes": "routes", "Controllers": "controllers", "Services": "services",
        "Models / entities": "models", "Models": "models", "Repositories": "repositories",
        "Middleware": "middleware", "Templates": "templates", "Views / templates": "templates",
        "Database migrations": "database_schema", "Migrations / seeders / factories": "database_schema",
        "Database seeders": "database_seeders", "Test data factories": "test_fixtures",
        "Tests": "tests", "Configuration": "configuration", "Configuration / bootstrap": "configuration",
        "Bootstrap": "entrypoints", "Public entrypoints / assets": "entrypoints",
        "Framework providers": "configuration", "Service providers": "configuration",
        "Background jobs": "background_tasks", "Background jobs / events": "background_tasks",
        "Events": "events", "Event listeners": "events", "CMS plugins": "other",
        "CMS themes / templates": "templates", "CMS core": "other"
    }
    for item in files:
        classification = item.get("classification", {})
        role = classification.get("group", "Unclassified PHP")
        bucket = role_map.get(role, "other")
        entry = {"source_path": item.get("path"), "role": role,
                 "classification_confidence": classification.get("confidence", "LOW"),
                 "analysis_status": item.get("status", "UNKNOWN"),
                 "analysis_mode": item.get("analysis_mode", "UNKNOWN"),
                 "namespace": item.get("namespace"),
                 "symbols": {k: item.get(k, []) for k in ("classes", "interfaces", "traits", "functions", "methods")},
                 "source_evidence": {"route_candidates": item.get("route_candidates", []),
                                     "database_signals": item.get("database_signals", []),
                                     "output_signals": item.get("output_signals", []),
                                     "includes": item.get("includes", [])}}
        components[bucket].append(entry)
        if item.get("database_signals") and bucket != "database_schema":
            components["database_access"].append(entry)
    behavior = analysis.get("behavior_report", {})
    graph = analysis.get("dependency_intelligence", analysis.get("dependency_graph", {}))
    return {
        "schema": "codebridge.common_application_representation",
        "schema_version": SCHEMA_VERSION,
        "application": {"language": "PHP", "framework": analysis.get("framework_detection", {}).get("name", "UNKNOWN"),
                        "framework_confidence": analysis.get("framework_detection", {}).get("confidence", "LOW"),
                        "framework_adapter": analysis.get("framework_detection", {}).get("adapter_id", "unknown"),
                        "framework_is_required_for_core_analysis": False},
        "inventory": {"files_discovered": scan.get("file_count", 0),
                      "php_files_discovered": scan.get("php_file_count", 0),
                      "php_files_analyzed": analysis.get("php_files_analyzed", 0),
                      "warnings": scan.get("warnings", [])},
        "components": components,
        "dependency_graph": graph,
        "dependencies": graph.get("edges", []),
        "behaviour_contracts": behavior.get("route_contracts", []),
        "uncertainties": {
            "unresolved_references": graph.get("unresolved_relationships", graph.get("unresolved_edges", [])),
            "runtime_call_order_verified": graph.get("coverage", {}).get("runtime_call_order_verified", False),
            "database_engine_verified": graph.get("coverage", {}).get("database_engine_identified", False),
            "missing_static_signals_are_not_proof_of_absence": True,
            "analysis_limitations": analysis.get("limitations", [])
        },
        "safety": {"source_read_only": True, "php_execution_performed": False,
                   "database_mutation_performed": False, "generation_authorized": False}
    }
