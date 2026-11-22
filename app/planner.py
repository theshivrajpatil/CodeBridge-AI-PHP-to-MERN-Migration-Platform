"""Evidence-driven migration planning; no framework-specific assumptions."""
from collections import defaultdict


def build_plan(scan: dict, analysis: dict | None = None) -> dict:
    analysis = analysis or {}
    groups = {key: [] for key in (
        "Routes", "Controllers", "Models", "Models / entities", "Database migrations",
        "Database seeders", "Test data factories", "Middleware", "Services", "Repositories",
        "Templates", "Views / templates", "Configuration", "Configuration / bootstrap",
        "Bootstrap", "Tests", "Framework providers", "Background jobs", "Background jobs / events",
        "Events", "Event listeners", "Public entrypoints / assets", "CMS core", "CMS plugins",
        "CMS themes / templates", "Data-access candidates", "Other PHP", "Unclassified PHP")}

    analyzed_by_path = {item["path"]: item for item in analysis.get("files", [])}
    for item in scan.get("php_files", []):
        path = item["path"]
        info = analyzed_by_path.get(path, {})
        name = path.lower()
        signals = " ".join(info.get("signals", [])).lower()
        parts = name.split("/")
        filename = parts[-1]
        detected_group = info.get("classification", {}).get("group")
        if detected_group and detected_group != "Other PHP":
            group = detected_group
        elif filename.startswith(("web.php", "api.php")) or "/routes/" in f"/{name}":
            group = "Routes"
        elif "/middleware/" in f"/{name}" or filename.endswith("middleware.php"):
            group = "Middleware"
        elif "/controllers/" in f"/{name}" or filename.endswith("controller.php"):
            group = "Controllers"
        elif "/models/" in f"/{name}" or "/entities/" in f"/{name}":
            group = "Models"
        elif any(x in f"/{name}" for x in ("/migrations/", "/seeders/", "/factories/")):
            group = "Migrations / seeders / factories"
        elif "/tests/" in f"/{name}" or filename.endswith("test.php"):
            group = "Tests"
        elif "/views/" in f"/{name}" or "/templates/" in f"/{name}" or filename.endswith((".blade.php", ".twig.php", ".phtml")):
            group = "Views / templates"
        elif any(x in name for x in ("config", "bootstrap", "autoload")):
            group = "Configuration / bootstrap"
        elif info.get("database_signals"):
            group = "Data-access candidates"
        else:
            group = "Other PHP"
        groups.setdefault(group, []).append(path)

    graph = analysis.get("dependency_graph", {})
    edge_count = graph.get("edge_count", len(analysis.get("dependency_edges", [])))
    steps = [
        {"phase": 1, "name": "Repository inventory", "status": "COMPLETE" if scan.get("file_count", 0) else "NEEDS REVIEW",
         "details": "Read-only inventory, file limits, skipped directories, and repository warnings."},
        {"phase": 2, "name": "PHP AST and signal analysis", "status": "COMPLETE" if analysis.get("ast_files_parsed") == analysis.get("php_files_discovered") else "NEEDS REVIEW",
         "details": "Tree-sitter structural extraction where available; fallback files are explicitly marked NEEDS REVIEW. Runtime semantics remain unresolved."},
        {"phase": 3, "name": "Dependency graph and migration units", "status": "NEEDS REVIEW" if edge_count or analysis.get("php_files_analyzed") else "BLOCKED",
         "details": "Review evidence-based edges and group tightly coupled source files before generating target code."},
        {"phase": 4, "name": "Migration specification", "status": "DRAFT",
         "details": "Proposed backend/frontend responsibilities, data contracts, risks and validation gates. Requires human approval."},
        {"phase": 5, "name": "Incremental implementation and parity validation", "status": "BLOCKED",
         "details": "Not run by the planner. Parity validation (POST /api/parity) and controlled generation (POST /api/generate, disabled by default) are separate steps that require an approved specification and fingerprint-bound human approval."}
    ]
    return {"project_root": scan["root"],
        "summary": {"files": scan.get("file_count", 0), "php_files_discovered": scan.get("php_file_count", 0),
                    "php_files_in_inventory": len(scan.get("php_files", [])),
                    "framework_hints": scan.get("framework_hints", []),
                    "php_files_analyzed": analysis.get("php_files_analyzed", 0), "dependency_edges": edge_count},
        "php_file_groups": groups,
        "source_to_target_map": {
            "Routes": "Express routers only after route method/path and middleware contracts are verified",
            "Controllers": "Express controllers/services after behaviour contract review",
            "Models": "Data-access layer preserving existing schema and database engine",
            "Migrations / seeders / factories": "Review-only; never execute or translate into DB mutations without approval",
            "Database migrations": "Review-only schema evidence; never execute without separate explicit approval",
            "Database seeders": "Review-only data-loading evidence; never execute against source/production",
            "Test data factories": "Test-fixture evidence only; do not treat as production data",
            "Middleware": "Express middleware after authentication/authorization parity review",
            "Services": "backend/services after controller/service contract review",
            "Repositories": "backend/data-access preserving the existing database engine and schema",
            "Views / templates": "React components only after inputs, escaping and navigation are documented",
            "Tests": "Node test suites preserving assertions; never convert tests into HTTP endpoints",
            "Configuration / bootstrap": "Environment-backed configuration; never copy secrets",
            "Data-access candidates": "Repository/service modules using the existing database engine and parameterized queries",
            "Template / output candidates": "React components only after identifying inputs, outputs, validation, escaping and navigation behaviour",
            "Configuration / bootstrap candidates": "Environment-backed configuration and explicit startup wiring; never copy secrets",
            "Other PHP": "Isolated migration unit requiring manual classification before conversion",
            "Unclassified PHP": "Isolated review unit; do not infer frontend/backend responsibility",
            "Templates": "React components only after inputs, escaping and navigation are documented",
            "Models / entities": "Data-access contracts preserving existing schema and engine",
            "Public entrypoints / assets": "Review runtime entrypoints and static assets separately",
            "Configuration": "Environment-backed configuration; inspect secrets and runtime dependencies",
            "Bootstrap": "Target startup wiring after lifecycle analysis",
            "CMS core": "Platform-managed code; exclude from automatic migration unless explicitly scoped",
            "CMS plugins": "Plugin boundary review; map hooks and extension points",
            "CMS themes / templates": "Frontend templates after rendering contract review"},
        "steps": steps,
        "database_policy": "Preserve the existing database engine, schema, data, constraints and transaction behaviour by default. No database connection or mutation is performed.",
        "analysis": analysis,
        "warnings": list(scan.get("warnings", [])) + (["Only a capped subset of PHP files is included in the inventory."] if scan.get("php_file_count", 0) > len(scan.get("php_files", [])) else []),
        "limitations": ["Framework hints and path-based classifications are advisory; verify every file assignment.",
            "AST findings do not establish runtime behaviour; dependency edges must be reviewed.",
            "No claim of behaviour equivalence, security correctness or successful migration is made.",
            "No source file or database is modified."]}
