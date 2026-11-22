from pathlib import Path
from typing import Any
from app.agents.base import Agent
from app.analyzer import analyze_repository
from app.planner import build_plan

class RepositoryAnalystAgent(Agent):
    name = "repository_analyst"
    description = "Summarises the read-only repository inventory and framework hints."
    def run(self, context: dict[str, Any]) -> dict[str, Any]:
        scan = context["scan"]
        return {"framework_hints": scan.get("framework_hints", []), "file_count": scan.get("file_count", 0),
                "php_file_count": scan.get("php_file_count", 0), "root": scan.get("root"),
                "warnings": scan.get("warnings", []), "status": "COMPLETE"}

class PHPUnderstandingAgent(Agent):
    name = "php_understanding"
    description = "Runs the deterministic PHP AST/signal and behaviour analysis engine."
    def run(self, context: dict[str, Any]) -> dict[str, Any]:
        analysis = context.get("analysis") or analyze_repository(context["scan"])
        context["analysis"] = analysis
        return {"php_files_analyzed": analysis.get("php_files_analyzed", 0),
                "ast_files_parsed": analysis.get("ast_files_parsed", 0),
                "behavior_route_count": analysis.get("behavior_report", {}).get("route_contract_count", 0),
                "analysis_type": analysis.get("analysis_type", "static analysis"), "status": "COMPLETE"}

class DependencyAnalystAgent(Agent):
    name = "dependency_analyst"
    description = "Reports evidence-backed static dependency relationships."
    def run(self, context: dict[str, Any]) -> dict[str, Any]:
        analysis = context["analysis"]
        graph = analysis.get("dependency_intelligence", {})
        return {"node_count": len(graph.get("nodes", [])), "edge_count": graph.get("edge_count", len(graph.get("edges", []))),
                "database_operation_count": graph.get("database_operation_count", len(graph.get("database_operations", []))),
                "unresolved_relationships": graph.get("unresolved_relationships", []),
                "runtime_call_order_verified": graph.get("coverage", {}).get("runtime_call_order_verified", False),
                "status": "STATIC_EVIDENCE_REQUIRES_REVIEW"}

class ArchitectureAnalystAgent(Agent):
    name = "architecture_analyst"
    description = "Builds a source-evidence-based architecture summary; does not infer missing layers."
    def run(self, context: dict[str, Any]) -> dict[str, Any]:
        analysis = context["analysis"]
        groups: dict[str, int] = {}
        for item in analysis.get("files", []):
            group = item.get("classification", {}).get("group", "Other PHP")
            groups[group] = groups.get(group, 0) + 1
        return {"framework": analysis.get("framework_detection", {}).get("name", "UNKNOWN"),
                "file_groups": groups, "architecture_confidence": "STATIC_EVIDENCE_ONLY",
                "unverified_runtime_semantics": True, "status": "NEEDS_REVIEW"}

class MigrationPlannerAgent(Agent):
    name = "migration_planner"
    description = "Creates a conservative migration plan from verified analysis outputs."
    def run(self, context: dict[str, Any]) -> dict[str, Any]:
        plan = build_plan(context["scan"], context["analysis"])
        context["plan"] = plan
        return {"summary": plan.get("summary", {}), "steps": plan.get("steps", []),
                "database_policy": "PRESERVE_EXISTING_DATABASE_BY_DEFAULT", "status": "DRAFT_REQUIRES_HUMAN_REVIEW"}
