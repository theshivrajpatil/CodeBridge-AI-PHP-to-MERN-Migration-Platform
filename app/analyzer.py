"""Conservative static PHP analysis without executing project code.

This is a lexical/regex analyser, not a complete PHP grammar or AST parser.
Findings are evidence for review, never proof of runtime behaviour.
"""
from __future__ import annotations

from pathlib import Path, PurePosixPath
import re
from app.config import MAX_FILE_BYTES
from app.php_ast import parse_php_source
from app.frameworks import detect_framework, classify_php_path
from app.behavior_analyzer import build_behavior_report
from app.dependency_intelligence import build_dependency_intelligence
from app.architecture_intelligence import enrich_dependency_intelligence
from app.intermediate_representation import build_common_ir

PHP_EXTENSIONS = {".php", ".phtml", ".inc"}
IDENT = r"[A-Za-z_][A-Za-z0-9_]*"

# Mask comments while preserving quoted strings and offsets. This avoids most
# comment-related false positives without pretending to parse PHP completely.
def _mask_comments(source: str, mask_strings: bool = False) -> str:
    out = list(source)
    i, n, state = 0, len(source), "code"
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if state == "code":
            if ch == "'": state = "single"
            elif ch == '"': state = "double"
            elif ch == "`": state = "backtick"
            elif ch == "/" and nxt == "/" or ch == "#":
                state = "line"
                out[i] = " "
                if ch == "/": out[i + 1] = " "; i += 1
            elif ch == "/" and nxt == "*":
                state = "block"; out[i] = out[i + 1] = " "; i += 1
        elif state in {"single", "double", "backtick"}:
            if mask_strings and ch != "\n": out[i] = " "
            if ch == "\\":
                if mask_strings and i + 1 < n and source[i + 1] != "\n": out[i + 1] = " "
                i += 1
            elif (state == "single" and ch == "'") or (state == "double" and ch == '"') or (state == "backtick" and ch == "`"):
                state = "code"
        elif state == "line":
            if ch == "\n": state = "code"
            else: out[i] = " "
        elif state == "block":
            if ch == "*" and nxt == "/": out[i] = out[i + 1] = " "; i += 1; state = "code"
            elif ch != "\n": out[i] = " "
        i += 1
    return "".join(out)


def _unique(values):
    return list(dict.fromkeys(v.strip() for v in values if v and v.strip()))


def analyze_php_file(root: Path, relative_path: str) -> dict:
    root = Path(root).resolve()
    rel = PurePosixPath(relative_path)
    base = {"path": rel.as_posix(), "status": "ANALYZED", "namespace": None,
            "classes": [], "interfaces": [], "traits": [], "functions": [], "methods": [],
            "imports": [], "extends": [], "implements": [], "includes": [],
            "route_candidates": [], "database_signals": [], "output_signals": [],
            "signals": [], "references": [], "line_count": 0, "parse_errors": []}
    if rel.is_absolute() or ".." in rel.parts:
        base.update(status="BLOCKED", signals=["Path rejected: outside-repository path"])
        return base
    path = (root / Path(*rel.parts)).resolve()
    try:
        path.relative_to(root)
        if not path.is_file() or path.suffix.lower() not in PHP_EXTENSIONS:
            raise ValueError("Not an existing PHP source file")
        if path.stat().st_size > MAX_FILE_BYTES:
            base.update(status="NEEDS REVIEW", signals=[f"File exceeds {MAX_FILE_BYTES}-byte analysis limit"])
            return base
        source = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError) as exc:
        base.update(status="BLOCKED", signals=[f"Cannot safely read source: {type(exc).__name__}"])
        return base

    ast = parse_php_source(source)
    base["ast"] = ast
    base["analysis_mode"] = "TREE_SITTER_AST" if ast.get("available") and ast.get("status") in {"PARSED", "PARSED_WITH_ERRORS"} else "LEXICAL_FALLBACK"
    if not ast.get("available"):
        base["status"] = "NEEDS REVIEW"
        base["signals"].append("PHP AST parser unavailable; lexical findings are fallback evidence only")
    elif ast.get("status") == "PARSE_FAILED":
        base["status"] = "NEEDS REVIEW"
        base["signals"].append("PHP AST parsing failed; lexical findings are fallback evidence only")
    elif ast.get("status") == "PARSED_WITH_ERRORS":
        base["status"] = "NEEDS REVIEW"
        base["signals"].append("PHP syntax errors detected; AST findings may be incomplete")

    code = _mask_comments(source, mask_strings=True)
    base["line_count"] = source.count("\n") + (1 if source else 0)
    patterns = {
        "classes": rf"\b(?:abstract\s+|final\s+|readonly\s+)*class\s+({IDENT})",
        "interfaces": rf"\binterface\s+({IDENT})",
        "traits": rf"\btrait\s+({IDENT})",
        "functions": rf"\bfunction\s*&?\s*({IDENT})\s*\(",
        "imports": r"\buse\s+((?:function\s+|const\s+)?[A-Za-z_\\][A-Za-z0-9_\\]*(?:\s+as\s+\w+)?)\s*;",
        "extends": rf"\bextends\s+([\\A-Za-z_][\\A-Za-z0-9_]*)",
        "implements": rf"\bimplements\s+([\\A-Za-z_][\\A-Za-z0-9_]*(?:\s*,\s*[\\A-Za-z_][\\A-Za-z0-9_]*)*)",
    }
    for key, pattern in patterns.items():
        vals = _unique(m.group(1) for m in re.finditer(pattern, code))
        if key == "implements":
            vals = _unique(part for val in vals for part in val.split(","))
        base[key] = vals
    namespaces = _unique(m.group(1).strip() for m in re.finditer(r"\bnamespace\s+([^;{]+)[;{]", code))
    base["namespace"] = namespaces[0] if namespaces else None
    if ast.get("available") and ast.get("status") in {"PARSED", "PARSED_WITH_ERRORS"}:
        for key in ("classes", "interfaces", "traits", "functions", "methods", "imports", "extends", "implements"):
            base[key] = [x["name"] for x in ast.get(key, [])]
        base["namespace"] = ast.get("namespace")
        # AST evidence is retained with line numbers for declarations and relationships.
        base["ast"]["declarations"] = {key: ast.get(key, []) for key in ("classes", "interfaces", "traits", "functions", "methods")}

    # Includes are intentionally collected from source strings; only literal paths are actionable.
    for m in re.finditer(r"\b(?:include|include_once|require|require_once)\s*(?:\(\s*)?(['\"])([^'\"]+)\1", source, re.I):
        base["includes"].append({"path": m.group(2), "kind": m.group(0).split()[0].lower(), "line": source.count("\n", 0, m.start()) + 1})
    base["includes"] = list({(x["path"], x["kind"], x["line"]): x for x in base["includes"]}.values())

    if base["analysis_mode"] == "TREE_SITTER_AST" and ast.get("route_calls"):
        for call in ast["route_calls"]:
            expr = call.get("expression", "")
            method_match = re.search(r"Route\s*::\s*(get|post|put|patch|delete|any|match|resource)", expr, re.I)
            path_match = re.search(r"Route\s*::\s*\w+\s*\(\s*(['\"])(.*?)\1", expr, re.I)
            base["route_candidates"].append({
                "kind": "AST Route facade call",
                "line": call.get("line"),
                "method": method_match.group(1).upper() if method_match else None,
                "path": path_match.group(2) if path_match else None,
                "evidence": expr[:1200],
                "node_type": call.get("node_type"),
                "contract_status": "PARTIAL" if method_match and path_match else "NEEDS REVIEW"
            })
    else:
        # Fallback patterns are deliberately labelled as candidates, never confirmed routes.
        route_patterns = [
            ("Lexical Route facade candidate", r"\bRoute\s*::\s*(?:get|post|put|patch|delete|any|match|resource)\s*\(")]
        for label, pattern in route_patterns:
            for m in re.finditer(pattern, code, re.I):
                base["route_candidates"].append({"kind": label, "line": code.count("\n", 0, m.start()) + 1,
                    "evidence": m.group(0).strip(), "contract_status": "NEEDS REVIEW"})
    base["route_candidates"] = _dedupe_dicts(base["route_candidates"])

    db_patterns = [
        ("PDO", r"\bPDO\b"), ("mysqli", r"\bmysqli?_(?:query|prepare|connect|real_connect)\b"),
        ("PostgreSQL API", r"\bpg_(?:query|prepare|connect)\s*\("),
        ("query-like method", r"->\s*(?:query|prepare|execute|fetch|fetchAll)\s*\("),
        ("SQL statement", r"\b(?:SELECT\s+.+?\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b")]
    for label, pattern in db_patterns:
        for m in re.finditer(pattern, code, re.I):
            base["database_signals"].append({"kind": label, "line": code.count("\n", 0, m.start()) + 1})
    base["database_signals"] = _dedupe_dicts(base["database_signals"])
    for label, pattern in [("PHP output", r"\b(?:echo|print)\b|<\?="), ("template inclusion", r"\b(?:include|include_once|require|require_once)\b")]:
        for m in re.finditer(pattern, code, re.I):
            base["output_signals"].append({"kind": label, "line": code.count("\n", 0, m.start()) + 1})
    base["output_signals"] = _dedupe_dicts(base["output_signals"])
    if base["route_candidates"]: base["signals"].append("Possible HTTP route or handler; inspect route contract")
    if base["database_signals"]: base["signals"].append("Possible database access; preserve database and verify query semantics")
    if base["output_signals"]: base["signals"].append("Possible server-rendered output or include; inspect UI/data flow")
    if re.search(r"\b(?:eval|assert)\s*\(|\b(?:call_user_func|call_user_func_array)\s*\(|\$\$", code):
        base["signals"].append("Dynamic execution/dispatch pattern; static dependency confidence is reduced")
    if not any(base[k] for k in ("classes", "interfaces", "traits", "functions")):
        base["signals"].append("No named declarations detected; file may be script/template/configuration")
    return base


def _dedupe_dicts(items):
    seen, result = set(), []
    for item in items:
        key = tuple(sorted(item.items()))
        if key not in seen: seen.add(key); result.append(item)
    return result


def analyze_repository(scan: dict) -> dict:
    """Build a conservative dependency graph from AST evidence where available."""
    root = Path(scan["root"]).resolve()
    all_php = scan.get("php_files", [])
    analyzed = [analyze_php_file(root, item["path"]) for item in all_php]
    by_path = {item["path"]: item for item in analyzed}
    symbol_index = {}
    for item in analyzed:
        for kind in ("classes", "interfaces", "traits"):
            for symbol in item.get(kind, []):
                symbol_index.setdefault(symbol.lower(), []).append(item["path"])

    edges, edge_index = [], {}
    def add_edge(src, target, relation, evidence, confidence):
        if src == target or target not in by_path:
            return
        key = (src, target, relation)
        if key not in edge_index:
            edge_index[key] = {"from": src, "to": target, "type": relation,
                               "evidence": [], "confidence": confidence}
            edges.append(edge_index[key])
        if evidence not in edge_index[key]["evidence"]:
            edge_index[key]["evidence"].append(evidence)

    for item in analyzed:
        path = item["path"]
        ast_data = item.get("ast", {})
        ast_ok = item.get("analysis_mode") == "TREE_SITTER_AST" and item.get("status") == "ANALYZED"
        # Imports/inheritance are AST-derived when parser is healthy; fallback remains review-only.
        imports = ast_data.get("imports", []) if ast_ok else [
            {"name": value, "line": None} for value in item.get("imports", [])
        ]
        for entry in imports:
            raw = entry.get("name", "")
            if raw.startswith(("function ", "const ")):
                continue
            # Group-use syntax is not resolved automatically; avoid speculative edges.
            if "{" in raw or "}" in raw:
                continue
            fqcn = raw.split(" as ")[0].strip().lstrip("\\\\")
            short = raw.split(" as ")[-1].split("\\")[-1].strip().lower()
            matches = symbol_index.get(short, [])
            for target in matches:
                add_edge(path, target, "imports", f"AST import line {entry.get('line')}: {fqcn}", "medium")
        relationship_entries = {}
        for key in ("extends", "implements"):
            relationship_entries[key] = ast_data.get(key, []) if ast_ok else [
                {"name": value, "line": None} for value in item.get(key, [])
            ]
        for key, relation in (("extends", "extends"), ("implements", "implements")):
            for entry in relationship_entries[key]:
                short = entry["name"].strip("\\\\").split("\\")[-1].lower()
                for target in symbol_index.get(short, []):
                    add_edge(path, target, relation,
                             f"{'AST' if ast_ok else 'lexical fallback'} {key} line {entry.get('line')}: {entry['name']}",
                             "high" if ast_ok else "low")
        instantiations = ast_data.get("instantiations", []) if ast_ok else []
        if not ast_ok:
            try:
                source_code = _mask_comments((root / path).read_text(encoding="utf-8", errors="replace"), mask_strings=True)
                instantiations = [{"name": m.group(1), "line": source_code.count("\\n", 0, m.start()) + 1}
                                  for m in re.finditer(r"\\bnew\\s+\\\\?([A-Za-z_][A-Za-z0-9_\\\\]*)", source_code)]
            except OSError:
                instantiations = []
        for entry in instantiations:
            short = entry["name"].strip("\\\\").split("\\")[-1].lower()
            for target in symbol_index.get(short, []):
                add_edge(path, target, "instantiates",
                         f"{'AST' if ast_ok else 'lexical fallback'} object creation line {entry.get('line')}: {entry['name']}",
                         "medium" if ast_ok else "low")
        # Only literal include/require paths are linked; dynamic expressions are unresolved.
        for include in item.get("includes", []):
            include_path = (Path(path).parent / include["path"]).as_posix()
            candidate = str(PurePosixPath(include_path))
            if candidate not in by_path:
                candidate = str(PurePosixPath(include["path"].lstrip("./")))
            if candidate in by_path:
                add_edge(path, candidate, "includes", f"Literal include line {include['line']}: {include['path']}", "high")

    framework = detect_framework(scan)
    for item in analyzed:
        item["classification"] = classify_php_path(item["path"], framework.get("name", ""))
    nodes = [{"path": x["path"], "status": x["status"],
              "classification": x.get("classification", {}),
              "symbol_count": sum(len(x[k]) for k in ("classes", "interfaces", "traits", "functions", "methods"))}
             for x in analyzed]
    ast_count = sum(x.get("analysis_mode") == "TREE_SITTER_AST" and x.get("status") == "ANALYZED" for x in analyzed)
    result = {
        "analysis_type": "Tree-sitter PHP AST with explicitly labelled lexical signal fallback",
        "php_files_discovered": len(all_php),
        "php_files_analyzed": sum(x["status"] == "ANALYZED" for x in analyzed),
        "ast_files_parsed": ast_count,
        "symbol_counts": {kind: sum(len(x.get(kind, [])) for x in analyzed)
                          for kind in ("classes", "interfaces", "traits", "functions", "methods", "imports")},
        "files": analyzed,
        "dependency_graph": {"nodes": nodes, "edges": edges, "unresolved_edges": [], "edge_count": len(edges)},
        "dependency_edges": edges,
        "coverage": {"discovered_php_files": len(all_php),
                     "analyzed_php_files": sum(x["status"] == "ANALYZED" for x in analyzed),
                     "ast_files_parsed": ast_count,
                     "not_analyzed": [x["path"] for x in analyzed if x["status"] != "ANALYZED"]},
        "limitations": [
            "AST extraction is structural, not runtime execution; dynamic dispatch, reflection, generated code and framework bootstrapping are unresolved.",
            "Route calls are partial evidence only; middleware, authorization, validation, response semantics and route groups require review.",
            "Dependency edges are static evidence and may be ambiguous when duplicate short class names exist.",
            "The scanner caps the PHP inventory; check coverage and scan warnings before relying on completeness."
        ]
    }
    result["framework_detection"] = framework
    result["behavior_report"] = build_behavior_report(result, repository_root=root)
    result["dependency_intelligence"] = enrich_dependency_intelligence(build_dependency_intelligence(result, root), result)
    # Dependency intelligence is the canonical graph. The earlier lexical graph
    # is retained only as a legacy analysis field and is not merged because its
    # short-name matching can create false local edges (e.g. PHPUnit\\TestCase).
    canonical_edges = result["dependency_intelligence"].get("edges", [])
    result["dependency_intelligence"]["edges"] = canonical_edges
    result["dependency_intelligence"]["edge_count"] = len(canonical_edges)
    result["dependency_graph"] = {
        "nodes": result["dependency_intelligence"].get("nodes", []),
        "edges": canonical_edges, "edge_count": len(canonical_edges),
        "unresolved_edges": result["dependency_intelligence"].get("unresolved_relationships", [])
    }
    result["dependency_edges"] = canonical_edges
    result["analysis_type"] = "Framework-neutral PHP AST + pluggable framework adapters + evidence-linked behaviour and dependency intelligence with labelled lexical fallback"
    result["common_ir"] = build_common_ir(scan, result)
    return result
