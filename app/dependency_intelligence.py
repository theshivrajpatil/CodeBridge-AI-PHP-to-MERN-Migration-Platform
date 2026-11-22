"""Framework-neutral, evidence-backed PHP dependency and database analysis.

Static-only: this module never executes PHP, loads Composer autoloaders, or connects
 to a database. Class relationships are resolved by fully-qualified names; short-name
matches are never accepted as proof of a local dependency.
"""
from __future__ import annotations

from pathlib import Path, PurePosixPath
import re

MODEL_STATIC_METHODS = {
    "find": "READ", "findorfail": "READ", "first": "READ", "firstorfail": "READ",
    "get": "READ", "all": "READ", "paginate": "READ", "simplepaginate": "READ",
    "count": "READ", "exists": "READ", "query": "QUERY_BUILDER", "where": "QUERY_BUILDER",
    "create": "INSERT", "insert": "INSERT", "insertgetid": "INSERT", "update": "UPDATE",
    "upsert": "UPSERT", "delete": "DELETE", "destroy": "DELETE",
}
INSTANCE_METHODS = {"save": "WRITE", "update": "UPDATE", "delete": "DELETE", "forcedelete": "DELETE",
                    "restore": "UPDATE", "refresh": "READ", "load": "READ", "loadmissing": "READ"}
DRIVERS = {"mysql", "mariadb", "pgsql", "postgresql", "sqlite", "sqlsrv", "oci", "odbc"}


def _line(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _mask_comments(source: str) -> str:
    out = list(source); i = 0; state = "code"
    while i < len(source):
        c = source[i]; n = source[i + 1] if i + 1 < len(source) else ""
        if state == "code":
            if c == "'": state = "single"
            elif c == '"': state = "double"
            elif c == "`": state = "backtick"
            elif (c == "/" and n == "/") or c == "#":
                out[i] = " "
                if c == "/": out[i + 1] = " "; i += 1
                state = "line"
            elif c == "/" and n == "*": out[i] = out[i + 1] = " "; i += 1; state = "block"
        elif state in {"single", "double", "backtick"}:
            if c == "\\": i += 1
            elif (state == "single" and c == "'") or (state == "double" and c == '"') or (state == "backtick" and c == "`"): state = "code"
        elif state == "line":
            if c == "\n": state = "code"
            else: out[i] = " "
        elif state == "block":
            if c == "*" and n == "/": out[i] = out[i + 1] = " "; i += 1; state = "code"
            elif c != "\n": out[i] = " "
        i += 1
    return "".join(out)


def _normal(name: str) -> str:
    return "\\".join(part for part in name.strip().strip("\\").split("\\") if part).lower()


def _parse_imports(code: str) -> dict[str, str]:
    """Parse common PHP class imports, aliases, comma lists and group-use clauses."""
    aliases: dict[str, str] = {}
    pattern = re.compile(r"\buse\s+(?!function\b|const\b)([^;]+);", re.I)
    declarations = re.search(r"\b(?:class|interface|trait|enum|function)\s+", code, re.I)
    declaration_start = declarations.start() if declarations else len(code)
    for match in pattern.finditer(code):
        # Namespace imports must occur before declarations. This excludes trait-use
        # statements inside classes and closure capture lists.
        if match.start() >= declaration_start:
            continue
        statement = match.group(1).strip()
        if "{" in statement and "}" in statement:
            prefix, rest = statement.split("{", 1); group = rest.split("}", 1)[0]
            prefix = prefix.strip().rstrip("\\")
            clauses = [prefix + "\\" + x.strip() for x in group.split(",") if x.strip()]
        else:
            clauses = [x.strip() for x in statement.split(",") if x.strip()]
        for clause in clauses:
            clause = re.sub(r"^\\", "", clause.strip())
            parts = re.split(r"\s+as\s+", clause, flags=re.I)
            fqcn = parts[0].strip().strip("\\")
            if not fqcn: continue
            alias = parts[1].strip() if len(parts) > 1 else fqcn.split("\\")[-1]
            aliases[alias.lower()] = fqcn
    return aliases


def _resolve_reference(reference: str, namespace: str | None, imports: dict[str, str]) -> str | None:
    ref = reference.strip()
    if not ref or ref.startswith("$") or ref.lower() in {"self", "static", "parent"}:
        return None
    if ref.startswith("\\"):
        return _normal(ref)
    first, *tail = ref.split("\\")
    if first.lower() in imports:
        return _normal(imports[first.lower()] + (("\\" + "\\".join(tail)) if tail else ""))
    if namespace:
        return _normal(namespace + "\\" + ref)
    return _normal(ref)


def _classify_name_map(files: list[dict], sources: dict[str, str]) -> tuple[dict[str, str], dict[str, str]]:
    fqcn_to_path: dict[str, str] = {}
    path_namespace: dict[str, str] = {}
    for item in files:
        path = item.get("path")
        if not path: continue
        source = sources.get(path, "")
        ns = item.get("namespace")
        if not ns:
            m = re.search(r"\bnamespace\s+([^;{]+)\s*[;{]", _mask_comments(source))
            ns = m.group(1).strip() if m else ""
        path_namespace[path] = ns or ""
        declarations = []
        for key in ("classes", "interfaces", "traits", "enums"):
            declarations.extend(item.get(key, []) or [])
        for declaration in declarations:
            name = declaration.get("name") if isinstance(declaration, dict) else declaration
            if name:
                fqcn = _normal((ns + "\\" if ns else "") + str(name))
                # Duplicate FQCNs are ambiguous and must not be arbitrarily selected.
                fqcn_to_path[fqcn] = path if fqcn not in fqcn_to_path else ""
    return fqcn_to_path, path_namespace


def build_dependency_intelligence(analysis: dict, repository_root: str | Path) -> dict:
    root = Path(repository_root).resolve()
    files = analysis.get("files", [])
    by_path = {x.get("path"): x for x in files if x.get("path")}
    sources: dict[str, str] = {}
    codes: dict[str, str] = {}
    for path in by_path:
        try:
            full = (root / path).resolve(); full.relative_to(root)
            if full.is_file() and full.stat().st_size <= 1_000_000:
                sources[path] = full.read_text(encoding="utf-8", errors="replace")
                codes[path] = _mask_comments(sources[path])
        except (OSError, ValueError):
            continue
    fqcn_to_path, namespaces = _classify_name_map(files, sources)
    short_name_paths: dict[str, list[str]] = {}
    for file_item in files:
        source_path = file_item.get("path")
        ns = namespaces.get(source_path, "")
        for declaration_kind in ("classes", "interfaces", "traits", "enums"):
            for declaration in file_item.get(declaration_kind, []) or []:
                declared = declaration.get("name") if isinstance(declaration, dict) else declaration
                if declared:
                    short_name_paths.setdefault(str(declared).split("\\")[-1].lower(), []).append(source_path)
    role_by_path = {p: by_path[p].get("classification", {}).get("group", "") for p in by_path}
    edges: list[dict] = []; edge_keys = set(); unresolved: list[dict] = []

    def add_edge(src, dst, relation, evidence, line=None, confidence="MEDIUM"):
        if not dst or dst == src or dst not in by_path: return
        key = (src, dst, relation)
        if key not in edge_keys:
            edge_keys.add(key); edges.append({"from": src, "to": dst, "type": relation,
                "evidence": [], "confidence": confidence, "status": "STATIC_REFERENCE_REQUIRES_REVIEW"})
        edge = next(x for x in edges if (x["from"], x["to"], x["type"]) == key)
        ev = f"line {line}: {evidence}" if line else evidence
        if ev not in edge["evidence"]: edge["evidence"].append(ev)

    def resolve(src, ref, relation, evidence, line, confidence="MEDIUM"):
        target_fqcn = _resolve_reference(ref, namespaces.get(src), imports_by_path.get(src, {}))
        if not target_fqcn: return
        target = fqcn_to_path.get(target_fqcn)
        if target:
            add_edge(src, target, relation, evidence, line, confidence)
        elif target_fqcn in fqcn_to_path and not target:
            unresolved.append({"source": src, "symbol": ref, "resolved_name": target_fqcn,
                "relationship": relation, "line": line, "reason": "Duplicate fully-qualified declaration"})
        # External or unresolved symbols are not local dependency edges.

    imports_by_path = {p: _parse_imports(code) for p, code in codes.items()}
    database_configs: list[dict] = []; schema_evidence: list[dict] = []; schema_columns: list[dict] = []
    findings: list[dict] = []; database_source_signals: list[dict] = []; default_connection_evidence: list[dict] = []
    dynamic_uncertainties: list[dict] = []
    for path, code in codes.items():
        source = sources[path]
        # Imports are parsed as class imports only. This avoids treating PHPUnit's
        # TestCase as a local Tests\\TestCase based on its short name.
        for alias, fqcn in imports_by_path[path].items():
            target = fqcn_to_path.get(_normal(fqcn))
            if target:
                import_pattern = re.compile(r"\buse\s+" + re.escape(fqcn) + r"(?:\s+as\s+" + re.escape(alias) + r")?\s*;", re.I)
                import_match = import_pattern.search(code)
                import_line = _line(source, import_match.start()) if import_match else None
                add_edge(path, target, "imports", f"use {fqcn} as {alias}", import_line, "HIGH")
        # Inheritance and object creation are resolved in the current namespace/import context.
        for match in re.finditer(r"\b(?:extends|implements)\s+([\\A-Za-z_][A-Za-z0-9_\\]*(?:\s*,\s*[\\A-Za-z_][A-Za-z0-9_\\]*)*)", code):
            relation = "implements" if match.group(0).lstrip().lower().startswith("implements") else "extends"
            for ref in match.group(1).split(","):
                resolve(path, ref.strip(), relation, f"{relation} {ref.strip()}", _line(source, match.start()), "HIGH")
        for match in re.finditer(r"\bnew\s+(\\?[A-Za-z_][A-Za-z0-9_\\]*)", code):
            resolve(path, match.group(1), "instantiates", f"new {match.group(1)}", _line(source, match.start()), "HIGH")
        # Static class calls are linked only when the class resolves to a local
        # declaration through its FQCN/import context. This also prevents facade
        # calls such as Route::get from becoming database dependencies.
        static_call = re.compile(r"(?<![\w$])([\\A-Za-z_][A-Za-z0-9_\\]*)\s*::\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(")
        for m in static_call.finditer(code):
            ref, method = m.group(1), m.group(2)
            resolved = _resolve_reference(ref, namespaces.get(path), imports_by_path[path])
            target = fqcn_to_path.get(resolved) if resolved else None
            if target:
                relation = "uses_model" if role_by_path.get(target) == "Models" else "static_call"
                add_edge(path, target, relation, f"{ref}::{method}()", _line(source, m.start()), "HIGH")
                if role_by_path.get(target) == "Models" and method.lower() in MODEL_STATIC_METHODS:
                    findings.append({"source_path": path, "source_line": _line(source, m.start()),
                        "operation": MODEL_STATIC_METHODS[method.lower()], "source_expression": m.group(0)[:240],
                        "model_or_facade": ref, "confidence": "HIGH",
                        "status": "STATIC_DATABASE_SIGNAL_REQUIRES_REVIEW",
                        "limitations": ["Static call evidence does not prove execution or identify the active engine."]})
            elif "\\" not in ref.strip("\\") and len(short_name_paths.get(ref.split("\\")[-1].lower(), [])) > 1:
                unresolved.append({"source": path, "symbol": ref, "relationship": "static_call",
                    "line": _line(source, m.start()), "candidates": short_name_paths[ref.lower()],
                    "reason": "Ambiguous short class name; no namespace/import context resolves it"})
        # Instance method relationships are emitted only when a variable is
        # directly assigned from a locally resolvable `new ClassName()`.
        variable_types = {}
        for m in re.finditer(r"\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+([\\A-Za-z_][A-Za-z0-9_\\]*)", code):
            resolved = _resolve_reference(m.group(2), namespaces.get(path), imports_by_path[path])
            if resolved and resolved in fqcn_to_path and fqcn_to_path[resolved]:
                variable_types[m.group(1)] = (resolved, fqcn_to_path[resolved])
                add_edge(path, fqcn_to_path[resolved], "instantiates", f"new {m.group(2)}", _line(source, m.start()), "HIGH")
        for m in re.finditer(r"\$([A-Za-z_][A-Za-z0-9_]*)\s*->\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(", code):
            receiver = variable_types.get(m.group(1))
            if receiver:
                target_path = receiver[1]
                relation = "calls_service" if role_by_path.get(target_path) == "Services" else "method_call"
                add_edge(path, target_path, relation, f"${m.group(1)}->{m.group(2)}()", _line(source, m.start()), "MEDIUM")
                if role_by_path.get(target_path) == "Models" and m.group(2).lower() in INSTANCE_METHODS:
                    findings.append({"source_path": path, "source_line": _line(source, m.start()),
                        "operation": INSTANCE_METHODS[m.group(2).lower()], "source_expression": m.group(0)[:240],
                        "model_or_facade": receiver[0], "confidence": "MEDIUM",
                        "status": "STATIC_DATABASE_SIGNAL_REQUIRES_REVIEW",
                        "limitations": ["Static call evidence does not prove execution or identify the active engine."]})

        # Literal include/require references only.
        for match in re.finditer(r"\b(include|include_once|require|require_once)\s*(?:\(\s*)?(['\"])([^'\"]+)\2", code, re.I):
            raw = match.group(3); candidate = (PurePosixPath(path).parent / raw).as_posix()
            candidate = str(PurePosixPath(candidate))
            if candidate not in by_path: candidate = str(PurePosixPath(raw.lstrip("./")))
            if candidate in by_path: add_edge(path, candidate, "includes", f"{match.group(1)} {raw}", _line(source, match.start()), "HIGH")

        # Carry forward independently extracted DB signals so coverage is based
        # on the same complete evidence set surfaced by the analysis pipeline.
        for signal in by_path[path].get("database_signals", []) or []:
            database_source_signals.append({"source_path": path, **signal})
        # Database driver configuration: record all driver literals, but never
        # claim the active runtime engine from static config alone.
        if re.search(r"(?:database|db|connection)", path, re.I):
            for m in re.finditer(r"(['\"])(mysql|mariadb|pgsql|postgresql|sqlite|sqlsrv|oci|odbc)\1", code, re.I):
                database_configs.append({"source_path": path, "source_line": _line(source, m.start()),
                    "driver": m.group(2).lower(), "confidence": "HIGH", "status": "STATIC_CONFIGURATION_EVIDENCE_REQUIRES_REVIEW"})
            default_match = re.search(r"['\"]default['\"]\s*=>\s*(?:env\s*\(\s*['\"]DB_CONNECTION['\"]\s*,\s*)?(['\"])([A-Za-z0-9_]+)\1", code, re.I)
            if default_match:
                default_connection_evidence.append({"source_path": path, "source_line": _line(source, default_match.start()),
                    "configured_default_candidate": default_match.group(2).lower(),
                    "status": "STATIC_DEFAULT_CONFIGURATION_REQUIRES_RUNTIME_VERIFICATION"})
        # Detect schema operations and associate Laravel-style column DSL with
        # the enclosing table callback and up/down migration direction.
        if re.search(r"(?:migration|schema|database)", path, re.I):
            table_pattern = re.compile(
                r"(?:Schema\s*::\s*)?(create|table|dropIfExists|drop)\s*"
                r"\(\s*(['\"])([^'\"]+)\2\s*(?:,\s*function\s*\([^)]*\)\s*\{)?",
                re.I)
            for m in table_pattern.finditer(code):
                operation, table_name = m.group(1), m.group(3)
                direction_matches = list(re.finditer(r"\bfunction\s+(up|down)\s*\(", code[:m.start()], re.I))
                direction = direction_matches[-1].group(1).upper() if direction_matches else "UNKNOWN"
                record = {"source_path": path, "source_line": _line(source, m.start()),
                    "operation": operation, "direction": direction, "table": table_name,
                    "columns": [], "constraints": [], "indexes": [], "schema_macro_evidence": [], "confidence": "MEDIUM",
                    "status": "STATIC_SCHEMA_EVIDENCE_REQUIRES_REVIEW",
                    "limitations": ["Static migration source is not proof of the deployed database schema.",
                                    "Dynamic column names, macros, custom Blueprint extensions and runtime migration order may be unresolved."]}
                callback_open = code.find("{", m.start(), min(len(code), m.end() + 8))
                if callback_open >= 0 and operation.lower() in {"create", "table"}:
                    depth, callback_end = 1, callback_open + 1
                    while callback_end < len(code) and depth:
                        if code[callback_end] == "{": depth += 1
                        elif code[callback_end] == "}": depth -= 1
                        callback_end += 1
                    callback = code[callback_open + 1:callback_end - 1]
                    # Keep Blueprint shorthand helpers separate from explicit
                    # column declarations. Methods such as id(), timestamps(),
                    # softDeletes() and rememberToken() expand into multiple
                    # columns (or framework-managed conventions); treating each
                    # as one ordinary column corrupts the schema catalogue.
                    macro_pattern = re.compile(
                        r"->\s*(id|increments|bigIncrements|timestamps|timestampsTz|softDeletes|softDeletesTz|rememberToken|morphs|nullableMorphs|uuidMorphs|ulidMorphs)\s*\(\s*([^)]*)\)",
                        re.I)
                    for macro in macro_pattern.finditer(callback):
                        raw_args = macro.group(2).strip()
                        macro_args = re.findall(r'''['"]([^'"]*)['"]''', raw_args)
                        record.setdefault("schema_macro_evidence", []).append({
                            "source_path": path,
                            "source_line": _line(source, callback_open + 1 + macro.start()),
                            "table": table_name,
                            "macro": macro.group(1),
                            "arguments": macro_args,
                            "raw_arguments": raw_args[:160],
                            "status": "FRAMEWORK_SCHEMA_MACRO_REQUIRES_ADAPTER_EXPANSION",
                            "limitations": ["Not emitted as a concrete column; expansion depends on framework and version."]})
                    column_pattern = re.compile(
                        r"->\s*(uuid|foreignId|foreignIdFor|string|char|text|mediumText|longText|integer|tinyInteger|smallInteger|mediumInteger|bigInteger|unsignedTinyInteger|unsignedSmallInteger|unsignedMediumInteger|unsignedInteger|unsignedBigInteger|boolean|date|dateTime|timestamp|decimal|float|double|json|enum|binary)\s*"
                        r"\(\s*(?:(['\"])([^'\"]+)\2)?", re.I)
                    for col in column_pattern.finditer(callback):
                        tail = callback[col.end():]
                        tail = tail.lstrip()
                        if tail.startswith(")"):
                            tail = tail[1:]
                        chain = re.match(r"((?:\s*->\s*[A-Za-z_][A-Za-z0-9_]*\s*(?:\([^;()]*\))?){0,12})", tail)
                        chain_text = chain.group(1) if chain else ""
                        modifier_calls = []
                        for modifier in re.finditer(r"->\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(([^()]*)\))?", chain_text):
                            raw_args = (modifier.group(2) or "").strip()
                            literals = re.findall(r"['\"]([^'\"]*)['\"]", raw_args)
                            modifier_calls.append({"name": modifier.group(1), "arguments": literals,
                                                  "raw_arguments": raw_args[:160]})
                        modifiers = [x["name"] for x in modifier_calls]
                        column = {"source_path": path, "source_line": _line(source, callback_open + 1 + col.start()),
                            "table": table_name, "column_type_candidate": col.group(1),
                            "column_name_candidate": col.group(3), "modifiers": modifiers,
                            "modifier_calls": modifier_calls,
                            "nullable_candidate": "nullable" in modifiers,
                            "unique_candidate": "unique" in modifiers,
                            "primary_candidate": "primary" in modifiers,
                            "indexed_candidate": "index" in modifiers,
                            "unsigned_candidate": "unsigned" in modifiers or col.group(1).lower().startswith("unsigned"),
                            "default_candidate": next((x["arguments"][0] for x in modifier_calls if x["name"] == "default" and x["arguments"]), None),
                            "references_candidate": next((x["arguments"][0] for x in modifier_calls if x["name"] in {"constrained", "references"} and x["arguments"]), None),
                            "confidence": "MEDIUM", "status": "STATIC_COLUMN_EVIDENCE_REQUIRES_REVIEW"}
                        record["columns"].append(column)
                        schema_columns.append(column)
                        # Column modifiers are first-class schema evidence too. In
                        # Laravel Blueprint, ->unique(), ->index() and ->primary()
                        # create constraints/indexes even without a separate call.
                        for modifier_name, kind in (("unique", "unique"), ("index", "index"), ("primary", "primary")):
                            if modifier_name in modifiers:
                                record["indexes"].append({
                                    "source_path": path, "source_line": column["source_line"],
                                    "table": table_name, "kind": kind,
                                    "columns": [column_name] if (column_name := col.group(3)) else [],
                                    "name_candidate": next((arg for call in modifier_calls if call["name"] == modifier_name for arg in call["arguments"][1:]), None),
                                    "evidence_source": "column_modifier",
                                    "status": "STATIC_INDEX_EVIDENCE_REQUIRES_REVIEW"})
                        if "unique" in modifiers or "primary" in modifiers:
                            record["constraints"].append({
                                "source_path": path, "source_line": column["source_line"],
                                "table": table_name,
                                "kind": "unique_constraint_candidate" if "unique" in modifiers else "primary_key_candidate",
                                "columns": [column_name] if (column_name := col.group(3)) else [],
                                "status": "STATIC_CONSTRAINT_EVIDENCE_REQUIRES_REVIEW"})
                    # Index and constraint declarations. Capture chained foreign-key
                    # semantics (references/on/cascade) rather than requiring the
                    # foreign() call to be immediately followed by a semicolon.
                    for idx in re.finditer(r"->\s*(primary|unique|index|fullText|spatialIndex)\s*\(\s*([^;]*?)\)\s*;", callback, re.I):
                        raw = idx.group(2).strip()
                        cols = re.findall(r"['\"]([^'\"]+)['\"]", raw)
                        record["indexes"].append({"source_path": path,
                            "source_line": _line(source, callback_open + 1 + idx.start()),
                            "table": table_name, "kind": idx.group(1).lower(), "columns": cols,
                            "raw_arguments": raw[:200],
                            "name_candidate": cols[-1] if len(cols) > len(set(cols)) else None,
                            "status": "STATIC_INDEX_EVIDENCE_REQUIRES_REVIEW"})
                    for fk in re.finditer(r"->\s*foreign\s*\(\s*([^)]*)\)([^;]*);", callback, re.I):
                        raw = fk.group(1).strip()
                        chain = fk.group(2)
                        args = re.findall(r"['\"]([^'\"]*)['\"]", raw)
                        chain_calls = []
                        for call in re.finditer(r"->\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(\s*([^)]*)\s*\))?", chain):
                            call_args = re.findall(r"['\"]([^'\"]*)['\"]", call.group(2) or "")
                            chain_calls.append({"name": call.group(1), "arguments": call_args})
                        by_name = {x["name"].lower(): x["arguments"] for x in chain_calls}
                        record["constraints"].append({
                            "source_path": path, "source_line": _line(source, callback_open + 1 + fk.start()),
                            "table": table_name, "kind": "foreign_key_candidate",
                            "columns": args, "referenced_columns_candidate": by_name.get("references", []),
                            "referenced_table_candidate": by_name.get("on", []),
                            "actions_candidate": [{"method": x["name"], "arguments": x["arguments"]} for x in chain_calls if x["name"].lower() in {"cascadeondelete", "restrictondelete", "nullondelete", "noactionondelelte", "cascadeonupdate", "restrictonupdate", "nullonupdate", "noactiononupdate", "ondelete", "onupdate"}],
                            "chain_evidence": chain.strip()[:300],
                            "status": "STATIC_CONSTRAINT_EVIDENCE_REQUIRES_REVIEW"})
                    # Laravel foreignId(...)->constrained(...) chains are captured from column metadata.
                    for col_data in record["columns"]:
                        if col_data.get("column_type_candidate", "").lower() in {"foreignid", "foreignidfor"} and "constrained" in col_data.get("modifiers", []):
                            record["constraints"].append({"source_path": path, "source_line": col_data["source_line"],
                                "table": table_name, "kind": "foreign_key_candidate",
                                "column": col_data.get("column_name_candidate"),
                                "references_candidate": col_data.get("references_candidate"),
                                "referenced_table_candidate": col_data.get("references_candidate"),
                                "reference_inference": ("EXPLICIT_CONSTRAINED_ARGUMENT" if col_data.get("references_candidate") else "CONVENTION_NOT_RESOLVED"),
                                "actions_candidate": [{"method": call["name"], "arguments": call["arguments"]}
                                    for call in col_data.get("modifier_calls", [])
                                    if call["name"].lower() in {"cascadeondelete", "restrictondelete", "nullondelete", "cascadeonupdate", "restrictonupdate", "nullonupdate", "ondelete", "onupdate"}],
                                "status": "STATIC_CONSTRAINT_EVIDENCE_REQUIRES_REVIEW"})
                schema_evidence.append(record)
        # Conservative DB access signals: explicit PDO/mysqli/DB facade and raw SQL.
        db_patterns = [(r"\bDB\s*::\s*(?:table|select|statement|insert|update|delete)\s*\(", "QUERY"),
                       (r"\bnew\s+PDO\s*\(", "CONNECTION"),
                       (r"\bmysqli_(?:query|prepare|connect)\s*\(", "QUERY"),
                       (r"\b(?:SELECT\s+.+?\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b", "RAW_SQL")]
        for pattern, operation in db_patterns:
            for m in re.finditer(pattern, code, re.I | (re.S if operation == "RAW_SQL" else 0)):
                findings.append({"source_path": path, "source_line": _line(source, m.start()),
                    "operation": operation, "source_expression": m.group(0)[:240], "confidence": "MEDIUM",
                    "status": "STATIC_DATABASE_SIGNAL_REQUIRES_REVIEW",
                    "limitations": ["Static evidence does not prove execution or identify the active engine."]})
        if re.search(r"\b(?:eval|call_user_func|call_user_func_array)\s*\(|\$\$", code):
            dynamic_uncertainties.append({"source": path, "reason": "Dynamic execution or dispatch limits static dependency resolution"})

    nodes = [{"id": p, "kind": "SOURCE_FILE", "role": role_by_path.get(p, "Other PHP"),
              "symbols": [*(by_path[p].get("classes", []) or []), *(by_path[p].get("interfaces", []) or []), *(by_path[p].get("traits", []) or [])]}
             for p in by_path]
    if findings or database_configs or schema_evidence:
        nodes.append({"id": "DATABASE:EXISTING_SYSTEM", "kind": "DATABASE_BOUNDARY",
                      "role": "Existing database; engine/schema require verification", "symbols": []})
    drivers = sorted({x["driver"] for x in database_configs})
    files_with_db_signals = {x["source_path"] for x in findings}
    files_with_db_signals.update(x["source_path"] for x in database_configs)
    files_with_db_signals.update(x["source_path"] for x in schema_evidence)
    files_with_db_signals.update(x["source_path"] for x in schema_columns)
    files_with_db_signals.update(x["source_path"] for x in database_source_signals)
    # Normalized, table-keyed schema catalogue. Preserve every migration operation
    # (including later alters/drops); do not collapse history into a claimed live schema.
    schema_catalog: dict[str, dict] = {}
    for operation_record in schema_evidence:
        table = operation_record.get("table") or "<dynamic>"
        entry = schema_catalog.setdefault(table, {"table": table, "operations": [], "column_evidence": [],
                                                   "constraint_evidence": [], "index_evidence": [], "schema_macro_evidence": [],
                                                   "status": "MIGRATION_HISTORY_EVIDENCE_REQUIRES_REVIEW"})
        entry["operations"].append({"operation": operation_record.get("operation"),
                                    "direction": operation_record.get("direction"),
                                    "source_path": operation_record.get("source_path"),
                                    "source_line": operation_record.get("source_line")})
        entry["column_evidence"].extend(operation_record.get("columns", []))
        entry["constraint_evidence"].extend(operation_record.get("constraints", []))
        entry["index_evidence"].extend(operation_record.get("indexes", []))
        entry["schema_macro_evidence"].extend(operation_record.get("schema_macro_evidence", []))
    # Column-level modifiers and explicit Blueprint index calls can describe
    # the same declaration. Deduplicate identical source-backed evidence.
    for entry in schema_catalog.values():
        unique_indexes = []
        seen_indexes = set()
        for item in entry["index_evidence"]:
            identity = (item.get("source_path"), item.get("source_line"),
                        item.get("kind"), tuple(item.get("columns", [])),
                        item.get("name_candidate"))
            if identity not in seen_indexes:
                seen_indexes.add(identity)
                unique_indexes.append(item)
        entry["index_evidence"] = unique_indexes
    schema_catalog_list = [schema_catalog[k] for k in sorted(schema_catalog)]
    # Imports are counted separately from local edges: external framework/vendor
    # classes are expected and must not be mistaken for unresolved local symbols.
    imported_class_count = sum(len(v) for v in imports_by_path.values())
    local_import_count = sum(1 for edge in edges if edge["type"] == "imports")
    coverage = {"source_files_considered": len(files),
        "files_with_database_signals": len(files_with_db_signals),
        "database_engine_identified": False,
        "database_engine_candidate_count": len(drivers),
        "configured_database_drivers": drivers,
        "configured_default_connection_candidate_count": len(default_connection_evidence),
        "schema_evidence_count": len(schema_evidence),
        "schema_column_evidence_count": len(schema_columns),
        "schema_macro_evidence_count": sum(len(x.get("schema_macro_evidence", [])) for x in schema_catalog_list),
        "runtime_call_order_verified": False,
        "unresolved_reference_count": len(unresolved),
        "dynamic_uncertainty_count": len(dynamic_uncertainties),
        "class_import_declarations": imported_class_count,
        "resolved_local_import_edges": local_import_count,
        "external_or_unresolved_imports_not_classified_as_local_edges": max(0, imported_class_count - local_import_count),
        "schema_table_candidate_count": len(schema_catalog_list),
        "schema_constraint_candidate_count": sum(len(x["constraint_evidence"]) for x in schema_catalog_list),
        "schema_index_candidate_count": sum(len(x["index_evidence"]) for x in schema_catalog_list),
        "foreign_key_candidate_count": sum(1 for x in schema_catalog_list for c in x["constraint_evidence"] if c.get("kind") == "foreign_key_candidate"),
        "referential_action_candidate_count": sum(1 for x in schema_catalog_list for c in x["constraint_evidence"] if c.get("actions_candidate"))}
    role_counts: dict[str, int] = {}
    for node in nodes: role_counts[node["role"]] = role_counts.get(node["role"], 0) + 1
    return {"status": "STATIC_DEPENDENCY_EVIDENCE_REQUIRES_REVIEW", "nodes": nodes,
        "edges": edges, "edge_count": len(edges), "database_operation_count": len(findings),
        "database_operations": findings, "database_configuration_evidence": database_configs,
        "database_schema_evidence": schema_evidence, "database_schema_operations": schema_evidence,
        "database_schema_column_evidence": schema_columns, "database_schema_catalog": schema_catalog_list,
        "database_source_signal_evidence": database_source_signals,
        "database_default_connection_evidence": default_connection_evidence,
        "database_engine_candidates": drivers,
        "unresolved_relationships": unresolved, "unresolved_reference_count": len(unresolved),
        "dynamic_uncertainties": dynamic_uncertainties,
        "runtime_uncertainty": {"call_order_verified": False, "reason": "Static source references do not establish execution order."},
        "role_inventory": role_counts, "coverage": coverage,
        "policy": "Static source references only. No PHP execution, database connection, schema mutation, or runtime call-order claim. Configured driver/default candidates are not proof of the active runtime engine."}
