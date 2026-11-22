"""V5.19 — Behavioural Contract Extraction.

Extracts *what each handler does* as structured, source-located facts:

* callable contracts  — inputs, model operations, side effects, guard clauses,
  exits (abort/throw/authorize) and return statements of controller/service methods;
* model contracts     — fillable/hidden/casts/relationships/traits;
* schema contracts    — columns and constraints from ``Schema::create`` migrations.

Nothing is executed. Unknown semantics are reported as ``NEEDS_REVIEW`` and
translatability is conservative: only recognised CRUD shapes are flagged simple.
"""
from __future__ import annotations

from pathlib import Path
import re

from app.dependency_graph import build_dependency_graph
from app.php_source import (IDENT, find_classes, find_methods, iter_php_files, line_of, mask_comments,
                            match_delim, parse_parameters, parse_value, safe_read, short_name, split_top_level, unquote)

ENGINE_VERSION = "5.19.0"
HANDLER_ROLES = {"controller", "service", "repository", "job"}
READ_OPS = {"all", "find", "findorfail", "first", "firstorfail", "get", "paginate", "simplepaginate", "count", "exists",
            "pluck", "value", "sum", "max", "min", "avg", "findmany", "firstwhere", "cursor"}
WRITE_OPS = {"create", "insert", "update", "updateorcreate", "firstorcreate", "save", "upsert", "increment",
             "decrement", "fill", "forcecreate", "createmany", "attach", "sync", "detach"}
DELETE_OPS = {"delete", "destroy", "forcedelete", "truncate"}
MODIFIER_OPS = {"where", "wherein", "wherenull", "wherenotnull", "orwhere", "latest", "oldest", "orderby", "with",
                "limit", "take", "skip", "select", "when", "has", "wherehas", "orderbydesc", "withtrashed", "ontlytrashed"}
SIDE_EFFECTS = {
    "password_hashing": r"\b(?:Hash\s*::\s*make|bcrypt\s*\()",
    "password_check": r"\bHash\s*::\s*check\b",
    "token_issue": r"->\s*createToken\s*\(",
    "token_revoke": r"->\s*(?:currentAccessToken|tokens)\s*\(\s*\)\s*->\s*delete",
    "session_login": r"\bAuth\s*::\s*(?:attempt|login|logout|loginUsingId)\b",
    "mail_or_notification": r"\b(?:Mail\s*::|->\s*notify\s*\(|Notification\s*::)",
    "event_dispatch": r"\b(?:event\s*\(|Event\s*::\s*dispatch|dispatch\s*\()",
    "outbound_http": r"\b(?:Http\s*::|curl_init|GuzzleHttp)",
    "file_storage": r"\b(?:Storage\s*::|->\s*store(?:As)?\s*\(|move_uploaded_file)",
    "cache": r"\bCache\s*::",
    "session_state": r"\bsession\s*\(|\$_SESSION",
    "logging": r"\bLog\s*::",
    "transaction": r"\bDB\s*::\s*(?:transaction|beginTransaction)\b",
    "raw_sql": r"\bDB\s*::\s*(?:select|insert|update|delete|statement|raw)\b",
}
INPUT_PATTERNS = [
    r"\$request\s*->\s*(?:input|get|query|post|string|integer|boolean|file|has|filled)\s*\(\s*('(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\")",
    r"\$request\s*->\s*([A-Za-z_][A-Za-z0-9_]*)\b(?!\s*\()",
    r"\$_(?:GET|POST|REQUEST)\s*\[\s*('(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\")\s*\]",
]
PLURAL_EXCEPTIONS = {"person": "people", "child": "children", "man": "men", "woman": "women"}


def snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def pluralize(word: str) -> str:
    word = word.lower()
    if word in PLURAL_EXCEPTIONS:
        return PLURAL_EXCEPTIONS[word]
    if re.search(r"(?:s|x|z|ch|sh)$", word):
        return word + "es"
    if re.search(r"[^aeiou]y$", word):
        return word[:-1] + "ies"
    return word + "s"


def _statement_end(text: str, start: int) -> int:
    depth, i, n = 0, start, len(text)
    while i < n:
        c = text[i]
        if c in "'\"`":
            q = c; i += 1
            while i < n and text[i] != q:
                i += 2 if text[i] == "\\" else 1
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth < 0:
                return i
        elif c == ";" and depth == 0:
            return i
        i += 1
    return n


def _walk_chain(text: str, pos: int, first_is_call: bool = True) -> list[tuple[str, str, int]]:
    """Follow ``name(args)->name(args)`` starting at ``pos``; returns (name, args, end)."""
    calls, i = [], pos
    head = re.compile(rf"\s*({IDENT})\s*\(")
    link = re.compile(rf"\s*\??->\s*({IDENT})\s*\(")
    first = True
    while True:
        m = (head if first and first_is_call else link).match(text, i)
        if not m:
            break
        open_pos = m.end() - 1
        close = match_delim(text, open_pos)
        if close is None:
            break
        calls.append((m.group(1), text[open_pos + 1:close], close + 1))
        i, first = close + 1, False
    return calls


def _classify(op: str) -> str | None:
    low = op.lower()
    return "read" if low in READ_OPS else "write" if low in WRITE_OPS else "delete" if low in DELETE_OPS else None


def _literal_conditions(chain) -> list[dict]:
    out = []
    for name, args, _ in chain:
        if name.lower() in {"where", "orwhere"}:
            parts = [parse_value(p) for p in split_top_level(args)]
            if len(parts) >= 2 and isinstance(parts[0], str):
                out.append({"field": parts[0], "operator": "=" if len(parts) == 2 else parts[1],
                            "value": parts[-1] if not hasattr(parts[-1], "text") else {"$raw": parts[-1].text}})
    return out


def _model_operations(body: str, models: dict[str, str], bound: dict[str, str], base_line: int) -> list[dict]:
    ops = []
    def record(model, relation, chain, offset, via):
        terminal = next((c for c in reversed(chain) if _classify(c[0])), None)
        if not terminal:
            return
        modifiers = [c[0] for c in chain if c[0].lower() in MODIFIER_OPS]
        assign = re.search(r"\$([A-Za-z_]\w*)\s*=\s*\(?\s*$", body[max(0, offset - 60):offset])
        entry = {"model": model, "relation": relation, "operation": terminal[0], "kind": _classify(terminal[0]),
                 "assigned_to": assign.group(1) if assign else None,
                 "modifiers": modifiers, "conditions": _literal_conditions(chain), "via": via,
                 "line": base_line + body.count("\n", 0, offset), "evidence": body[offset:chain[-1][2]].strip()[:240]}
        if terminal[0].lower() in {"paginate", "simplepaginate"}:
            size = parse_value(terminal[1].split(",")[0]) if terminal[1].strip() else None
            entry["page_size"] = size if isinstance(size, int) else None
        ops.append(entry)
    for m in re.finditer(rf"\\?({IDENT}(?:\\{IDENT})*)\s*::\s*(?=({IDENT})\s*\()", body):
        model = models.get(short_name(m.group(1)).lower())
        if model:
            record(model, None, _walk_chain(body, m.end()), m.start(), "static")
    for m in re.finditer(r"\$([A-Za-z_][A-Za-z0-9_]*)\s*->\s*", body):
        var = m.group(1)
        if var in bound:  # route-model-bound instance: $post->update(...), $post->comments()->get()
            chain = _walk_chain(body, m.end(), True)
            if chain and _classify(chain[0][0]):
                record(bound[var], None, chain, m.start(), "bound_instance")
            elif chain:
                record(bound[var], chain[0][0], chain[1:], m.start(), "bound_relation")
    return sorted(ops, key=lambda o: (o["line"], o["evidence"]))


def _guards(body: str, base_line: int) -> list[dict]:
    guards = []
    for m in re.finditer(r"\bif\s*\(", body):
        open_pos = m.end() - 1
        close = match_delim(body, open_pos)
        if close is None:
            continue
        rest = body[close + 1:].lstrip()
        offset = close + 1 + (len(body[close + 1:]) - len(rest))
        if rest.startswith("{"):
            end = match_delim(body, offset)
            block = body[offset + 1:end] if end else ""
        else:
            end = _statement_end(body, offset)
            block = body[offset:end]
        exit_m = re.search(r"\b(abort(?:_if|_unless)?)\s*\(\s*(\d{3})|\breturn\b[^;]*?\b(\d{3})\b|\bthrow\s+new\s+\\?([A-Za-z0-9_\\]+)|\breturn\b", block)
        if exit_m:
            status = exit_m.group(2) or exit_m.group(3)
            guards.append({"condition": body[open_pos + 1:close].strip()[:200], "line": base_line + body.count("\n", 0, m.start()),
                           "exit": "abort" if exit_m.group(1) else "throw" if exit_m.group(4) else "return",
                           "status": int(status) if status else None,
                           "exception": exit_m.group(4), "evidence": block.strip()[:200]})
    return guards


def _returns(body: str, base_line: int) -> list[dict]:
    result = []
    for m in re.finditer(r"\breturn\b", body):
        end = _statement_end(body, m.end())
        expr = body[m.end():end].strip()
        # Ignore returns inside nested closures only when the closure is a validator/callback argument.
        result.append({"line": base_line + body.count("\n", 0, m.start()), "expression": expr[:600]})
    return result


def _inputs(body: str) -> dict:
    fields = []
    for pattern in INPUT_PATTERNS:
        for m in re.finditer(pattern, body):
            value = unquote(m.group(1)) if m.group(1)[:1] in "'\"" else m.group(1)
            if value and value not in fields and value not in {"user", "validate", "validated", "all", "only", "except",
                                                               "input", "query", "file", "route", "merge", "has", "filled"}:
                fields.append(value)
    return {"fields": fields,
            "uses_validated": bool(re.search(r"->\s*validated\s*\(", body)),
            "uses_validate": bool(re.search(r"->\s*validate\s*\(|Validator\s*::\s*make", body)),
            "uses_all": bool(re.search(r"\$request\s*->\s*all\s*\(", body)),
            "uses_files": bool(re.search(r"->\s*file\s*\(|\$_FILES", body)),
            "authenticated_user_read": bool(re.search(r"\$request\s*->\s*user\s*\(|\bauth\s*\(\s*\)|\bAuth\s*::\s*(?:user|id)\b", body))}


def _complexity(body: str) -> int:
    return 1 + len(re.findall(r"\b(?:if|elseif|for|foreach|while|case|catch)\b|&&|\|\||\?(?!->)", body))


def extract_callable_contracts(root: str | Path, graph: dict | None = None) -> list[dict]:
    root = Path(root).resolve(strict=True)
    graph = graph or build_dependency_graph(root)
    by_id = {n["id"]: n for n in graph["nodes"]}
    models = {short_name(n["id"]).lower(): n["id"] for n in graph["nodes"] if n["role"] == "model"}
    contracts = []
    for node in graph["nodes"]:
        if node["role"] not in HANDLER_ROLES or node["kind"] != "class":
            continue
        source = safe_read(root, node["file"])
        if source is None:
            continue
        text = mask_comments(source)
        cls = next((c for c in find_classes(source) if f"\\{c['name']}" == "\\" + short_name(node["id"])), None)
        if not cls:
            continue
        for method in find_methods(text, cls["body_start"], cls["body_end"]):
            if method["name"].startswith("__") or method["visibility"] != "public":
                continue
            body, base_line = method["body"], method["line"]
            params = parse_parameters(method["params_text"])
            bound = {}
            for p in params:
                kind = "scalar"
                target = models.get(short_name(p["type"] or "").lower()) if p["type"] else None
                if target:
                    kind, bound[p["name"]] = "route_model", target
                elif p["type"] and p["type"].endswith("Request"):
                    kind = "form_request" if p["type"] not in {"Request"} else "request"
                p["kind"], p["model"] = kind, target
            effects = sorted(k for k, pat in SIDE_EFFECTS.items() if re.search(pat, body))
            ops = _model_operations(body, models, bound, base_line)
            guards, returns = _guards(body, base_line), _returns(body, base_line)
            authorize = [{"ability": a[0], "subject": a[1].strip()[:80]} for a in
                         [(unquote(split_top_level(m.group(1))[0]) or "?", ",".join(split_top_level(m.group(1))[1:]))
                          for m in re.finditer(r"->\s*authorize\s*\(([^;]*?)\)\s*;", body)]]
            exits = [{"kind": "abort", "status": int(m.group(2)), "line": base_line + body.count("\n", 0, m.start())}
                     for m in re.finditer(r"\babort(_if|_unless)?\s*\(\s*(?:[^,()]+,\s*)?(\d{3})", body)]
            exits += [{"kind": "throw", "exception": m.group(1), "line": base_line + body.count("\n", 0, m.start())}
                      for m in re.finditer(r"\bthrow\s+new\s+\\?([A-Za-z0-9_\\]+)", body)]
            complexity = _complexity(body)
            bindings = [{"parameter": p["name"], "model": p["model"], "operation": "findOrFail", "kind": "read",
                         "via": "route_model_binding"} for p in params if p["kind"] == "route_model"]
            simple = (complexity <= 3 and not set(effects) - {"password_hashing", "token_issue"} and len(ops) <= 2)
            contracts.append({
                "id": f"{node['id']}::{method['name']}", "class": node["id"], "role": node["role"],
                "method": method["name"], "source_path": node["file"], "source_line": base_line,
                "parameters": params, "inputs": _inputs(body), "model_operations": ops,
                "route_model_bindings": bindings, "side_effects": effects, "authorization_calls": authorize, "guard_clauses": guards,
                "exits": exits, "returns": returns, "complexity": complexity,
                "translation_class": "SIMPLE_CRUD_CANDIDATE" if simple and (ops or bindings) else "NEEDS_MANUAL_REVIEW",
                "status": "EXTRACTED_STATIC_EVIDENCE", "confidence": "MEDIUM",
                "limitations": ["Static extraction; reachability, runtime values and dynamic dispatch are not evaluated."],
            })
    return sorted(contracts, key=lambda c: c["id"])


# ------------------------------------------------------------------- models/schema
def _array_prop(body: str, name: str):
    m = re.search(rf"\$\s*{name}\s*=\s*", body)
    if not m:
        return None
    end = _statement_end(body, m.end())
    return parse_value(body[m.end():end])


def extract_model_contracts(root: str | Path, graph: dict | None = None) -> list[dict]:
    root = Path(root).resolve(strict=True)
    graph = graph or build_dependency_graph(root)
    models = []
    rel_pattern = re.compile(r"->\s*(hasOne|hasMany|belongsTo|belongsToMany|morphTo|morphMany|hasManyThrough)\s*\(")
    for node in graph["nodes"]:
        if node["role"] != "model" or node["kind"] != "class":
            continue
        source = safe_read(root, node["file"])
        cls = next(iter(find_classes(source or "")), None)
        if not cls:
            continue
        text = mask_comments(source)
        body = text[cls["body_start"]:cls["body_end"]]
        table = _array_prop(body, "table")
        casts = _array_prop(body, "casts")
        relations = []
        for method in find_methods(text, cls["body_start"], cls["body_end"]):
            m = rel_pattern.search(method["body"])
            if m and method["name"] != "casts":
                args = split_top_level(method["body"][m.end():match_delim(method["body"], m.end() - 1)])
                related = parse_value(args[0]) if args else None
                relations.append({"name": method["name"], "type": m.group(1),
                                  "related": related["$class"] if isinstance(related, dict) and "$class" in related else None,
                                  "extra_arguments": [str(parse_value(a)) for a in args[1:]], "line": method["line"]})
        name = short_name(node["id"])
        models.append({
            "id": node["id"], "name": name, "source_path": node["file"],
            "table": table if isinstance(table, str) else pluralize(snake(name)),
            "table_source": "EXPLICIT_PROPERTY" if isinstance(table, str) else "LARAVEL_NAMING_CONVENTION",
            "fillable": _array_prop(body, "fillable") if isinstance(_array_prop(body, "fillable"), list) else [],
            "guarded": _array_prop(body, "guarded") if isinstance(_array_prop(body, "guarded"), list) else None,
            "hidden": _array_prop(body, "hidden") if isinstance(_array_prop(body, "hidden"), list) else [],
            "casts": casts if isinstance(casts, dict) else {},
            "traits": [short_name(t) for t in cls["traits"]], "extends": cls["extends"],
            "soft_deletes": any(short_name(t) == "SoftDeletes" for t in cls["traits"]),
            "authenticatable": any("Authenticatable" in e or e.endswith("User") for e in cls["extends"]),
            "relationships": relations,
        })
    return sorted(models, key=lambda m: m["id"])


COLUMN_TYPES = {"id": "bigint", "bigIncrements": "bigint", "increments": "integer", "string": "string", "char": "string",
                "text": "text", "longText": "text", "mediumText": "text", "integer": "integer", "bigInteger": "bigint",
                "unsignedBigInteger": "bigint", "smallInteger": "integer", "tinyInteger": "integer", "boolean": "boolean",
                "json": "json", "jsonb": "json", "timestamp": "datetime", "dateTime": "datetime", "date": "date",
                "decimal": "decimal", "float": "float", "double": "float", "enum": "enum", "uuid": "uuid",
                "foreignId": "foreign_key", "foreignUuid": "foreign_key", "ulid": "uuid"}


def extract_schema_contracts(root: str | Path) -> list[dict]:
    root = Path(root).resolve(strict=True)
    tables: dict[str, dict] = {}
    for rel in iter_php_files(root):
        if not rel.startswith("database/migrations/"):
            continue
        source = safe_read(root, rel)
        if not source:
            continue
        text = mask_comments(source)
        for m in re.finditer(r"Schema\s*::\s*(create|table)\s*\(\s*('(?:[^'\\]|\\.)*'|\"[^\"]*\")\s*,\s*function\s*\([^)]*\)\s*\{", text):
            end = match_delim(text, text.find("{", m.end() - 1))
            if end is None:
                continue
            name = unquote(m.group(2)) or "?"
            table = tables.setdefault(name, {"table": name, "columns": [], "created_in": rel, "indexes": [], "soft_deletes": False,
                                             "timestamps": False, "migrations": []})
            table["migrations"].append(rel)
            block = text[m.end():end]
            for stmt in (s for s in split_top_level(block, ";") if s.strip().startswith("$table")):
                calls = _walk_chain(stmt, stmt.find("->") + 2, True) if "->" in stmt else []
                if not calls:
                    continue
                kind, args, _ = calls[0]
                args_list = [parse_value(a) for a in split_top_level(args)]
                mods = {c[0]: [parse_value(a) for a in split_top_level(c[1])] for c in calls[1:]}
                if kind == "timestamps":
                    table["timestamps"] = True; continue
                if kind == "softDeletes":
                    table["soft_deletes"] = True; continue
                if kind == "rememberToken":
                    table["columns"].append({"name": "remember_token", "type": "string", "nullable": True}); continue
                if kind in {"unique", "index"}:
                    table["indexes"].append({"kind": kind, "columns": [str(a) for a in (args_list[0] if args_list and isinstance(args_list[0], list) else args_list)]}); continue
                if kind not in COLUMN_TYPES:
                    table.setdefault("unrecognised", []).append(stmt.strip()[:120]); continue
                column = "id" if kind in {"id", "bigIncrements", "increments"} and not args_list else (args_list[0] if args_list and isinstance(args_list[0], str) else None)
                if column is None:
                    continue
                entry = {"name": column, "type": COLUMN_TYPES[kind], "laravel_type": kind, "nullable": "nullable" in mods,
                         "unique": "unique" in mods, "primary": kind in {"id", "bigIncrements", "increments"},
                         "indexed": "index" in mods}
                if "default" in mods and mods["default"]:
                    default = mods["default"][0]
                    entry["default"] = default if not hasattr(default, "text") else {"$raw": default.text}
                if kind == "string" and len(args_list) > 1 and isinstance(args_list[1], int):
                    entry["length"] = args_list[1]
                if kind == "enum" and len(args_list) > 1 and isinstance(args_list[1], list):
                    entry["enum_values"] = [str(v) for v in args_list[1]]
                if kind in {"foreignId", "foreignUuid"}:
                    ref = pluralize(column[:-3]) if column.endswith("_id") else None
                    entry["references"] = {"table": ref, "source": "constrained() naming convention" if "constrained" in mods else "NAME_CONVENTION_ONLY",
                                           "enforced": "constrained" in mods, "on_delete": "cascade" if "cascadeOnDelete" in mods else None}
                table["columns"].append(entry)
    return sorted(tables.values(), key=lambda t: t["table"])


def extract_behavioural_contracts(root: str | Path, graph: dict | None = None) -> dict:
    root = Path(root).resolve(strict=True)
    graph = graph or build_dependency_graph(root)
    callables = extract_callable_contracts(root, graph)
    return {"engine": "behavioural_contracts", "engine_version": ENGINE_VERSION,
            "graph_fingerprint": graph["fingerprint"],
            "callable_contracts": callables, "model_contracts": extract_model_contracts(root, graph),
            "schema_contracts": extract_schema_contracts(root),
            "summary": {"callables": len(callables),
                        "simple_crud_candidates": sum(c["translation_class"] == "SIMPLE_CRUD_CANDIDATE" for c in callables),
                        "needs_manual_review": sum(c["translation_class"] == "NEEDS_MANUAL_REVIEW" for c in callables)},
            "policy": "Static evidence only; contracts are inputs to review and parity checking, not proof of runtime behaviour."}
