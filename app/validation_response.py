"""V5.22 — Validation and HTTP Response Analysis.

Validation
    FormRequest ``rules()``, inline ``$request->validate([...])`` and
    ``Validator::make()`` rules are parsed into a typed field schema and mapped to a
    zod schema. Rules with no safe equivalent (conditional requirements, custom
    ``Rule::`` objects, unknown rules) are reported in ``unsupported`` and force review.

Responses
    Handler ``return`` statements are classified (json / no_content / resource /
    resource_collection / redirect / view / implicit model serialisation) with
    literal status codes, response shapes, ``JsonResource`` field maps, the
    default ``data`` wrapper and the pagination envelope. Framework-generated error
    contracts (401/403/404/422) are recorded as *assumed defaults*.
"""
from __future__ import annotations

import json
from pathlib import Path
import re

from app.contract_extraction import _statement_end, extract_behavioural_contracts
from app.dependency_graph import build_dependency_graph
from app.php_source import (IDENT, Raw, find_classes, find_methods, mask_comments, match_delim, parse_value, safe_read,
                            short_name, split_top_level, unquote)
from app.routes_intelligence import build_routes_intelligence

ENGINE_VERSION = "5.22.0"
TYPE_RULES = {"string": "string", "integer": "integer", "int": "integer", "numeric": "number", "boolean": "boolean",
              "bool": "boolean", "array": "array", "file": "file", "image": "file", "date": "date", "email": "string",
              "url": "string", "uuid": "string", "json": "string", "ip": "string", "alpha": "string", "alpha_num": "string",
              "alpha_dash": "string", "mimes": "file", "mimetypes": "file", "date_format": "string", "accepted": "boolean"}
CONDITIONAL = {"required_if", "required_unless", "required_with", "required_with_all", "required_without",
               "required_without_all", "exclude_if", "exclude_unless", "prohibited_if", "missing_if"}
KNOWN = set(TYPE_RULES) | CONDITIONAL | {"required", "nullable", "sometimes", "min", "max", "size", "between", "in", "not_in",
        "regex", "confirmed", "unique", "exists", "same", "different", "after", "before", "after_or_equal", "before_or_equal",
        "present", "filled", "digits", "digits_between", "bail", "distinct", "starts_with", "ends_with", "prohibited"}
FRAMEWORK_ERRORS = {
    422: {"body": {"message": "string", "errors": "Record<field, string[]>"}, "when": "validation fails"},
    401: {"body": {"message": "Unauthenticated."}, "when": "auth middleware rejects an unauthenticated request"},
    403: {"body": {"message": "This action is unauthorized."}, "when": "authorize()/Gate/policy denies"},
    404: {"body": {"message": "No query results for model [Model] id"}, "when": "route-model binding / findOrFail misses"},
    429: {"body": {"message": "Too Many Attempts."}, "when": "throttle middleware limit exceeded"},
}


def parse_rules(value) -> tuple[list[dict], list[str]]:
    """Return ([{name,args}], unsupported_raw_rules) for a string/list rule definition."""
    items = split_top_level(value, "|") if isinstance(value, str) else value if isinstance(value, list) else [value]
    rules, raw = [], []
    for item in items:
        if isinstance(item, str):
            for piece in ([item] if isinstance(value, list) else [item]):
                name, _, arg_text = piece.strip().partition(":")
                args = [arg_text] if name.lower() == "regex" else [a.strip() for a in arg_text.split(",")] if arg_text else []
                rules.append({"name": name.strip().lower(), "args": args})
        else:
            raw.append(str(item))
    return rules, raw


def _num(text: str):
    try:
        return int(text)
    except (TypeError, ValueError):
        try:
            return float(text)
        except (TypeError, ValueError):
            return None


def build_field_schema(field: str, rule_definition) -> dict:
    rules, raw = parse_rules(rule_definition)
    names = {r["name"] for r in rules}
    ftype = next((TYPE_RULES[r["name"]] for r in rules if r["name"] in TYPE_RULES), "any")
    schema = {"field": field, "type": ftype, "required": "required" in names, "nullable": "nullable" in names,
              "sometimes": "sometimes" in names, "constraints": {}, "async_checks": [], "conditional": [], "unsupported": list(raw)}
    c = schema["constraints"]
    for r in rules:
        n, a = r["name"], r["args"]
        if n in {"min", "max", "size"} and a and _num(a[0]) is not None:
            c[n] = _num(a[0])
        elif n == "between" and len(a) == 2:
            c["min"], c["max"] = _num(a[0]), _num(a[1])
        elif n in {"in", "not_in"}:
            c[n] = a
        elif n == "regex" and a:
            c["regex"] = a[0]
        elif n in {"email", "url", "uuid", "ip", "alpha", "alpha_num", "alpha_dash", "json", "confirmed", "distinct", "filled"}:
            c[n] = True
        elif n == "date_format" and a:
            c["date_format"] = a[0]
        elif n in {"unique", "exists"}:
            table, column = (a + [None, None])[:2] if a else (None, None)
            schema["async_checks"].append({"type": n, "table": table, "column": column or field, "extra_arguments": a[2:]})
        elif n in {"same", "different", "after", "before", "after_or_equal", "before_or_equal", "starts_with", "ends_with"}:
            c[n] = a
        elif n in CONDITIONAL:
            schema["conditional"].append({"rule": n, "arguments": a})
        elif n in {"mimes", "mimetypes"}:
            c[n] = a
        elif n not in KNOWN:
            schema["unsupported"].append(n)
    if ftype == "any" and any(k in c for k in ("regex", "email", "url", "uuid", "alpha", "alpha_num", "alpha_dash")):
        schema["type"] = "string"  # pattern rules imply string input; never drop them silently
    schema["status"] = "REVIEW_REQUIRED" if schema["unsupported"] or schema["conditional"] else "MAPPED"
    return schema


def _zod_field(schema: dict, items: dict | None, as_item: bool = False) -> str:
    c, t = schema["constraints"], schema["type"]
    if "in" in c and t in {"string", "any"}:
        expr = "z.enum(" + json.dumps(c["in"]) + ")"
    elif t == "integer":
        expr = "z.coerce.number().int()" + (f".min({c['min']})" if "min" in c else "") + (f".max({c['max']})" if "max" in c else "")
    elif t == "number":
        expr = "z.coerce.number()" + (f".min({c['min']})" if "min" in c else "") + (f".max({c['max']})" if "max" in c else "")
    elif t == "boolean":
        expr = "looseBoolean"
    elif t == "date":
        expr = "z.coerce.date()"
    elif t == "array":
        inner = _zod_field(items, None, as_item=True) if items else "z.unknown()"
        expr = f"z.array({inner})" + (f".min({c['min']})" if "min" in c else "") + (f".max({c['max']})" if "max" in c else "")
    elif t == "file":
        expr = "z.any()"
    elif t == "any":
        expr = "z.any()"
    else:
        expr = "z.string()"
        if c.get("email"): expr += ".email()"
        if c.get("url"): expr += ".url()"
        if c.get("uuid"): expr += ".uuid()"
        if c.get("alpha"): expr += ".regex(/^[A-Za-z]+$/)"
        if c.get("alpha_num"): expr += ".regex(/^[A-Za-z0-9]+$/)"
        if c.get("alpha_dash"): expr += ".regex(/^[A-Za-z0-9_-]+$/)"
        minimum = c.get("min", 1 if schema["required"] else None)
        if minimum is not None: expr += f".min({minimum})"
        if "max" in c: expr += f".max({c['max']})"
        if "size" in c: expr += f".length({c['size']})"
        rx = c.get("regex")
        delimiter = re.fullmatch(r"/(.+)/([a-z]*)", rx or "", re.S)
        if delimiter:
            try:
                re.compile(delimiter.group(1))   # an uncompilable pattern would crash the generated server at load time
            except re.error:
                schema["unsupported"].append("regex(pattern does not compile)")
                delimiter = None
        if delimiter and re.fullmatch(r"[gimsuy]*", delimiter.group(2)):
            # Emitted as a JSON string literal so a crafted pattern can never break out of the generated JS.
            expr += f".regex(new RegExp({json.dumps(delimiter.group(1))}, {json.dumps(delimiter.group(2))}))"
        elif rx and "regex(pattern does not compile)" not in schema["unsupported"]:
            schema["unsupported"].append("regex(non-/-delimited pattern)")
    if schema["nullable"] and not schema["required"]:
        expr += ".nullish()"
    elif schema["nullable"]:
        expr += ".nullable()"
    elif not schema["required"] and not as_item:
        expr += ".optional()"
    return expr


def rules_to_target(rules: dict) -> dict:
    """Group dotted/wildcard rules and emit a zod object expression + review metadata."""
    schemas = {f: build_field_schema(f, d) for f, d in rules.items() if isinstance(f, str)}
    top = {f: s for f, s in schemas.items() if "." not in f}
    lines, refinements, async_checks, unsupported = [], [], [], []
    for field, schema in top.items():
        items = schemas.get(f"{field}.*")
        nested = {k[len(field) + 1:]: v for k, v in schemas.items() if k.startswith(field + ".") and k != f"{field}.*"}
        if nested and not items:
            sub = ",".join(f"{json.dumps(k)}: {_zod_field(v, None)}" for k, v in nested.items() if "." not in k)
            expr = f"z.object({{{sub}}})" + ("" if schema["required"] else ".optional()")
        else:
            expr = _zod_field(schema, items)
        lines.append(f"  {json.dumps(field)}: {expr},")
        if schema["constraints"].get("confirmed"):
            lines.append(f'  "{field}_confirmation": z.string(),')
            refinements.append({"field": field, "rule": "confirmed"})
        async_checks += [{"field": field, **chk} for chk in schema["async_checks"]]
        unsupported += [{"field": field, "rule": u} for u in schema["unsupported"]]
        unsupported += [{"field": field, "rule": c["rule"], "arguments": c["arguments"], "reason": "conditional requirement"} for c in schema["conditional"]]
    for field, schema in schemas.items():
        if "." in field and not field.endswith(".*"):
            continue
        if field.endswith(".*") and field[:-2] not in top:
            unsupported.append({"field": field, "rule": "wildcard without parent rule"})
    return {"zod_object": "z.object({\n" + "\n".join(lines) + "\n})", "fields": list(schemas.values()),
            "refinements": refinements, "async_checks": async_checks, "unsupported": unsupported,
            "status": "MAPPED" if not unsupported else "REVIEW_REQUIRED"}


def _array_arg(args_text: str, which: int = 0):
    parts = split_top_level(args_text)
    return parse_value(parts[which]) if len(parts) > which else None


def extract_validation(root: Path, graph: dict, contract: dict, body_lookup) -> dict:
    sources = []
    for p in contract["parameters"]:
        if p["kind"] != "form_request":
            continue
        node = next((n for n in graph["nodes"] if short_name(n["id"]) == short_name(p["type"]) and n["role"] == "form_request"), None)
        source = safe_read(root, node["file"]) if node else None
        if not source:
            sources.append({"source": "form_request", "class": p["type"], "status": "FORM_REQUEST_NOT_FOUND", "rules": None})
            continue
        text = mask_comments(source)
        rules_m = next((m for m in find_methods(text) if m["name"] == "rules"), None)
        expr = None
        if rules_m:
            r = re.search(r"\breturn\b\s*", rules_m["body"])
            expr = rules_m["body"][r.end():_statement_end(rules_m["body"], r.end())] if r else None
        parsed = parse_value(expr) if expr else None
        messages_m = next((m for m in find_methods(text) if m["name"] == "messages"), None)
        sources.append({"source": "form_request", "class": node["id"], "source_path": node["file"],
                        "rules": parsed if isinstance(parsed, dict) else None,
                        "custom_messages": bool(messages_m), "status": "EXTRACTED" if isinstance(parsed, dict) else "RULES_NOT_LITERAL"})
    body = body_lookup(contract)
    if body:
        for m in re.finditer(r"->\s*validate(?:WithBag)?\s*\(", body):
            close = match_delim(body, m.end() - 1)
            parsed = _array_arg(body[m.end():close], 0) if close else None
            sources.append({"source": "inline_validate", "rules": parsed if isinstance(parsed, dict) else None,
                            "status": "EXTRACTED" if isinstance(parsed, dict) else "RULES_NOT_LITERAL"})
        for m in re.finditer(r"Validator\s*::\s*make\s*\(", body):
            close = match_delim(body, m.end() - 1)
            parsed = _array_arg(body[m.end():close], 1) if close else None
            sources.append({"source": "validator_make", "rules": parsed if isinstance(parsed, dict) else None,
                            "status": "EXTRACTED" if isinstance(parsed, dict) else "RULES_NOT_LITERAL"})
    for s in sources:
        s["target"] = rules_to_target(s["rules"]) if s.get("rules") else None
    return {"sources": sources, "validated": bool(sources)}


# ------------------------------------------------------------------------ responses
def _status_of(expr: str) -> int | None:
    m = re.search(r"(?:,\s*|setStatusCode\s*\(\s*|noContent\s*\(\s*|status\s*\(\s*)(\d{3})\s*\)?\s*(?:\)|,|$)", expr)
    return int(m.group(1)) if m else None


def _shape(args_text: str) -> dict:
    parts = split_top_level(args_text)
    if not parts:
        return {"kind": "empty"}
    data = parse_value(parts[0])
    if isinstance(data, dict):
        return {"kind": "object", "keys": {str(k): ("literal" if not isinstance(v, Raw) else "expression") for k, v in data.items()},
                "expressions": {str(k): v.text[:120] for k, v in data.items() if isinstance(v, Raw)}}
    if isinstance(data, list):
        return {"kind": "list"}
    return {"kind": "expression", "expression": str(data)[:160]}


def analyse_resources(root: Path, graph: dict) -> dict:
    resources = {}
    for node in graph["nodes"]:
        if node["role"] != "resource" or node["kind"] != "class":
            continue
        source = safe_read(root, node["file"])
        text = mask_comments(source or "")
        method = next((m for m in find_methods(text) if m["name"] == "toArray"), None)
        fields, wrapping_disabled = [], "withoutWrapping" in text
        if method:
            r = re.search(r"\breturn\b\s*", method["body"])
            parsed = parse_value(method["body"][r.end():_statement_end(method["body"], r.end())]) if r else None
            if isinstance(parsed, dict):
                for key, value in parsed.items():
                    expr = value.text if isinstance(value, Raw) else repr(value)
                    attr = re.fullmatch(r"\$this\s*->\s*(\w+)", expr)
                    rel = re.fullmatch(r"\$this\s*->\s*(\w+)\s*->\s*(\w+)", expr)
                    nested = re.search(rf"new\s+({IDENT})Resource|({IDENT})Resource\s*::\s*(?:make|collection)", expr)
                    fields.append({"name": str(key), "kind": "attribute" if attr else "relation_attribute" if rel else
                                   "nested_resource" if nested else "conditional" if "when" in expr else "expression",
                                   "source": attr.group(1) if attr else f"{rel.group(1)}.{rel.group(2)}" if rel else expr[:120]})
        resources[short_name(node["id"])] = {"id": node["id"], "source_path": node["file"], "fields": fields,
                                              "wrapped_in_data": not wrapping_disabled,
                                              "status": "EXTRACTED" if fields else "TOARRAY_NOT_LITERAL"}
    return resources


def closure_return_expression(inline_source: str) -> str:
    """Return the expression a simple inline route closure returns."""
    arrow = re.search(r"\bfn\s*\([^)]*\)\s*=>\s*(.*)$", inline_source, re.S)
    if arrow:
        return arrow.group(1).strip().rstrip(";")
    brace = inline_source.find("{")
    body = inline_source[brace + 1:inline_source.rfind("}")] if brace != -1 else ""
    m = re.search(r"\breturn\b\s*", body)
    return body[m.end():_statement_end(body, m.end())].strip() if m else ""


def classify_return(expr: str, ctx: dict) -> dict:
    e = expr.strip()
    status = _status_of(e)
    base = {"expression": e[:300]}
    m = re.search(rf"\b({IDENT})Resource\s*::\s*collection\s*\(\s*\$(\w+)", e)
    if m:
        res = ctx["resources"].get(m.group(1) + "Resource")
        paged = ctx["paginated_vars"].get(m.group(2), False)
        return {**base, "type": "resource_collection", "status": status or 200, "resource": m.group(1) + "Resource",
                "envelope": ["data", "links", "meta"] if paged else ["data"], "paginated": paged,
                "fields": [f["name"] for f in res["fields"]] if res else None}
    m = re.search(rf"new\s+({IDENT})Resource\s*\(", e)
    if m:
        res = ctx["resources"].get(m.group(1) + "Resource")
        return {**base, "type": "resource", "status": status or 200, "resource": m.group(1) + "Resource",
                "envelope": ["data"] if (res is None or res["wrapped_in_data"]) else [], "fields": [f["name"] for f in res["fields"]] if res else None}
    if re.search(r"response\s*\(\s*\)\s*->\s*noContent", e):
        return {**base, "type": "no_content", "status": status or 204}
    if re.search(r"response\s*\(\s*\)\s*->\s*json\s*\(", e):
        open_pos = e.find("(", e.find("json"))
        close = match_delim(e, open_pos)
        shape = _shape(e[open_pos + 1:close]) if close else {"kind": "unknown"}
        models = {}
        for key, expr in shape.get("expressions", {}).items():
            var = re.fullmatch(r"\$(\w+)", expr)
            if var and var.group(1) in ctx["variable_models"]:
                models[key] = ctx["variable_models"][var.group(1)]
        direct = re.fullmatch(r"\$(\w+)", shape.get("expression", ""))
        if direct and direct.group(1) in ctx["variable_models"]:
            models["$"] = ctx["variable_models"][direct.group(1)]
        return {**base, "type": "json", "status": status or 200, "shape": shape, "serialised_models": models}
    if re.match(r"redirect\s*\(|back\s*\(|to_route\s*\(", e):
        return {**base, "type": "redirect", "status": status or 302, "web_only": True}
    if re.match(r"view\s*\(", e):
        return {**base, "type": "view", "status": 200, "web_only": True}
    var = re.fullmatch(r"\$(\w+)", e)
    if var:
        model = ctx["variable_models"].get(var.group(1))
        return {**base, "type": "implicit_json", "status": 200, "serialised_models": {"$": model} if model else {}}
    return {**base, "type": "unknown", "status": status}


def build_validation_response_analysis(root: str | Path, graph: dict | None = None, contracts: dict | None = None,
                                       routes: dict | None = None) -> dict:
    root = Path(root).resolve(strict=True)
    graph = graph or build_dependency_graph(root)
    contracts = contracts or extract_behavioural_contracts(root, graph)
    callables = {c["id"]: c for c in contracts["callable_contracts"]}
    routes = routes or build_routes_intelligence(root, graph, set(callables))
    models = {m["id"]: m for m in contracts["model_contracts"]}
    related = {(m["id"], r["name"]): next((i for i in models if i.endswith("\\" + (r["related"] or "?"))), None)
               for m in models.values() for r in m["relationships"]}
    resources = analyse_resources(root, graph)
    body_cache: dict[str, str | None] = {}

    def body_lookup(contract: dict) -> str | None:
        key = contract["id"]
        if key not in body_cache:
            source = safe_read(root, contract["source_path"])
            body = None
            if source:
                text = mask_comments(source)
                body = next((m["body"] for m in find_methods(text) if m["name"] == contract["method"] and m["line"] == contract["source_line"]), None)
            body_cache[key] = body
        return body_cache[key]

    endpoints = []
    for route in routes["routes"]:
        contract = callables.get(route.get("handler_contract_id") or "")
        entry = {"route_id": route["id"], "method": route["method"], "uri": route["uri"], "validation": {"sources": [], "validated": False},
                 "responses": [], "error_contracts": [], "review_flags": []}
        if contract is None:
            entry["review_flags"].append("NO_HANDLER_CONTRACT")
            h = route["handler"]
            if h["type"] == "closure":
                entry["responses"] = [classify_return(closure_return_expression(h["inline_source"]),
                                                      {"resources": resources, "paginated_vars": {}, "variable_models": {}})]
            endpoints.append(entry); continue
        entry["validation"] = extract_validation(root, graph, contract, body_lookup)
        variable_models, paginated = {}, {}
        for p in contract["parameters"]:
            if p["kind"] == "route_model":
                variable_models[p["name"]] = p["model"]
        for op in contract["model_operations"]:
            target = op["model"]
            if op["relation"]:
                target = related.get((op["model"], op["relation"])) or target
            if op["assigned_to"]:
                variable_models[op["assigned_to"]] = target
                paginated[op["assigned_to"]] = op["operation"].lower() in {"paginate", "simplepaginate"}
        ctx = {"resources": resources, "paginated_vars": paginated, "variable_models": variable_models}
        entry["responses"] = [dict(classify_return(r["expression"], ctx), line=r["line"]) for r in contract["returns"]]
        for response in entry["responses"]:
            for key, model_id in response.get("serialised_models", {}).items():
                model = models.get(model_id)
                if model and model["hidden"]:
                    response.setdefault("hidden_fields_removed", {})[key] = model["hidden"]
            if response["type"] in {"implicit_json", "json"} and response.get("serialised_models"):
                response["implicit_serialisation_note"] = "Eloquent serialisation omits $hidden attributes and applies casts; target must replicate."
            if response["type"] == "unknown":
                entry["review_flags"].append("UNCLASSIFIED_RETURN")
            if response.get("web_only"):
                entry["review_flags"].append("WEB_RESPONSE_IN_API_CONTEXT")
        errors = []
        if entry["validation"]["validated"]:
            errors.append(422)
        if any(m["category"] == "authentication" for m in route["middleware"]):
            errors.append(401)
        if any(m["category"] in {"authorization"} or (m["behaviour"] and m["behaviour"]["denies_with_status"]) for m in route["middleware"]) or contract["authorization_calls"]:
            errors.append(403)
        if contract["route_model_bindings"] or any(o["operation"].lower().endswith("orfail") for o in contract["model_operations"]):
            errors.append(404)
        if any(m["category"] == "rate_limit" for m in route["middleware"]):
            errors.append(429)
        errors += [e["status"] for e in contract["exits"] if e["kind"] == "abort" and e["status"] not in errors]
        entry["error_contracts"] = [{"status": s, **FRAMEWORK_ERRORS.get(s, {"body": {"message": "string"}, "when": "explicit abort()"}),
                                     "assumed_framework_default": s in FRAMEWORK_ERRORS} for s in dict.fromkeys(errors)]
        if entry["validation"]["validated"] and any(s["status"] == "REVIEW_REQUIRED" for src in entry["validation"]["sources"] if src.get("target") for s in [src["target"]]):
            entry["review_flags"].append("VALIDATION_RULES_NEED_REVIEW")
        if any(s.get("status") in {"RULES_NOT_LITERAL", "FORM_REQUEST_NOT_FOUND"} for s in entry["validation"]["sources"]):
            entry["review_flags"].append("VALIDATION_RULES_NOT_EXTRACTED")
        endpoints.append(entry)
    return {
        "engine": "validation_response", "engine_version": ENGINE_VERSION, "graph_fingerprint": graph["fingerprint"],
        "resources": resources, "endpoints": endpoints, "framework_error_defaults": {str(k): v for k, v in FRAMEWORK_ERRORS.items()},
        "summary": {"endpoints": len(endpoints), "validated_endpoints": sum(e["validation"]["validated"] for e in endpoints),
                    "endpoints_needing_review": sum(bool(e["review_flags"]) for e in endpoints),
                    "resource_classes": len(resources)},
        "policy": "Validation and response contracts are static; custom Rule objects, conditional rules and dynamic responses are never guessed.",
    }
