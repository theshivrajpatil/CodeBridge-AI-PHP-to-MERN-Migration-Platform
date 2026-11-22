"""V5.21 — Authentication and Authorization Intelligence.

Produces, per endpoint, an evidence-backed access contract:

* authentication requirement (REQUIRED / PUBLIC / GUEST_ONLY / PUBLIC_BUT_READS_USER),
* authorization controls (``can:`` middleware, role middleware, ``authorize()``
  calls resolved to Policy/Gate rules, FormRequest ``authorize()``, inline 401/403 guards),
* security risk flags (possible IDOR, unauthenticated state change, credential
  endpoints without rate limiting),
* a target mapping consumed by the MERN generator.

Rules are summarised into a small normalised vocabulary (owner / role / any_of /
all_of / constant); anything else stays ``unrecognised`` and blocks automatic
translation.
"""
from __future__ import annotations

from pathlib import Path
import re

from app.contract_extraction import extract_behavioural_contracts, snake
from app.dependency_graph import build_dependency_graph
from app.php_source import (as_strings, find_classes, find_methods, mask_comments, match_delim, parse_value,
                            safe_read, short_name, split_top_level, unquote)
from app.routes_intelligence import build_routes_intelligence

ENGINE_VERSION = "5.21.0"
AUTH_PACKAGES = {"laravel/sanctum": "token_sanctum", "laravel/passport": "oauth2_passport", "tymon/jwt-auth": "jwt",
                 "laravel/breeze": "session_breeze", "laravel/jetstream": "session_jetstream", "laravel/fortify": "session_fortify",
                 "spatie/laravel-permission": "roles_permissions_spatie", "laravel/socialite": "social_login"}
STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}


def _strip_parens(text: str) -> str:
    text = text.strip()
    while text.startswith("(") and match_delim(text, 0) == len(text) - 1:
        text = text[1:-1].strip()
    return text


def summarize_rule(expression: str, depth: int = 0) -> dict:
    """Normalise a policy/gate return expression into a rule tree."""
    expr = _strip_parens(expression.strip().rstrip(";"))
    if depth > 6 or not expr:
        return {"kind": "unrecognised", "expression": expr[:200]}
    for operator, kind in (("||", "any_of"), ("&&", "all_of")):
        parts = split_top_level(expr, operator)
        if len(parts) > 1:
            return {"kind": kind, "rules": [summarize_rule(p, depth + 1) for p in parts]}
    low = expr.lower()
    if low in {"true", "false"}:
        return {"kind": "constant", "value": low == "true"}
    m = re.fullmatch(r"\$(\w+)\s*->\s*(\w+)\s*(===|==)\s*\$(\w+)\s*->\s*(\w+)", expr)
    if m:
        return {"kind": "owner", "actor_field": m.group(2), "resource_field": m.group(5), "resource_variable": m.group(4)}
    m = re.fullmatch(r"\$(\w+)\s*->\s*(role|type|is_admin|isAdmin|level)\s*(===|==)\s*('(?:[^'\\]|\\.)*'|\"[^\"]*\")", expr)
    if m:
        return {"kind": "role_equals", "field": m.group(2), "value": unquote(m.group(4))}
    m = re.fullmatch(r"\$(\w+)\s*->\s*(?:hasRole|can|hasPermissionTo)\s*\(\s*('(?:[^'\\]|\\.)*')\s*\)", expr)
    if m:
        return {"kind": "permission_or_role", "value": unquote(m.group(2)), "requires_package": "spatie/laravel-permission"}
    m = re.fullmatch(r"\$(\w+)\s*->\s*(\w+)\s*(?:!==|!=)\s*null|\$this\s*->\s*user\s*\(\s*\)\s*(?:!==|!=)\s*null", expr)
    if m:
        return {"kind": "authenticated_only"}
    m = re.fullmatch(r"\$(\w+)\s*->\s*(\w+)", expr)
    if m:
        return {"kind": "boolean_flag", "field": m.group(2)}
    return {"kind": "unrecognised", "expression": expr[:200]}


def _first_return(body: str) -> str | None:
    m = re.search(r"\breturn\b\s*", body)
    if not m:
        return None
    from app.contract_extraction import _statement_end
    return body[m.end():_statement_end(body, m.end())]


def _closure_rule(args_text: str) -> tuple[dict, bool]:
    arrow = re.search(r"\bfn\s*\([^)]*\)\s*=>\s*(.*)$", args_text, re.S)
    if arrow:
        return summarize_rule(arrow.group(1)), True
    brace = args_text.find("{")
    end = match_delim(args_text, brace) if brace != -1 else None
    if end is not None:
        expr = _first_return(args_text[brace + 1:end])
        return (summarize_rule(expr) if expr else {"kind": "unrecognised", "expression": ""}), True
    return {"kind": "unrecognised", "expression": args_text[:120]}, False


def _discover_auth_config(root: Path) -> dict:
    source = safe_read(root, "config/auth.php")
    result = {"default_guard": None, "guards": {}, "providers": {}, "config_present": source is not None}
    if not source:
        return result
    text = mask_comments(source)
    m = re.search(r"return\s*", text)
    config = parse_value(text[m.end():text.rfind(";")]) if m else None
    if isinstance(config, dict):
        defaults = config.get("defaults")
        result["default_guard"] = defaults.get("guard") if isinstance(defaults, dict) and isinstance(defaults.get("guard"), str) else None
        for key in ("guards", "providers"):
            section = config.get(key)
            if isinstance(section, dict):
                result[key] = {k: {ik: (iv["$class"] if isinstance(iv, dict) and "$class" in iv else iv if isinstance(iv, str) else str(iv))
                                   for ik, iv in v.items()} for k, v in section.items() if isinstance(v, dict)}
    return result


def _gates_and_policies(root: Path, graph: dict) -> tuple[list, list]:
    gates, policies = [], []
    registrations: dict[str, str] = {}
    for node in graph["nodes"]:
        if node["role"] != "provider":
            continue
        source = safe_read(root, node["file"])
        if not source:
            continue
        text = mask_comments(source)
        for m in re.finditer(r"Gate\s*::\s*define\s*\(", text):
            close = match_delim(text, m.end() - 1)
            args = split_top_level(text[m.end():close]) if close else []
            if not args:
                continue
            ability = unquote(args[0])
            rule, parsed = _closure_rule(text[m.end() + len(args[0]) + 1:close]) if len(args) > 1 else ({"kind": "unrecognised"}, False)
            gates.append({"ability": ability, "rule": rule, "source_path": node["file"], "line": source.count("\n", 0, m.start()) + 1,
                          "status": "SUMMARISED" if parsed and rule["kind"] != "unrecognised" else "NEEDS_REVIEW"})
        for m in re.finditer(r"Gate\s*::\s*policy\s*\(([^;]*?)\)\s*;", text):
            args = [parse_value(a) for a in split_top_level(m.group(1))]
            if len(args) == 2 and all(isinstance(a, dict) for a in args):
                registrations[short_name(args[0]["$class"])] = short_name(args[1]["$class"])
    models = {short_name(n["id"]): n["id"] for n in graph["nodes"] if n["role"] == "model"}
    for node in graph["nodes"]:
        if node["role"] != "policy" or node["kind"] != "class":
            continue
        source = safe_read(root, node["file"])
        cls = next(iter(find_classes(source or "")), None)
        if not cls:
            continue
        text = mask_comments(source)
        policy_name = short_name(node["id"])
        guessed = policy_name[:-6] if policy_name.endswith("Policy") else None
        model = next((m for m, p in registrations.items() if p == policy_name), guessed if guessed in models else None)
        abilities = {}
        for method in find_methods(text, cls["body_start"], cls["body_end"]):
            if method["name"].startswith("__") or method["visibility"] != "public":
                continue
            expr = _first_return(method["body"])
            abilities[method["name"]] = {"rule": summarize_rule(expr) if expr else {"kind": "unrecognised", "expression": ""},
                                         "line": method["line"]}
        policies.append({"id": node["id"], "model": model, "model_source": "Gate::policy registration" if model in registrations else
                         "Laravel naming convention (auto-discovery)" if model else "UNRESOLVED", "source_path": node["file"], "abilities": abilities})
    return gates, policies


def _form_request_authorize(root: Path, graph: dict, class_short: str) -> dict | None:
    node = next((n for n in graph["nodes"] if short_name(n["id"]) == class_short and n["role"] == "form_request"), None)
    source = safe_read(root, node["file"]) if node else None
    if not source:
        return None
    method = next((m for m in find_methods(mask_comments(source)) if m["name"] == "authorize"), None)
    expr = _first_return(method["body"]) if method else None
    return {"class": node["id"], "rule": summarize_rule(expr) if expr else {"kind": "unrecognised", "expression": ""}}


def _rule_is_trivial_allow(rule: dict) -> bool:
    return rule.get("kind") == "constant" and rule.get("value") is True


def build_auth_intelligence(root: str | Path, graph: dict | None = None, contracts: dict | None = None,
                            routes: dict | None = None) -> dict:
    root = Path(root).resolve(strict=True)
    graph = graph or build_dependency_graph(root)
    contracts = contracts or extract_behavioural_contracts(root, graph)
    callables = {c["id"]: c for c in contracts["callable_contracts"]}
    routes = routes or build_routes_intelligence(root, graph, set(callables))
    config = _discover_auth_config(root)
    gates, policies = _gates_and_policies(root, graph)
    policy_by_model = {p["model"]: p for p in policies if p["model"]}
    packages = [{"package": p["package"], "mechanism": AUTH_PACKAGES[p["package"]]}
                for p in graph["composer"]["packages"] if p["package"] in AUTH_PACKAGES]
    mechanisms = sorted({p["mechanism"] for p in packages} | {f"guard_driver:{g.get('driver')}" for g in config["guards"].values() if g.get("driver")})
    models = {m["id"]: m for m in contracts["model_contracts"]}
    roles = sorted({v for r in [g["rule"] for g in gates] + [a["rule"] for p in policies for a in p["abilities"].values()]
                    for v in _collect(r, "role_equals")} |
                   {a for rt in routes["routes"] for mw in rt["middleware"] if mw["category"] == "custom" and mw["behaviour"] and
                    mw["behaviour"]["checks_role_or_permission"] for a in mw["arguments"]})
    endpoints = []
    for route in routes["routes"]:
        contract = callables.get(route.get("handler_contract_id") or "")
        mws = route["middleware"]
        auth_mw = [m for m in mws if m["category"] == "authentication"]
        guest = [m for m in mws if m["category"] == "guest"]
        reads_user = bool(contract and contract["inputs"]["authenticated_user_read"])
        controls: list[dict] = []
        for m in mws:
            if m["category"] == "authorization" and m["name"] == "can":
                ability = m["arguments"][0] if m["arguments"] else None
                subject = m["arguments"][1] if len(m["arguments"]) > 1 else None
                gate = next((g for g in gates if g["ability"] == ability), None)
                pol = policy_by_model.get(short_name(subject)) if subject else None
                controls.append({"type": "can_middleware", "ability": ability, "subject": subject,
                                 "rule": (gate["rule"] if gate else pol["abilities"].get(ability, {}).get("rule") if pol else None),
                                 "status": "RESOLVED" if gate or (pol and ability in pol["abilities"]) else "RULE_NOT_FOUND"})
            elif m["category"] == "custom" and m["behaviour"] and (m["behaviour"]["checks_role_or_permission"] or m["behaviour"]["denies_with_status"]):
                controls.append({"type": "middleware_check", "middleware": m["name"], "arguments": m["arguments"],
                                 "roles": m["arguments"] if m["behaviour"]["checks_role_or_permission"] else [],
                                 "denies_with_status": m["behaviour"]["denies_with_status"], "status": "SUMMARISED_FROM_MIDDLEWARE_BODY"})
        if contract:
            for call in contract["authorization_calls"]:
                subject_var = call["subject"].lstrip("$").split(",")[0].strip()
                param = next((p for p in contract["parameters"] if p["name"] == subject_var), None)
                model = short_name(param["model"]) if param and param.get("model") else None
                pol = policy_by_model.get(model) if model else None
                gate = next((g for g in gates if g["ability"] == call["ability"]), None)
                rule = (pol["abilities"].get(call["ability"], {}).get("rule") if pol else None) or (gate["rule"] if gate else None)
                controls.append({"type": "authorize_call", "ability": call["ability"], "subject_model": model, "rule": rule,
                                 "policy": pol["id"] if pol else None, "status": "RESOLVED" if rule else "RULE_NOT_FOUND"})
            for g in contract["guard_clauses"]:
                if g["status"] in {401, 403} or (g["exit"] == "abort" and g["status"] in {401, 403}):
                    controls.append({"type": "inline_guard", "condition": g["condition"], "status_code": g["status"], "line": g["line"],
                                     "rule": summarize_rule(g["condition"]) , "status": "SOURCE_EVIDENCE"})
            for p in contract["parameters"]:
                if p["kind"] == "form_request":
                    fr = _form_request_authorize(root, graph, short_name(p["type"]))
                    if fr and not _rule_is_trivial_allow(fr["rule"]):
                        controls.append({"type": "form_request_authorize", "form_request": fr["class"], "rule": fr["rule"], "status": "SUMMARISED"})
        credential = bool(contract and ({"password_check", "session_login"} & set(contract["side_effects"])))
        issues_token = bool(contract and "token_issue" in contract["side_effects"])
        authentication = ("REQUIRED" if auth_mw else "GUEST_ONLY" if guest else
                          "PUBLIC_BUT_READS_USER" if reads_user and not (credential or issues_token) else "PUBLIC")
        write_ops = bool(contract and any(o["kind"] in {"write", "delete"} for o in contract["model_operations"]))
        bound = bool(contract and contract["route_model_bindings"])
        flags = []
        if route["method"] in STATE_CHANGING and authentication == "PUBLIC" and not (credential or issues_token):
            flags.append({"flag": "UNAUTHENTICATED_STATE_CHANGE", "severity": "HIGH"})
        if bound and write_ops and not any(c["type"] in {"authorize_call", "can_middleware", "inline_guard", "middleware_check"} for c in controls) and authentication != "PUBLIC":
            flags.append({"flag": "BOUND_MODEL_WITHOUT_AUTHORIZATION", "severity": "HIGH",
                          "detail": "Authenticated write on a route-bound model with no ownership/policy evidence (possible IDOR)."})
        if (credential or issues_token) and not any(m["category"] == "rate_limit" for m in mws):
            flags.append({"flag": "CREDENTIAL_ENDPOINT_WITHOUT_RATE_LIMIT", "severity": "MEDIUM"})
        if any(c.get("status") in {"RULE_NOT_FOUND"} for c in controls):
            flags.append({"flag": "AUTHORIZATION_RULE_UNRESOLVED", "severity": "MEDIUM"})
        unresolved_rules = any(c.get("rule", {}) and c["rule"].get("kind") == "unrecognised" for c in controls if c.get("rule") and c["type"] != "inline_guard")
        endpoints.append({
            "route_id": route["id"], "method": route["method"], "uri": route["uri"],
            "authentication": authentication, "guards": sorted({m["guard"] or config["default_guard"] or "default" for m in auth_mw}),
            "authorization_controls": controls, "risk_flags": flags,
            "target_mapping": {"authenticate": "jwt" if authentication == "REQUIRED" else "none",
                               "authorize": [c for c in controls if c["type"] != "inline_guard"],
                               "requires_manual_review": unresolved_rules or any(f["flag"] == "AUTHORIZATION_RULE_UNRESOLVED" for f in flags)},
            "status": "STATIC_EVIDENCE_REQUIRES_REVIEW"})
    return {
        "engine": "auth_intelligence", "engine_version": ENGINE_VERSION, "graph_fingerprint": graph["fingerprint"],
        "authentication_system": {**config, "packages": packages, "mechanisms": mechanisms,
                                  "authenticatable_models": [m["id"] for m in models.values() if m["authenticatable"]],
                                  "password_hashing_observed": any("password_hashing" in c["side_effects"] for c in contracts["callable_contracts"]),
                                  "token_issue_observed": any("token_issue" in c["side_effects"] for c in contracts["callable_contracts"])},
        "gates": gates, "policies": policies, "roles_observed": roles, "endpoints": endpoints,
        "summary": {"endpoints": len(endpoints),
                    "authentication_required": sum(e["authentication"] == "REQUIRED" for e in endpoints),
                    "public": sum(e["authentication"].startswith("PUBLIC") for e in endpoints),
                    "high_severity_flags": sum(f["severity"] == "HIGH" for e in endpoints for f in e["risk_flags"]),
                    "flag_count": sum(len(e["risk_flags"]) for e in endpoints)},
        "policy": "Access contracts summarise static evidence. Missing evidence never implies absence of runtime enforcement.",
    }


def _collect(rule: dict, kind: str) -> list[str]:
    if rule.get("kind") == kind:
        return [rule["value"]]
    return [v for sub in rule.get("rules", []) for v in _collect(sub, kind)]
