"""V5.23 — Behavioural Parity Engine.

Compares behaviour extracted from a PHP/Laravel source (V5.18–V5.22 outputs) with a migrated
Express/Mongoose target analysed by :mod:`app.target_analysis`, optionally enriched with real
runtime differential results from :mod:`app.differential_testing`.

Design rules
* Deterministic, evidence-linked comparison of values, operators, statuses, keys and rules — never text similarity.
* Unknown or unresolvable behaviour is UNVERIFIED, never "equivalent".
* VERIFIED_EQUIVALENT requires every applicable check to MATCH and no unresolved evidence; with static
  evidence only it is labelled ``STATIC_ONLY`` and still requires human review. Runtime equivalence is only
  claimed when differential tests really ran and passed.
* Reports never approve anything: ``auto_approval`` and ``generation_authorized`` are always false.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from app.intelligence_pipeline import run_stage
from app.php_source import find_methods, mask_comments, safe_read, short_name
from app.php_source import Raw
from app.target_analysis import analyse_body, analyze_express_project, extract_rules

ENGINE_VERSION = "5.23.0"
STATUSES = ("VERIFIED_EQUIVALENT", "VERIFIED_MISMATCH", "PARTIALLY_VERIFIED", "NOT_IMPLEMENTED", "UNVERIFIED", "BLOCKED")
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
IGNORED_EFFECTS = {"session_login", "session_state", "logging", "raw_sql"}
EFFECT_SEVERITY = {"password_hashing": "high", "password_check": "high", "token_issue": "high", "token_revoke": "medium"}
EXTRA_ROUTE_ALLOWLIST = {"/healthz", "/health"}
RECOMMENDATIONS = {
    "authentication": "Add the equivalent authentication middleware to this route (or remove it if the source route is public).",
    "authorization": "Implement the source authorization rule (role/ownership/policy) with deny-by-default semantics.",
    "validation": "Align the target schema with the source rules (required, type, min/max, enum, format).",
    "status": "Return the same HTTP status codes as the source for each outcome.",
    "response": "Match the source response envelope and field names; never expose attributes the source hides.",
    "database": "Implement the missing database operation with equivalent semantics.",
    "side_effect": "Implement the missing side effect (hashing, token issuance, notifications) as in the source.",
    "business_rule": "Reconcile the differing constant/condition with the source; confirm intended behaviour with the owner.",
    "rate_limit": "Apply the same rate limit (attempts and window) as the source throttle.",
    "runtime": "Investigate the differential-test difference between the PHP and MERN responses.",
}
_SECRET = re.compile(r"(?i)((?:secret|password|passwd|token|api[_-]?key|authorization)['\"]?\s*[:=]\s*['\"])[^'\"\s]{4,}(['\"])")
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{8,}")


def redact(text: str | None, limit: int = 240) -> str | None:
    if text is None:
        return None
    return _BEARER.sub("Bearer [REDACTED]", _SECRET.sub(r"\1[REDACTED]\2", text.strip()))[:limit]


def norm_path(path: str) -> str:
    return re.sub(r"\{\w+\??\}|:\w+", ":p", path.rstrip("/") or "/")


# ------------------------------------------------------------ source contracts
def resolve_target_root(target: str, source_root: str) -> Path:
    """Validate a user-supplied target path: real directory, no symlink root, not overlapping the source."""
    p = Path(target)
    if not str(target).strip() or "\x00" in str(target):
        raise ValueError("target path is empty or invalid")
    if p.is_symlink():
        raise ValueError("target path must not be a symlink")
    resolved = p.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError("target path is not a directory")
    src = Path(source_root).resolve(strict=True)
    if resolved == src or src in resolved.parents or resolved in src.parents:
        raise ValueError("target must be a separate directory that does not overlap the source repository")
    return resolved


def _php_body(root: str, contract: dict) -> str | None:
    source = safe_read(root, contract["source_path"])
    if not source:
        return None
    return next((m["body"] for m in find_methods(mask_comments(source)) if m["name"] == contract["method"]
                 and m["line"] == contract["source_line"]), None)


def build_source_contracts(root: str | Path, exclude_web: bool = True) -> dict:
    """Assemble route-level parity contracts from the cached V5.19–V5.22 stage outputs."""
    root = str(Path(root).resolve(strict=True))
    graph = run_stage(root, "dependency-graph")
    contracts_report = run_stage(root, "contracts")
    routes_report = run_stage(root, "routes")
    auth = run_stage(root, "auth")
    vr = run_stage(root, "validation-response")
    callables = {c["id"]: c for c in contracts_report["callable_contracts"]}
    models = {m["id"]: m for m in contracts_report["model_contracts"]}
    auth_by, vr_by = {e["route_id"]: e for e in auth["endpoints"]}, {e["route_id"]: e for e in vr["endpoints"]}
    out, excluded = [], []
    for r in routes_report["routes"]:
        a, v = auth_by[r["id"]], vr_by[r["id"]]
        c = callables.get(r.get("handler_contract_id") or "")
        web = r["handler"]["type"] in {"view", "redirect", "fallback", "permanentredirect"} or any(x.get("web_only") for x in v["responses"])
        if web and exclude_web:
            excluded.append({"contract_id": r["id"], "method": r["method"], "uri": r["uri"], "reason": "server-rendered web response; no API contract"})
            continue
        fields, async_checks, rule_status = [], [], []
        for src in v["validation"]["sources"]:
            rule_status.append(src["status"])
            if src.get("target"):
                fields += [f for f in src["target"]["fields"] if "." not in f["field"]]
                async_checks += src["target"]["async_checks"]
        throttle = next((m for m in r["middleware"] if m["category"] == "rate_limit"), None)
        incomplete = []
        if r["handler"]["type"] in {"controller", "invokable"} and c is None:
            incomplete.append("source handler contract not found")
        incomplete += [f"source flag {f}" for f in v["review_flags"] if f in {"UNCLASSIFIED_RETURN", "VALIDATION_RULES_NOT_EXTRACTED"}]
        incomplete += [f"source middleware '{m['name']}' unresolved" for m in r["middleware"] if m["status"] != "RESOLVED"]
        if a["target_mapping"]["requires_manual_review"]:
            incomplete.append("source authorization rule unresolved")
        body = _php_body(root, c) if c else None
        out.append({
            "contract_id": r["id"], "callable_contract_id": r.get("handler_contract_id"), "method": r["method"], "uri": r["uri"],
            "normalised_path": norm_path(r["uri"]), "source_path": c["source_path"] if c else r["source_path"],
            "source_line": c["source_line"] if c else r["source_line"], "handler": r["handler"],
            "authentication": a["authentication"], "authorization_controls": a["authorization_controls"],
            "validation_fields": fields, "async_checks": async_checks, "responses": v["responses"],
            "error_statuses": sorted({e["status"] for e in v["error_contracts"]}),
            "model_operations": c["model_operations"] if c else [], "bindings": c["route_model_bindings"] if c else [],
            "side_effects": c["side_effects"] if c else [], "guard_clauses": c["guard_clauses"] if c else [],
            "rules": extract_rules(body, php=True) if body else [], "complexity": c["complexity"] if c else None,
            "throttle": ({"max": int(throttle["arguments"][0]), "minutes": int(throttle["arguments"][1])}
                         if throttle and len(throttle["arguments"]) == 2 and all(x.isdigit() for x in throttle["arguments"]) else
                         {"named": throttle["arguments"]} if throttle else None),
            "middleware": [{"name": m["name"], "arguments": m["arguments"], "category": m["category"], "status": m["status"],
                            "role_check": bool(m["behaviour"] and m["behaviour"]["checks_role_or_permission"])} for m in r["middleware"]],
            "incomplete_source_evidence": incomplete, "confidence": c["confidence"] if c else "LOW",
        })
    return {"contracts": out, "excluded": excluded, "models": models, "graph_fingerprint": graph["fingerprint"],
            "stages": ["dependency-graph", "contracts", "routes", "auth", "validation-response"]}


# ------------------------------------------------------------ target facts
def _classify_mw(mw: dict) -> dict:
    name = mw["name"].split(".")[-1].lower()
    args = [a for a in mw["arguments"] if isinstance(a, (str, int, float, dict))]
    body = mw.get("body") or ""
    kind = "other"
    if re.search(r"authenticat|^auth$|protect|requireauth|verifytoken|isauth|ensureauth|passport", name) or re.search(r"jwt\s*\.\s*verify", body):
        kind = "authentication"
    elif re.search(r"role|admin|permission|authorize|^can$|hasrole", name):
        kind = "role"
    elif re.search(r"rate|limit|throttle", name):
        kind = "rate_limit"
    elif re.search(r"validat|schema", name):
        kind = "validation"
    info = {"kind": kind, "name": mw["name"], "resolved": mw["resolved"], "file": mw["file"], "line": mw["line"], "raw": mw["raw"], "body": mw.get("body"), "arguments": mw["arguments"]}
    if kind == "role":
        info["roles"] = [a for a in args if isinstance(a, str)] or sorted({r for rc in analyse_body(body, "", 1)["role_checks"] for r in rc["roles"]})
    if kind == "rate_limit" and args and isinstance(args[0], dict):
        d = args[0]
        mx = d.get("max", d.get("limit"))
        win = d.get("windowMinutes", (d["windowMs"] / 60000 if isinstance(d.get("windowMs"), (int, float)) else None))
        info["limit"] = {"max": mx if isinstance(mx, (int, float)) else None, "minutes": win if isinstance(win, (int, float)) else None}
    if kind == "validation":
        info["schema"] = str(mw["arguments"][0]) if mw["arguments"] else None
    return info


def _target_facts(route: dict, tctx: dict) -> dict:
    handler = route["handler"]
    segments, incomplete = [], []
    if handler is None:
        return {"segments": [], "incomplete": ["handler not resolved"], "mws": [], "analysis": None}
    by_name: dict[str, list[tuple[str, dict]]] = {}
    for key, fn in tctx["functions"].items():
        by_name.setdefault(key.split(":", 1)[1], []).append((fn["file"], fn))
    seen, queue = set(), [(handler["file"], handler["line"], handler["body"], 0)]
    while queue and len(segments) < 8:
        file, line, body, depth = queue.pop(0)
        if (file, line) in seen:
            continue
        seen.add((file, line))
        segments.append({"file": file, "line": line, "body": body})
        if depth >= 2:
            continue
        calls = analyse_body(body, file, line)["calls"]
        for call in calls:
            member = call.split(".")[-1]
            cands = by_name.get(member, [])
            if "." in call:
                owner = call.split(".")[0].lower().replace("service", "").replace("repository", "")
                cands = [c for c in cands if owner and (owner in c[0].lower() or (c[1]["owner"] or "").lower().startswith(owner))]
            if len(cands) == 1 and cands[0][0] != file or (len(cands) == 1 and cands[0][1]["line"] != line):
                f, fn = cands[0]
                queue.append((f, fn["line"], fn["body"], depth + 1))
            elif len(cands) == 0 and call in tctx["imports"].get(file, {}):
                incomplete.append(f"imported function '{call}' not found")
    mws = [_classify_mw(m) for m in route["middleware"]]
    incomplete += [f"middleware '{m['name']}' not resolved" for m in mws if not m["resolved"] and m["kind"] == "other"]
    analyses = [analyse_body(s["body"], s["file"], s["line"]) for s in segments]
    merged = {
        "statuses": sorted({s for a in analyses for s in a["statuses"]}),
        "db": [d for a in analyses for d in a["db_operations"]], "effects": sorted({e for a in analyses for e in a["side_effects"]}),
        "owner_checks": [o for a in analyses for o in a["owner_checks"]], "role_checks": [r for a in analyses for r in a["role_checks"]],
        "rules": [r for a in analyses for r in a["rules"]], "soft_delete": any(a["soft_delete_marker"] for a in analyses),
        "stub": analyses[0]["is_stub"], "responses": analyses[0]["responses"], "inline_validation": analyses[0]["inline_validation"],
        "text": "\n".join(s["body"] for s in segments),
    }
    for m in mws:
        if m["kind"] == "authentication": merged["statuses"] = sorted(set(merged["statuses"]) | {401})
        if m["kind"] == "validation": merged["statuses"] = sorted(set(merged["statuses"]) | {422})
        if m["kind"] == "rate_limit": merged["statuses"] = sorted(set(merged["statuses"]) | {429})
        if m["kind"] == "role": merged["statuses"] = sorted(set(merged["statuses"]) | {403})
        if m.get("body"):
            mb = analyse_body(m["body"], m["file"] or "", m["line"] or 1)
            # model-parameterised middleware (bind(param, Post), unique(User, ...)) reads the model passed as an argument
            if re.search(r"\.\s*(?:findById|findOne|exists|countDocuments)\s*\(", m["body"]):
                for a in m["arguments"]:
                    if isinstance(a, Raw) and re.fullmatch(r"[A-Z]\w*", a.text):
                        merged["db"].append({"model": a.text, "operation": "findById", "kind": "read", "line": m["line"] or 1})
            merged["role_checks"] += mb["role_checks"]
            merged["statuses"] = sorted(set(merged["statuses"]) | set(mb["statuses"]))
    return {"segments": segments, "incomplete": incomplete, "mws": mws, "analysis": merged}


# ------------------------------------------------------------------ checks
def _chk(dim, result, severity, src, tgt, diff, kind=None):
    return {"dimension": dim, "result": result, "severity": severity if result == "MISMATCH" else "info",
            "source_evidence": src, "target_evidence": tgt, "difference": diff,
            "recommendation": RECOMMENDATIONS.get(kind or dim) if result != "MATCH" else None}


def _src_ev(c, what=None):
    return {"file": c["source_path"], "line": c["source_line"], "contract": c["callable_contract_id"] or c["contract_id"], "detail": what}


def _tgt_ev(route, facts, what=None):
    h = route["handler"]
    return {"file": h["file"] if h else route["source_path"], "line": h["line"] if h else route["source_line"],
            "route": f"{route['method']} {route['path']}", "detail": redact(what)}


def _fam(t): return {"integer": "number", "number": "number"}.get(t, t)


def _eff(field, side):
    c = field["constraints"]
    mn = c.get("min")
    if field["type"] == "string" and field["required"]:
        mn = max(mn or 0, 1)
    return mn, c.get("max")


def _mapper_keys(raw: str, tctx: dict):
    """Keys of the object literal returned by a mapper function referenced as ``fn(x)`` or ``.map(fn)``."""
    from app.target_analysis import parse_js
    names = re.findall(r"\.\s*map\s*\(\s*(\w+)\s*\)", raw) or re.findall(r"^\s*(\w+)\s*\(", raw)
    for name in names:
        cands = [f for k, f in tctx["functions"].items() if k.split(":", 1)[1] == name]
        if len(cands) != 1:
            continue
        body = cands[0]["body"]
        m = re.search(r"\breturn\s*\(?\s*\{", body)
        if not m:
            continue
        start = body.find("{", m.start())
        from app.php_source import match_delim
        end = match_delim(body, start)
        obj = parse_js(body[start:end + 1]) if end else None
        if isinstance(obj, dict):
            return {k for k in obj if not k.startswith("...")}
    return None


def _cmp_validation(c, route, facts, tctx, checks):
    src_fields = {f["field"]: f for f in c["validation_fields"]}
    names = [m.get("schema") for m in facts["mws"] if m["kind"] == "validation"] + list(facts["analysis"]["inline_validation"])
    schema = next((tctx["schemas"].get(n.split(".")[-1]) for n in names if n and tctx["schemas"].get(n.split(".")[-1])), None)
    sev = "high"
    if src_fields and not names:
        checks.append(_chk("validation", "MISMATCH", sev, _src_ev(c, f"fields: {sorted(src_fields)}"), _tgt_ev(route, facts, "no validation middleware or inline validation"),
                           "Source validates input; target performs no validation (MISSING_BEHAVIOUR)."))
        return
    if src_fields and not schema:
        checks.append(_chk("validation", "UNVERIFIED", sev, _src_ev(c), _tgt_ev(route, facts, str(names)), "Target validation schema could not be resolved."))
        return
    if not src_fields:
        if schema:
            checks.append(_chk("validation", "MISMATCH", "medium", _src_ev(c, "no validation rules"), _tgt_ev(route, facts, f"schema fields: {sorted(schema['fields'])}"),
                               "Target adds validation that the source does not perform."))
        return
    tf, diffs = schema["fields"], []
    for name, s in src_fields.items():
        t = tf.get(name)
        if t is None:
            diffs.append((f"field '{name}' missing in target schema", "high")); continue
        if bool(s["required"] and not s["sometimes"]) != bool(t["required"]):
            diffs.append((f"field '{name}': source required={bool(s['required'] and not s['sometimes'])}, target required={t['required']}", "high"))
        if s["type"] not in ("any", "file") and t["type"] != "any" and _fam(s["type"]) != _fam(t["type"]):
            diffs.append((f"field '{name}': source type {s['type']}, target type {t['type']}", "high"))
        elif s["type"] == "integer" and t["type"] != "integer":
            diffs.append((f"field '{name}': source requires integer, target accepts non-integers", "medium"))
        if bool(s["nullable"]) != bool(t["nullable"]) and (s["nullable"] or t["nullable"]):
            diffs.append((f"field '{name}': source nullable={bool(s['nullable'])}, target nullable={t['nullable']}", "medium"))
        smn, smx = _eff({**s, "type": s["type"]}, "s"); tmn, tmx = _eff(t, "t")
        if s["type"] in ("string", "number", "integer", "array"):
            if smn != tmn and not (smn in (None, 0) and tmn in (None, 0)):
                diffs.append((f"field '{name}': source min={smn}, target min={tmn}", "high"))
            if smx != tmx:
                diffs.append((f"field '{name}': source max={smx}, target max={tmx}", "high"))
        sin, tin = s["constraints"].get("in"), t["constraints"].get("in")
        if sin and (not tin or sorted(map(str, sin)) != sorted(map(str, tin))):
            diffs.append((f"field '{name}': source allowed values {sin}, target {tin}", "high"))
        if s["constraints"].get("confirmed"):
            has = f"{name}_confirmation" in tf or re.search(rf"{name}_?[cC]onfirm", facts["analysis"]["text"])
            if not has:
                diffs.append((f"field '{name}': source requires '{name}_confirmation' to match; target does not check it", "medium"))
        for flag in ("email", "url", "uuid"):
            if s["constraints"].get(flag) and not t["constraints"].get(flag):
                diffs.append((f"field '{name}': source requires {flag} format, target does not", "high"))
    confirmations = {f"{n}_confirmation" for n, f in src_fields.items() if f["constraints"].get("confirmed")}
    for name in tf:
        if name not in src_fields and name not in confirmations:
            diffs.append((f"target schema declares extra field '{name}'", "low"))
    if diffs:
        worst = min(diffs, key=lambda d: SEVERITY_ORDER[d[1]])[1]
        checks.append(_chk("validation", "MISMATCH", worst, _src_ev(c, f"{len(src_fields)} source fields"), _tgt_ev(route, facts, f"schema {schema['file']}:{schema['line']}"),
                           "; ".join(d[0] for d in diffs)))
    else:
        checks.append(_chk("validation", "MATCH", "info", _src_ev(c), _tgt_ev(route, facts, f"schema {schema['file']}:{schema['line']}"), "Validation fields and constraints match."))
    for ac in c["async_checks"]:
        found = re.search(rf"\.\s*(?:findOne|exists|countDocuments)\s*\([^)]*\b{re.escape(ac['column'])}\b", facts["analysis"]["text"]) or "unique: true" in "".join(tctx["texts"].values())
        checks.append(_chk("validation", "MATCH" if found else "UNVERIFIED", "medium", _src_ev(c, f"{ac['type']}:{ac['table']}.{ac['column']}"), _tgt_ev(route, facts),
                           f"{ac['type']} check " + ("located in target" if found else "not located in target (may be enforced by a database index)")))


def _roles_from_controls(c):
    return sorted({r for ctl in c["authorization_controls"] if ctl["type"] == "middleware_check" for r in ctl["roles"]})


def _rule_present(rule, facts, owner_pattern=True):
    kind = rule.get("kind")
    a = facts["analysis"]
    if kind == "owner":
        return bool(a["owner_checks"]), "ownership comparison"
    if kind == "role_equals":
        return any(rule["value"] in rc["roles"] for rc in a["role_checks"]) or any(rule["value"] in (m.get("roles") or []) for m in facts["mws"] if m["kind"] == "role"), f"role == {rule['value']}"
    if kind in ("any_of", "all_of"):
        results = [_rule_present(r, facts) for r in rule["rules"]]
        if any(r[0] is None for r in results):
            return None, "contains unresolved rule"
        ok = all(r[0] for r in results) if kind == "all_of" else all(r[0] for r in results)  # any_of: every branch must exist in target
        return ok, " / ".join(r[1] for r in results)
    if kind == "constant":
        return True, "constant"
    if kind == "authenticated_only":
        return any(m["kind"] == "authentication" for m in facts["mws"]), "authenticated"
    return None, "unrecognised rule"


def _cmp_auth(c, route, facts, checks):
    mws = facts["mws"]
    has_auth = any(m["kind"] == "authentication" for m in mws)
    unresolved_auth = any(not m["resolved"] and m["kind"] == "other" for m in mws)
    if c["authentication"] == "REQUIRED" and not has_auth:
        checks.append(_chk("authentication", "UNVERIFIED" if unresolved_auth else "MISMATCH", "critical", _src_ev(c, "auth middleware required"),
                           _tgt_ev(route, facts, f"middleware: {[m['name'] for m in mws]}"),
                           "Source requires authentication; target route has no recognised authentication middleware." + (" (target middleware unresolved)" if unresolved_auth else "")))
    elif c["authentication"] != "REQUIRED" and has_auth and not c["authentication"].startswith("GUEST"):
        checks.append(_chk("authentication", "MISMATCH", "medium", _src_ev(c, c["authentication"]), _tgt_ev(route, facts),
                           "Target requires authentication on a route that is public in the source."))
    else:
        checks.append(_chk("authentication", "MATCH", "info", _src_ev(c, c["authentication"]), _tgt_ev(route, facts), "Authentication requirement matches."))
    src_roles, tgt_roles = _roles_from_controls(c), sorted({r for m in mws if m["kind"] == "role" for r in m.get("roles", [])})
    if src_roles:
        ok = set(src_roles) == set(tgt_roles) or any(set(src_roles) == set(rc["roles"]) for rc in facts["analysis"]["role_checks"])
        checks.append(_chk("authorization", "MATCH" if ok else "MISMATCH", "critical", _src_ev(c, f"roles {src_roles}"), _tgt_ev(route, facts, f"roles {tgt_roles}"),
                           "Role restriction matches." if ok else f"Source restricts to {src_roles}; target allows {tgt_roles or 'no role restriction'}."))
    elif tgt_roles:
        checks.append(_chk("authorization", "MISMATCH", "medium", _src_ev(c, "no role restriction"), _tgt_ev(route, facts, f"roles {tgt_roles}"), "Target adds a role restriction absent from the source."))
    for ctl in c["authorization_controls"]:
        if ctl["type"] in ("authorize_call", "can_middleware", "form_request_authorize"):
            rule = ctl.get("rule")
            if not rule or ctl.get("status") == "RULE_NOT_FOUND" or rule.get("kind") == "unrecognised":
                checks.append(_chk("authorization", "UNVERIFIED", "high", _src_ev(c, f"{ctl['type']} {ctl.get('ability')}: rule unresolved"), _tgt_ev(route, facts),
                                   "Source authorization rule could not be resolved (Laravel denies by default); target equivalence cannot be established."))
                continue
            ok, label = _rule_present(rule, facts)
            checks.append(_chk("authorization", "UNVERIFIED" if ok is None else "MATCH" if ok else "MISMATCH", "critical",
                               _src_ev(c, f"{ctl.get('ability')}: {label}"), _tgt_ev(route, facts, "; ".join(facts["analysis"]["owner_checks"][:1]) or None),
                               f"Source rule '{label}' " + ("is enforced in target." if ok else "was not found in the target (MISSING_BEHAVIOUR)." if ok is False else "cannot be compared.")))
    for g in c["guard_clauses"]:
        m = re.search(r"\$(\w+)\s*->\s*(\w+)\s*(?:!==|!=)\s*(?:auth\(\)\s*->\s*id\(\)|\$request\s*->\s*user\(\)\s*->\s*id|Auth::id\(\))", g["condition"])
        if m and g["status"] in (401, 403):
            ok = bool(facts["analysis"]["owner_checks"]) and g["status"] in facts["analysis"]["statuses"]
            checks.append(_chk("authorization", "MATCH" if ok else "MISMATCH", "critical", _src_ev(c, f"guard: {g['condition']} -> {g['status']}"),
                               _tgt_ev(route, facts, "; ".join(facts["analysis"]["owner_checks"][:1]) or None),
                               "Ownership guard matches." if ok else f"Source denies non-owners with {g['status']}; target has no equivalent ownership check/status."))


def _success_statuses(c):
    return sorted({r["status"] for r in c["responses"] if r.get("status") and r["status"] < 400} or {200})


def _cmp_status_response(c, route, facts, checks, tctx):
    a = facts["analysis"]
    t_success = sorted({r["status"] for r in a["responses"] if r["status"] < 400} or ({200} if a["responses"] else set()))
    s_success = _success_statuses(c)
    if not a["responses"]:
        checks.append(_chk("status", "UNVERIFIED", "high", _src_ev(c, f"success {s_success}"), _tgt_ev(route, facts), "Target handler sends its response indirectly; status codes cannot be extracted."))
    else:
        ok = s_success == t_success
        checks.append(_chk("status", "MATCH" if ok else "MISMATCH", "high", _src_ev(c, f"success statuses {s_success}"), _tgt_ev(route, facts, f"success statuses {t_success}"),
                           "Success status codes match." if ok else f"Source success status {s_success}; target {t_success}."))
    incomplete = bool(facts["incomplete"])
    missing = [s for s in c["error_statuses"] if s not in a["statuses"]]
    if missing:
        checks.append(_chk("status", "UNVERIFIED" if incomplete else "MISMATCH", "medium", _src_ev(c, f"error statuses {c['error_statuses']}"),
                           _tgt_ev(route, facts, f"error statuses {[s for s in a['statuses'] if s >= 400]}"),
                           f"Source can respond {missing}; the target never emits it" + (" (target evidence incomplete)." if incomplete else ".")))
    elif c["error_statuses"]:
        checks.append(_chk("status", "MATCH", "info", _src_ev(c, f"error statuses {c['error_statuses']}"), _tgt_ev(route, facts), "Error status codes are emitted by the target."))
    # response structure
    for sr in [r for r in c["responses"] if r.get("status", 200) < 400]:
        tr = next((r for r in a["responses"] if r["status"] == sr["status"]), None)
        if tr is None:
            continue
        if sr["type"] == "no_content":
            ok = tr["via"] in ("send", "end", "sendStatus") and not tr["argument"].strip() or tr["via"] == "sendStatus"
            checks.append(_chk("response", "MATCH" if ok else "MISMATCH", "high", _src_ev(c, "204 no content"), _tgt_ev(route, facts, tr["argument"]), "Empty response matches." if ok else "Source returns no body; target returns one."))
            continue
        expected = {"resource": {"data"}, "resource_collection": set(sr.get("envelope") or ["data"])}.get(sr["type"])
        if sr["type"] == "json" and sr.get("shape", {}).get("kind") == "object":
            expected = set(sr["shape"]["keys"])
        parsed = tr["parsed"]
        if expected is None:
            continue
        if not isinstance(parsed, dict):
            checks.append(_chk("response", "UNVERIFIED", "high", _src_ev(c, f"keys {sorted(expected)}"), _tgt_ev(route, facts, tr["argument"]), "Target response body is not a literal object; structure cannot be compared."))
            continue
        keys = {k for k in parsed if not k.startswith("...")}
        ok = keys == expected
        checks.append(_chk("response", "MATCH" if ok else "MISMATCH", "high", _src_ev(c, f"keys {sorted(expected)}"), _tgt_ev(route, facts, f"keys {sorted(keys)}"),
                           "Response envelope keys match." if ok else f"Source keys {sorted(expected)}; target keys {sorted(keys)}."))
        hidden = set().union(*[set(v) for v in (sr.get("hidden_fields_removed") or {}).values()]) if sr.get("hidden_fields_removed") else set()
        if hidden:
            leak = hidden & {w for v in re.findall(r"\b\w+\b", tr["argument"]) for w in [v]}
            hides = any(re.search(rf"(?:select\s*:\s*false|delete\s+ret\.{h}|toJSON|transform)", t) and h in t for h in hidden for t in tctx["texts"].values())
            checks.append(_chk("response", "MISMATCH" if (leak and not hides) else "MATCH" if hides else "UNVERIFIED", "critical",
                               _src_ev(c, f"hidden attributes {sorted(hidden)}"), _tgt_ev(route, facts, tr["argument"]),
                               "Target response may expose attributes the source hides." if leak and not hides else
                               "Hidden attributes are removed by the target model." if hides else "Hidden-attribute removal could not be verified in the target."))
        if sr.get("fields") and isinstance(parsed.get("data"), type(None)) is False:
            raw = str(parsed.get("data"))
            inline = re.search(r"\(\s*\{([^{}]*)\}\s*\)", raw)
            tf = _mapper_keys(raw, tctx)
            if tf is not None:
                pass
            elif inline:
                from app.target_analysis import parse_js
                po = parse_js("{" + inline.group(1) + "}")
                tf = {k for k in po} if isinstance(po, dict) else None
            elif isinstance(parsed["data"], dict):
                tf = set(parsed["data"])
            if tf is None:
                checks.append(_chk("response", "UNVERIFIED", "medium", _src_ev(c, f"resource fields {sr['fields']}"), _tgt_ev(route, facts, raw), "Resource field list not resolvable in the target."))
            else:
                ok = tf == set(sr["fields"])
                checks.append(_chk("response", "MATCH" if ok else "MISMATCH", "medium", _src_ev(c, f"resource fields {sr['fields']}"), _tgt_ev(route, facts, f"fields {sorted(tf)}"),
                                   "Resource fields match." if ok else f"Source resource fields {sorted(sr['fields'])}; target {sorted(tf)}."))


def _cmp_db_effects(c, route, facts, checks, tctx):
    a, inc = facts["analysis"], bool(facts["incomplete"])
    ops = list(c["model_operations"]) + [{"model": b["model"], "kind": "read", "operation": "findOrFail", "via": "route_model_binding", "relation": None} for b in c["bindings"]]
    related = {(m_id, r["name"]): r["related"] for m_id, m in tctx["models"].items() for r in m["relationships"]}
    for op in ops:
        model = op["model"]
        if op.get("relation"):
            model = next((i for i in tctx["models"] if short_name(i) == related.get((op["model"], op["relation"]))), model)
        name = short_name(model)
        soft = tctx["models"].get(model, {}).get("soft_deletes")
        hit = any(d["kind"] == op["kind"] and (d["model"] in (name, None)) for d in a["db"])
        if op["kind"] == "delete" and soft and a["soft_delete"]:
            hit = True
        checks.append(_chk("database", "MATCH" if hit else ("UNVERIFIED" if inc else "MISMATCH"), "high",
                           _src_ev(c, f"{name}.{op['operation']} ({op['kind']})"), _tgt_ev(route, facts, ", ".join(f"{d['model']}.{d['operation']}" for d in a["db"]) or "no database operations"),
                           f"Target performs a matching {op['kind']} on {name}." if hit else f"Source performs {op['kind']} on {name}; no equivalent operation found in the target" + (" (evidence incomplete)." if inc else " (MISSING_BEHAVIOUR).")))
        if op.get("page_size"):
            m = re.search(r"\.\s*limit\s*\(\s*(\d+)|(?:perPage|per_page|pageSize|limit)\s*=\s*(\d+)", a["text"])
            t = int(next(g for g in m.groups() if g)) if m else None
            checks.append(_chk("database", "UNVERIFIED" if t is None else "MATCH" if t == op["page_size"] else "MISMATCH", "medium", _src_ev(c, f"page size {op['page_size']}"),
                               _tgt_ev(route, facts, f"limit {t}"), "Page size matches." if t == op["page_size"] else f"Source page size {op['page_size']}; target {t if t else 'not found'}.", "business_rule"))
    for eff in c["side_effects"]:
        if eff in IGNORED_EFFECTS:
            continue
        hit = eff in a["effects"]
        checks.append(_chk("side_effect", "MATCH" if hit else ("UNVERIFIED" if inc else "MISMATCH"), EFFECT_SEVERITY.get(eff, "medium"), _src_ev(c, eff), _tgt_ev(route, facts, ", ".join(a["effects"]) or None),
                           f"Side effect '{eff}' present in target." if hit else f"Source performs '{eff}'; target has no equivalent" + (" (evidence incomplete)." if inc else " (MISSING_BEHAVIOUR)."), "side_effect"))


def _cmp_rules(c, route, facts, checks):
    for r in c["rules"]:
        cands = [t for t in facts["analysis"]["rules"] if t["subject"] == r["subject"] and t["kind"] == r["kind"]]
        if not cands:
            checks.append(_chk("business_rule", "UNVERIFIED", "medium", _src_ev(c, r["text"]), _tgt_ev(route, facts), f"Rule on '{r['subject']}' could not be located in the target."))
            continue
        if r["kind"] == "assignment":
            same = any((t["factor"] is not None and r["factor"] is not None and abs(t["factor"] - r["factor"]) < 1e-9) or (t["factor"] is None and r["factor"] is None and t["literals"] == r["literals"]) for t in cands)
            if r["factor"] is None and not same and any(set(t["literals"]) == set(r["literals"]) for t in cands):
                same = None
            checks.append(_chk("business_rule", "UNVERIFIED" if same is None else "MATCH" if same else "MISMATCH", "high", _src_ev(c, r["text"]), _tgt_ev(route, facts, cands[0]["text"]),
                               "Business constant matches." if same else f"Source: {r['text']} (factor {r['factor']}); target: {cands[0]['text']} (factor {cands[0]['factor']})." if same is False else "Expression forms differ; not comparable."))
        else:
            exact = any(t["operator"] == r["operator"] and t["value"] == r["value"] for t in cands)
            checks.append(_chk("business_rule", "MATCH" if exact else "MISMATCH", "high", _src_ev(c, r["text"]), _tgt_ev(route, facts, cands[0]["text"]),
                               "Condition matches." if exact else f"Source condition '{r['subject']} {r['operator']} {r['value']}'; target '{cands[0]['subject']} {cands[0]['operator']} {cands[0]['value']}'."))
    if c["throttle"]:
        rl = next((m for m in facts["mws"] if m["kind"] == "rate_limit"), None)
        if not rl:
            checks.append(_chk("rate_limit", "MISMATCH", "medium", _src_ev(c, f"throttle {c['throttle']}"), _tgt_ev(route, facts), "Source throttles this route; target has no rate limit (MISSING_BEHAVIOUR)."))
        elif "max" in c["throttle"] and rl.get("limit") and rl["limit"]["max"] is not None:
            ok = rl["limit"]["max"] == c["throttle"]["max"] and rl["limit"]["minutes"] == c["throttle"]["minutes"]
            checks.append(_chk("rate_limit", "MATCH" if ok else "MISMATCH", "medium", _src_ev(c, f"throttle {c['throttle']}"), _tgt_ev(route, facts, str(rl["limit"])), "Rate limit matches." if ok else "Rate limit values differ."))
        else:
            checks.append(_chk("rate_limit", "UNVERIFIED", "medium", _src_ev(c, f"throttle {c['throttle']}"), _tgt_ev(route, facts), "Target rate limiter present but its limits are not statically resolvable."))


def classify(checks: list[dict], found: bool, stub: bool, blocked: bool) -> str:
    if blocked:
        return "BLOCKED"
    if not found or stub:
        return "NOT_IMPLEMENTED"
    results = [k["result"] for k in checks if k["dimension"] != "route"]
    if any(r == "MISMATCH" for r in results):
        return "VERIFIED_MISMATCH"
    if not results:
        return "UNVERIFIED"
    if all(r == "MATCH" for r in results):
        return "VERIFIED_EQUIVALENT"
    return "PARTIALLY_VERIFIED" if "MATCH" in results else "UNVERIFIED"


def compare_contract(c: dict, tctx: dict, index: dict, runtime: dict | None) -> dict:
    route = index.get((c["method"], c["normalised_path"]))
    base = {"contract_id": c["contract_id"], "callable_contract_id": c["callable_contract_id"], "method": c["method"], "uri": c["uri"],
            "source": {"file": c["source_path"], "line": c["source_line"], "confidence": c["confidence"]}, "target": None,
            "verification_method": "static_structural", "evidence_level": "STATIC_ONLY", "human_review_required": True}
    if route is None:
        return {**base, "status": "NOT_IMPLEMENTED", "checks": [], "differences": [f"No target route for {c['method']} {c['uri']}"], "max_severity": "high",
                "limitations": ["Target route not found by static analysis (check mount prefixes and dynamic registration)."], "recommendation": "Implement the missing route."}
    handler = route["handler"]
    blocked = handler is None or any(s["file"] == (handler or {}).get("file") for s in tctx["skipped"])
    facts = _target_facts(route, tctx) if handler else {"mws": [], "incomplete": ["handler not resolved"], "analysis": None, "segments": []}
    checks = [_chk("route", "MATCH", "info", _src_ev(c), _tgt_ev(route, facts), "Route found in target.")]
    limitations = list(c["incomplete_source_evidence"]) + [f"target: {m}" for m in facts["incomplete"]]
    if handler and not blocked and not facts["analysis"]["stub"]:
        _cmp_auth(c, route, facts, checks); _cmp_validation(c, route, facts, tctx, checks)
        _cmp_status_response(c, route, facts, checks, tctx); _cmp_db_effects(c, route, facts, checks, tctx); _cmp_rules(c, route, facts, checks)
        if c["incomplete_source_evidence"]:
            checks.append(_chk("source_evidence", "UNVERIFIED", "medium", _src_ev(c, "; ".join(c["incomplete_source_evidence"])), None, "Source evidence is incomplete; equivalence cannot be established."))
        if (c["complexity"] or 0) > 5 or "raw_sql" in c["side_effects"]:
            checks.append(_chk("unsupported_dynamic_behaviour", "UNVERIFIED", "medium", _src_ev(c, f"complexity {c['complexity']}"), None, "Handler logic exceeds what static rule comparison covers (branching/dynamic/raw SQL)."))
    status = classify(checks, True, bool(facts["analysis"] and facts["analysis"]["stub"]), blocked)
    rt = (runtime or {}).get(c["contract_id"])
    if rt:
        base["runtime"] = rt
        if rt["failed"]:
            checks.append(_chk("runtime", "MISMATCH", "high", None, None, f"{rt['failed']} differential test(s) failed: " + "; ".join(d for r in rt["cases"] if r["status"] == "FAILED" for d in r["differences"][:2]), "runtime"))
            status = "VERIFIED_MISMATCH"
        elif rt["passed"] and not rt["blocked"] and status == "VERIFIED_EQUIVALENT":
            base["evidence_level"], base["verification_method"] = "STATIC_AND_RUNTIME", "static_structural+runtime_differential"
    limitations.append("Static structural comparison only; business logic not captured by extracted rules is not compared." if base["evidence_level"] == "STATIC_ONLY" else "Runtime evidence covers only the executed cases.")
    diffs = [k["difference"] for k in checks if k["result"] == "MISMATCH"]
    worst = min([k["severity"] for k in checks if k["result"] == "MISMATCH"] or ["info"], key=lambda s: SEVERITY_ORDER[s])
    return {**base, "status": status, "target": {"file": handler["file"], "line": handler["line"], "route": f"{route['method']} {route['path']}"} if handler else None,
            "checks": checks, "differences": diffs, "max_severity": worst, "limitations": limitations,
            "recommendation": next((k["recommendation"] for k in sorted(checks, key=lambda k: SEVERITY_ORDER[k["severity"]]) if k["recommendation"] and k["result"] == "MISMATCH"), None)}


# -------------------------------------------------------------------- driver
def run_parity(source_root: str | Path, target_root: str | Path, runtime: dict | None = None, exclude_web: bool = True) -> dict:
    """Run the full parity evaluation. ``runtime`` is the output of ``differential_testing.run_differential``."""
    source_root = str(Path(source_root).resolve(strict=True))
    target = resolve_target_root(str(target_root), source_root)
    src = build_source_contracts(source_root, exclude_web)
    t = analyze_express_project(target)
    tctx = {"functions": t["functions"], "imports": t["imports"], "schemas": t["schemas"], "texts": t["texts"], "skipped": t["skipped_files"], "models": src["models"]}
    index = {}
    for r in t["routes"]:
        index.setdefault((r["method"], norm_path(r["path"])), r)
    rt_by = {}
    if runtime and runtime.get("results"):
        for r in runtime["results"]:
            e = rt_by.setdefault(r["route_id"], {"cases": [], "passed": 0, "failed": 0, "blocked": 0, "skipped": 0})
            e["cases"].append(r); e[{"PASSED": "passed", "FAILED": "failed", "BLOCKED": "blocked", "SKIPPED": "skipped"}[r["status"]]] += 1
    results = [compare_contract(c, tctx, index, rt_by) for c in src["contracts"]]
    matched = {(r["method"], norm_path(r["uri"])) for r in results if r["status"] != "NOT_IMPLEMENTED"}
    wanted = {(c["method"], c["normalised_path"]) for c in src["contracts"]} | {(m["method"], norm_path(m["uri"])) for m in src["excluded"]}
    extras = [{"method": r["method"], "path": r["path"], "file": r["source_path"], "line": r["source_line"], "severity": "medium",
               "note": "Target route has no source contract: unreviewed attack surface or new feature."} for r in t["routes"]
              if (r["method"], norm_path(r["path"])) not in wanted and r["path"] not in EXTRA_ROUTE_ALLOWLIST]
    count = lambda s: sum(r["status"] == s for r in results)
    total = len(results)
    rt_results = (runtime or {}).get("results", [])
    metrics = {"total_source_contracts": total, "mapped_to_target": sum(r["status"] not in ("NOT_IMPLEMENTED",) and r["target"] is not None for r in results),
               **{k.lower(): count(k) for k in STATUSES},
               "runtime_tests_executed": sum(r["status"] in ("PASSED", "FAILED") for r in rt_results),
               "runtime_tests_passed": sum(r["status"] == "PASSED" for r in rt_results), "runtime_tests_failed": sum(r["status"] == "FAILED" for r in rt_results),
               "runtime_tests_blocked": sum(r["status"] == "BLOCKED" for r in rt_results),
               "excluded_web_contracts": len(src["excluded"]), "extra_target_routes": len(extras),
               "static_verification_coverage": round(count("VERIFIED_EQUIVALENT") / total, 4) if total else None,
               "coverage_definition": "verified_equivalent contracts / total_source_contracts (API route contracts; excluded web routes not counted)",
               "coverage_warning": "Coverage is a count of contracts whose compared dimensions matched statically. It is not proof of behavioural equivalence."}
    body = {"engine": "behavioural_parity", "engine_version": ENGINE_VERSION,
            "project_id": hashlib.sha256((Path(source_root).name + src["graph_fingerprint"]).encode()).hexdigest()[:16],
            "source": {"root_name": Path(source_root).name, "graph_fingerprint": src["graph_fingerprint"], "stages_used": src["stages"]},
            "target": {"root_name": target.name, "files_analysed": t["files_analysed"], "skipped_files": t["skipped_files"], "unresolved": t["unresolved"], "mount_roots": t["mount_roots"]},
            "contracts": results, "excluded_contracts": src["excluded"], "extra_target_routes": extras, "metrics": metrics,
            "runtime": {"performed": bool(rt_results), "status": (runtime or {}).get("status", "NOT_RUN"), "reason": (runtime or {}).get("reason", "runtime differential testing was not requested")},
            "policy": {"auto_approval": False, "generation_authorized": False, "human_review_required": True,
                       "note": "Parity results are evidence for human review; they never approve a migration or enable code generation."}}
    body["report_fingerprint"] = hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()
    body["generated_at"] = datetime.now(timezone.utc).isoformat()
    return body
