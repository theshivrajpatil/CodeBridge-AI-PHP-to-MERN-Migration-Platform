"""Conservative, source-linked Laravel/PHP behaviour extraction.

Static evidence only: this module never executes PHP and never upgrades an
unobserved runtime property into a verified contract.
"""
from __future__ import annotations
from pathlib import Path
import re

ROUTE_METHODS = {"get", "post", "put", "patch", "delete", "any", "match", "resource", "apiresource", "options"}


def _literal_first_arg(expression: str) -> str | None:
    m = re.search(r"Route\s*::\s*[A-Za-z_][A-Za-z0-9_]*\s*\(\s*(['\"])(.*?)\1", expression, re.I | re.S)
    return m.group(2) if m else None


def _controller_action(expression: str) -> tuple[str | None, str | None]:
    m = re.search(r"([\\A-Za-z_][\\A-Za-z0-9_]*)\s*::\s*class\s*,\s*(['\"])([A-Za-z_][A-Za-z0-9_]*)\2", expression)
    if m:
        return m.group(1).lstrip("\\"), m.group(3)
    m = re.search(r"\[\s*(['\"])([\\A-Za-z_][\\A-Za-z0-9_]*)@([A-Za-z_][A-Za-z0-9_]*)\1\s*\]", expression)
    if m:
        return m.group(2).lstrip("\\"), m.group(3)
    return None, None


def _matching_brace(source: str, open_pos: int) -> int | None:
    """Find a matching brace while ignoring quoted strings and PHP comments."""
    depth, i, state = 0, open_pos, "code"
    while i < len(source):
        c = source[i]
        n = source[i + 1] if i + 1 < len(source) else ""
        if state == "code":
            if c == "'": state = "single"
            elif c == '"': state = "double"
            elif c == "`": state = "backtick"
            elif c == "/" and n == "*": state = "block"; i += 1
            elif c == "/" and n == "/" or c == "#": state = "line"; i += 1
            elif c == "{": depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0: return i
        elif state in {"single", "double", "backtick"}:
            if c == "\\": i += 1
            elif (state == "single" and c == "'") or (state == "double" and c == '"') or (state == "backtick" and c == "`"): state = "code"
        elif state == "line":
            if c == "\n": state = "code"
        elif state == "block" and c == "*" and n == "/": state = "code"; i += 1
        i += 1
    return None


def _route_group_context(source: str, line: int) -> tuple[list[str], list[str], list[str]]:
    """Return literal prefix/middleware evidence from enclosing Route::group callbacks."""
    target_pos = sum(len(x) + 1 for x in source.splitlines()[:max(0, line - 1)])
    prefixes: list[str] = []
    middleware: list[str] = []
    evidence: list[str] = []
    pattern = re.compile(r"Route\s*::\s*prefix\s*\(\s*([\'\"])(.*?)\1\s*\)(?P<chain>(?:\s*->\s*(?:prefix|middleware|name|namespace)\s*\([^;]*?\))*)\s*->\s*group\s*\(\s*function\s*\([^)]*\)\s*\{", re.I | re.S)
    for match in pattern.finditer(source):
        brace = source.find("{", match.start(), match.end())
        end = _matching_brace(source, brace) if brace >= 0 else None
        if end is None or not (brace < target_pos < end):
            continue
        chain = match.group("chain")
        if match.group(2): prefixes.append(match.group(2).strip("/"))
        p = re.search(r"->\s*prefix\s*\(\s*(['\"])(.*?)\1\s*\)", chain, re.I | re.S)
        if p: prefixes.append(p.group(2).strip("/"))
        for mm in re.finditer(r"->\s*middleware\s*\(\s*(['\"])(.*?)\1\s*\)", chain, re.I | re.S):
            middleware.append(mm.group(2))
        evidence.append(source[match.start():min(end + 1, match.start() + 500)])
    return prefixes, middleware, evidence


def _closure_response(expression: str) -> dict:
    is_closure = bool(re.search(r"function\s*\([^)]*\)\s*\{", expression) or re.search(r"fn\s*\([^)]*\)\s*=>", expression))
    view = re.search(r"\bview\s*\(\s*(['\"])([^'\"]+)\1", expression)
    redirect = re.search(r"\bredirect\s*\(\s*(['\"])([^'\"]+)\1", expression)
    response = re.search(r"\bresponse\s*\(\s*", expression)
    status = re.search(r"(?:->\s*setStatusCode\s*\(|response\s*\([^;]*?,\s*)(\d{3})", expression, re.I | re.S)
    if view:
        return {"route_type": "CLOSURE" if is_closure else "CALLABLE_OR_UNKNOWN", "response_type": "BLADE_VIEW", "view_name": view.group(2), "response_status": "DEFAULT_NOT_EXPLICIT", "response_evidence": view.group(0)}
    if redirect:
        return {"route_type": "CLOSURE" if is_closure else "CALLABLE_OR_UNKNOWN", "response_type": "REDIRECT", "view_name": None, "redirect_target": redirect.group(2), "response_status": status.group(1) if status else "DEFAULT_NOT_EXPLICIT", "response_evidence": redirect.group(0)}
    if response:
        return {"route_type": "CLOSURE" if is_closure else "CALLABLE_OR_UNKNOWN", "response_type": "HTTP_RESPONSE", "view_name": None, "response_status": status.group(1) if status else "NEEDS_REVIEW", "response_evidence": response.group(0)}
    if is_closure:
        return {"route_type": "CLOSURE", "response_type": "NEEDS_REVIEW", "view_name": None, "response_status": "NEEDS_REVIEW", "response_evidence": None}
    return {"route_type": "CONTROLLER_OR_CALLABLE" if _controller_action(expression)[0] else "NEEDS_REVIEW", "response_type": "NEEDS_REVIEW", "view_name": None, "response_status": "NEEDS_REVIEW", "response_evidence": None}


def extract_route_contracts(files: list[dict], repository_root: str | Path | None = None) -> list[dict]:
    contracts = []
    for item in files:
        candidates = item.get("route_candidates", [])
        richest = {}
        for route in candidates:
            line = route.get("line")
            if line not in richest or len(route.get("evidence", "")) > len(richest[line].get("evidence", "")):
                richest[line] = route
        source = ""
        if repository_root and item.get("path"):
            try:
                p = (Path(repository_root) / item["path"]).resolve()
                p.relative_to(Path(repository_root).resolve())
                if p.is_file() and p.stat().st_size <= 1_000_000:
                    source = p.read_text(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                source = ""
        for route in richest.values():
            expr = route.get("evidence", "")
            # Only actual HTTP route registration methods create endpoint
            # contracts. Route::prefix()/middleware()/group() are context APIs.
            method_match = re.search(r"Route\s*::\s*(\w+)", expr, re.I)
            method_name = method_match.group(1).lower() if method_match else None
            if method_name not in ROUTE_METHODS:
                continue
            # Lexical fallback candidates may contain only the token
            # "Route::get(". Recover the complete source line when available.
            if source and (not _literal_first_arg(expr) or expr.rstrip().endswith("(")):
                source_lines = source.splitlines()
                line_no = route.get("line") or 1
                if 1 <= line_no <= len(source_lines):
                    expr = source_lines[line_no - 1].strip()
            method = method_name.upper() if method_name not in {"resource", "apiresource", "match", "any"} else None
            path = _literal_first_arg(expr)
            controller, action = _controller_action(expr)
            middleware = [x[1] for x in re.findall(r"->\s*middleware\s*\(\s*(['\"])(.*?)\1", expr, re.I | re.S)]
            prefixes, inherited_middleware, group_evidence = _route_group_context(source, route.get("line") or 1) if source else ([], [], [])
            middleware.extend(x for x in inherited_middleware if x not in middleware)
            effective_path = "/".join([*prefixes, (path or "").lstrip("/")]).rstrip("/")
            if path == "/" and not prefixes: effective_path = "/"
            elif path is not None: effective_path = "/" + effective_path
            response = _closure_response(expr)
            status = "PARTIALLY_VERIFIED" if method and path is not None else "NEEDS_REVIEW"
            if controller and action: status = "PARTIALLY_VERIFIED_CONTROLLER" if status == "PARTIALLY_VERIFIED" else status
            contracts.append({
                "source_path": item.get("path"), "source_line": route.get("line"),
                "framework": "Laravel" if "Route::" in expr else "PHP",
                "http_method": method, "route_definition": method_name, "path": path,
                "effective_path": effective_path if path is not None else None,
                "route_type": response["route_type"], "controller": controller, "action": action,
                "middleware_evidence": middleware, "middleware_inherited_evidence": inherited_middleware,
                "route_group_prefix_evidence": prefixes, "route_group_evidence": group_evidence,
                "authentication": "NEEDS_REVIEW", "authorization": "NEEDS_REVIEW",
                "request_validation": "NEEDS_REVIEW", "database_operations": "NEEDS_REVIEW",
                "response_status": response["response_status"], "response_type": response["response_type"],
                "view_name": response.get("view_name"), "redirect_target": response.get("redirect_target"),
                "response_evidence": response.get("response_evidence"),
                "redirect_session_cookie_semantics": "NEEDS_REVIEW",
                "evidence": expr[:1200], "confidence": "MEDIUM" if status.startswith("PARTIALLY") else "LOW",
                "status": status,
                "limitations": ["Route groups, route macros, dynamic registration and boot-time providers may alter the effective route." if not group_evidence else "Only literal enclosing group prefix/middleware calls were resolved; Laravel boot-time modifications remain unresolved.",
                                "Middleware names do not by themselves prove authentication or authorization semantics."]
            })
    return contracts



def _extract_callable_contracts(files: list[dict], repository_root: str | Path | None) -> list[dict]:
    """Extract conservative function/method body signals from PHP source.

    This is intentionally lexical and source-located; it does not claim that a
    method executes or that a detected call is reachable at runtime.
    """
    if not repository_root:
        return []
    root = Path(repository_root).resolve()
    contracts: list[dict] = []
    declaration = re.compile(
        r"(?P<visibility>public|protected|private)?\s*(?P<static>static\s+)?"
        r"function\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<params>[^)]*)\)"
        r"(?:\s*:\s*[\\A-Za-z_][\\A-Za-z0-9_?|\[\]]*)?\s*\{", re.I)
    for item in files:
        rel = item.get("path")
        if not rel:
            continue
        try:
            path = (root / rel).resolve()
            path.relative_to(root)
            if not path.is_file() or path.stat().st_size > 1_000_000:
                continue
            source = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            continue
        # Skip non-PHP templates even if their extension is .php-like; this
        # routine only records PHP declaration-shaped evidence.
        for match in declaration.finditer(source):
            brace = source.find("{", match.start(), match.end())
            end = _matching_brace(source, brace) if brace >= 0 else None
            if end is None:
                continue
            body = source[brace + 1:end]
            params = []
            for raw in match.group("params").split(","):
                raw = raw.strip()
                if not raw:
                    continue
                variable = re.search(r"\$([A-Za-z_][A-Za-z0-9_]*)", raw)
                params.append({"name": variable.group(1) if variable else None,
                               "type_candidate": raw.split("$", 1)[0].strip() or None,
                               "default_present": "=" in raw, "evidence": raw[:160]})
            line = source.count("\n", 0, match.start()) + 1
            checks = {
                "validation": bool(re.search(r"\b(validate|Validator::make|rules)\s*\(", body, re.I)),
                "authorization": bool(re.search(r"\b(authorize|Gate::|can\s*\()", body, re.I)),
                "authentication": bool(re.search(r"\b(auth\s*\(|Auth::|\$request->user\s*\()", body, re.I)),
                "database_read": bool(re.search(r"\b(?:find|findOrFail|first|firstOrFail|get|all|paginate|select|fetch|fetchAll)\s*\(|\bSELECT\b", body, re.I)),
                "database_write": bool(re.search(r"\b(?:create|insert|update|upsert|save|delete|destroy|execute)\s*\(|\b(?:INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b", body, re.I)),
                "redirect": bool(re.search(r"\bredirect\s*\(", body, re.I)),
                "session_or_cookie": bool(re.search(r"\b(?:session|cookie)\s*\(|\$_SESSION|setcookie\s*\(", body, re.I)),
                "file_io": bool(re.search(r"\b(?:file_get_contents|file_put_contents|fopen|Storage::|move_uploaded_file)\b", body, re.I)),
                "request_input": bool(re.search(r"(?:\$request\s*->\s*(?:input|query|all|only|except|validate)|\$_(?:GET|POST|REQUEST|FILES))", body, re.I)),
                "json_response": bool(re.search(r"\b(?:response\s*\(.*?\)->\s*json|response\s*\(.*?\)\s*->\s*json|json_encode)\b", body, re.I | re.S)),
                "exception_or_abort": bool(re.search(r"\b(?:throw\s+new|abort(?:_if|_unless)?\s*\()", body, re.I)),
                "transaction": bool(re.search(r"\b(?:DB::transaction|beginTransaction|commit|rollBack|rollback)\s*\(", body, re.I)),
                "external_http": bool(re.search(r"\b(?:Http::|curl_init|curl_exec|GuzzleHttp)", body, re.I)),
            }
            return_evidence = [m.group(0)[:180] for m in re.finditer(r"\breturn\s+([^;]+);", body, re.S)][:10]
            db_evidence = [{"line": source.count("\n", 0, brace + 1 + m.start()) + 1,
                            "expression": m.group(0)[:180]}
                           for m in re.finditer(r"(?:DB\s*::\s*\w+|\$\w+\s*->\s*(?:query|prepare|execute|save|update|delete)|\b(?:SELECT\s+.+?\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b)", body, re.I | re.S)][:20]
            contracts.append({
                "source_path": rel, "source_line": line, "callable_name": match.group("name"),
                "visibility_candidate": match.group("visibility") or "IMPLICIT",
                "static_candidate": bool(match.group("static")), "parameters": params,
                "signals": checks, "return_evidence": return_evidence,
                "database_call_evidence": db_evidence,
                "confidence": "MEDIUM", "status": "STATIC_CALLABLE_EVIDENCE_REQUIRES_REVIEW",
                "limitations": ["Static body patterns do not establish reachability, execution order, complete control flow, or runtime values.",
                                "Framework helpers and dynamically dispatched calls may not be recognized."]
            })
    return contracts


def build_behavior_report(analysis: dict, repository_root: str | Path | None = None) -> dict:
    contracts = extract_route_contracts(analysis.get("files", []), repository_root)
    callable_contracts = _extract_callable_contracts(analysis.get("files", []), repository_root)
    return {
        "status": "STATIC_EVIDENCE_REQUIRES_REVIEW", "route_contract_count": len(contracts),
        "route_contracts": contracts,
        "callable_contract_count": len(callable_contracts),
        "callable_contracts": callable_contracts,
        "coverage": {
            "routes_with_method_and_literal_path": sum(bool(x.get("http_method") and x.get("path") is not None) for x in contracts),
            "routes_with_controller_action": sum(bool(x.get("controller") and x.get("action")) for x in contracts),
            "closure_routes": sum(x.get("route_type") == "CLOSURE" for x in contracts),
            "blade_view_responses": sum(x.get("response_type") == "BLADE_VIEW" for x in contracts),
            "routes_with_middleware_evidence": sum(bool(x.get("middleware_evidence")) for x in contracts),
            "routes_with_inherited_group_prefix": sum(bool(x.get("route_group_prefix_evidence")) for x in contracts),
            "authentication_verified": 0, "validation_verified": 0,
            "database_behaviour_verified": 0,
            "callables_with_validation_evidence": sum(bool(x["signals"]["validation"]) for x in callable_contracts),
            "callables_with_authorization_evidence": sum(bool(x["signals"]["authorization"]) for x in callable_contracts),
            "callables_with_database_read_evidence": sum(bool(x["signals"]["database_read"]) for x in callable_contracts),
            "callables_with_database_write_evidence": sum(bool(x["signals"]["database_write"]) for x in callable_contracts),
            "callables_with_request_input_evidence": sum(bool(x["signals"]["request_input"]) for x in callable_contracts),
            "callables_with_json_response_evidence": sum(bool(x["signals"]["json_response"]) for x in callable_contracts),
            "callables_with_transaction_evidence": sum(bool(x["signals"]["transaction"]) for x in callable_contracts),
            "callables_with_external_http_evidence": sum(bool(x["signals"]["external_http"]) for x in callable_contracts),
            "response_contract_partially_extracted": sum(x.get("response_type") not in {"NEEDS_REVIEW", None} for x in contracts)
        },
        "policy": "Only source-backed facts are extracted. Unknown runtime semantics remain NEEDS_REVIEW; no behaviour is inferred from naming alone."
    }
