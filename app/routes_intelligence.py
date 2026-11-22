"""V5.20 — Routes and Middleware Intelligence.

Resolves Laravel route registration into *effective* routes:

* nested ``Route::prefix()/middleware()/controller()/name()->group()`` contexts,
* ``resource`` / ``apiResource`` expansion (``only``/``except``/nesting),
* route parameters with constraints and optionality,
* middleware alias/group resolution (bootstrap/app.php, Http/Kernel.php, built-ins),
* behavioural summaries of custom middleware classes,
* duplicate and shadowed route detection.

Static evidence only. Dynamic registration (loops, includes, macros) is reported
under ``unresolved`` rather than guessed.
"""
from __future__ import annotations

from pathlib import Path
import re

from app.php_source import (IDENT, as_strings, find_classes, find_methods, iter_php_files, line_of, mask_comments,
                            match_delim, parse_value, safe_read, short_name, split_top_level, stable_id, unquote)
from app.contract_extraction import _walk_chain
from app.dependency_graph import _use_map, _resolve, build_dependency_graph

ENGINE_VERSION = "5.20.0"
VERBS = {"get", "post", "put", "patch", "delete", "options", "any", "match"}
RESOURCE_ACTIONS = [("index", "GET", "", False), ("create", "GET", "/create", False), ("store", "POST", "", False),
                    ("show", "GET", "/{id}", True), ("edit", "GET", "/{id}/edit", False),
                    ("update", "PUT", "/{id}", True), ("destroy", "DELETE", "/{id}", True)]
BUILTIN_MIDDLEWARE = {
    "auth": ("authentication", "Illuminate\\Auth\\Middleware\\Authenticate"),
    "auth.basic": ("authentication", "Illuminate\\Auth\\Middleware\\AuthenticateWithBasicAuth"),
    "guest": ("guest", "App\\Http\\Middleware\\RedirectIfAuthenticated"),
    "verified": ("verification", "Illuminate\\Auth\\Middleware\\EnsureEmailIsVerified"),
    "throttle": ("rate_limit", "Illuminate\\Routing\\Middleware\\ThrottleRequests"),
    "can": ("authorization", "Illuminate\\Auth\\Middleware\\Authorize"),
    "signed": ("integrity", "Illuminate\\Routing\\Middleware\\ValidateSignature"),
    "password.confirm": ("authentication", "Illuminate\\Auth\\Middleware\\RequirePassword"),
    "cache.headers": ("caching", "Illuminate\\Http\\Middleware\\SetCacheHeaders"),
    "bindings": ("routing", "Illuminate\\Routing\\Middleware\\SubstituteBindings"),
}
GROUP_DEFAULTS = {"web": ["session", "csrf", "bindings"], "api": ["bindings"]}


def singular(word: str) -> str:
    word = word.replace("-", "_")
    if word.endswith("ies"):
        return word[:-3] + "y"
    if word.endswith(("sses", "xes", "ches", "shes")):
        return word[:-2]
    return word[:-1] if word.endswith("s") and not word.endswith("ss") else word


def _kernel_aliases(root: Path) -> dict[str, str]:
    aliases: dict[str, str] = {}
    sources = [(rel, safe_read(root, rel)) for rel in ("bootstrap/app.php", "app/Http/Kernel.php")]
    for rel, source in sources:
        if not source:
            continue
        text = mask_comments(source)
        uses = _use_map(text)
        ns = re.search(r"\bnamespace\s+([\\A-Za-z0-9_]+)", text)
        for m in re.finditer(r"(?:->\s*alias\s*\(|\$(?:middlewareAliases|routeMiddleware)\s*=)\s*", text):
            open_pos = text.find("[", m.end() - 1, m.end() + 3)
            close = match_delim(text, open_pos) if open_pos != -1 else None
            if close is None:
                continue
            parsed = parse_value(text[open_pos:close + 1])
            if isinstance(parsed, dict):
                for key, value in parsed.items():
                    if isinstance(value, dict) and "$class" in value:
                        aliases[str(key)] = _resolve(value["$class"], ns.group(1) if ns else "", uses)
    return aliases


def _custom_middleware_behaviour(root: Path, graph: dict, fqcn: str) -> dict | None:
    node = next((n for n in graph["nodes"] if n["id"] == fqcn), None)
    source = safe_read(root, node["file"]) if node else None
    if not source:
        return None
    text = mask_comments(source)
    method = next((m for m in find_methods(text) if m["name"] == "handle"), None)
    if not method:
        return None
    body = method["body"]
    denies = sorted({int(x) for x in re.findall(r"\babort(?:_if|_unless)?\s*\([^;]*?(\d{3})", body)} |
                    {int(x) for x in re.findall(r"->\s*json\s*\([^;]*?,\s*(\d{3})\s*\)", body)})
    return {"class": fqcn, "source_path": node["file"], "denies_with_status": denies,
            "reads_authenticated_user": bool(re.search(r"->\s*user\s*\(|\bAuth\s*::|\bauth\s*\(", body)),
            "checks_role_or_permission": bool(re.search(r"\brole\b|->\s*(?:hasRole|can|hasPermission)\s*\(|permission", body, re.I)),
            "redirects": bool(re.search(r"\bredirect\s*\(", body)),
            "extra_parameters": [p for p in re.findall(r"\$([A-Za-z_]\w*)", method["params_text"]) if p not in {"request", "next"}],
            "confidence": "MEDIUM", "status": "STATIC_EVIDENCE_REQUIRES_REVIEW"}


def _resolve_middleware(raw: str, aliases: dict, root: Path, graph: dict, cache: dict) -> dict:
    name, _, arg_text = raw.partition(":")
    args = [a.strip() for a in arg_text.split(",")] if arg_text else []
    builtin = BUILTIN_MIDDLEWARE.get(name)
    resolved = aliases.get(name) or (builtin[1] if builtin else None)
    category = builtin[0] if builtin and name not in aliases else "custom" if resolved else "unknown"
    if resolved and resolved not in cache:
        cache[resolved] = _custom_middleware_behaviour(root, graph, resolved) if name in aliases or "\\" in raw else None
    guard = args[0] if name == "auth" and args else None
    return {"raw": raw, "name": name, "arguments": args, "guard": guard, "resolved_class": resolved,
            "category": category, "builtin": bool(builtin) and name not in aliases,
            "behaviour": cache.get(resolved) if resolved else None,
            "status": "RESOLVED" if resolved else "UNRESOLVED_ALIAS"}


def _mount_info(root: Path) -> dict[str, dict]:
    """Route file -> {prefix, group, evidence}. Laravel 11 bootstrap/app.php, else RouteServiceProvider, else convention."""
    mounts = {"routes/api.php": {"prefix": "api", "group": "api", "evidence": "Laravel convention (api prefix)"},
              "routes/web.php": {"prefix": "", "group": "web", "evidence": "Laravel convention"}}
    boot = safe_read(root, "bootstrap/app.php")
    if boot:
        text = mask_comments(boot)
        for kind in ("web", "api"):
            m = re.search(rf"\b{kind}\s*:\s*__DIR__\s*\.\s*'/\.\./(routes/[\w./-]+)'", text)
            if m:
                mounts[m.group(1)] = {"prefix": "api" if kind == "api" else "", "group": kind,
                                      "evidence": f"bootstrap/app.php withRouting({kind}:)"}
        pm = re.search(r"\bapiPrefix\s*:\s*'([^']*)'", text)
        if pm:
            for v in mounts.values():
                if v["group"] == "api":
                    v["prefix"], v["evidence"] = pm.group(1).strip("/"), "bootstrap/app.php apiPrefix"
    provider = safe_read(root, "app/Providers/RouteServiceProvider.php")
    if provider:
        for m in re.finditer(r"Route\s*::\s*prefix\(\s*'([^']*)'\s*\)[^;]*?(?:base_path|__DIR__)[^;]*?'(?:/)?(routes/[\w./-]+)'", mask_comments(provider), re.S):
            mounts[m.group(2)] = {"prefix": m.group(1).strip("/"), "group": "api" if "api" in m.group(2) else "web",
                                  "evidence": "RouteServiceProvider"}
    return mounts


def _norm(*parts: str) -> str:
    joined = "/".join(p.strip("/") for p in parts if p and p.strip("/"))
    return "/" + joined


def _params(uri: str, where: dict) -> list[dict]:
    return [{"name": m.group(1), "optional": bool(m.group(2)), "constraint": where.get(m.group(1))}
            for m in re.finditer(r"\{(\w+)(\?)?\}", uri)]


def _apply_modifiers(chain, ctx_where: dict | None = None) -> dict:
    mod = {"middleware": [], "without": [], "name": None, "where": dict(ctx_where or {}), "only": None, "except": None,
           "names": None, "parameters": {}}
    for name, args, _ in chain:
        low, parts = name.lower(), [parse_value(a) for a in split_top_level(args)]
        if low == "middleware":
            mod["middleware"] += as_strings(parts)
        elif low == "withoutmiddleware":
            mod["without"] += as_strings(parts)
        elif low == "name" and parts and isinstance(parts[0], str):
            mod["name"] = parts[0]
        elif low == "where":
            if len(parts) == 2 and isinstance(parts[0], str):
                mod["where"][parts[0]] = str(parts[1])
            elif parts and isinstance(parts[0], dict):
                mod["where"].update({k: str(v) for k, v in parts[0].items()})
        elif low in {"wherenumber", "whereuuid", "wherealpha", "wherealphanumeric", "whereulid"}:
            pattern = {"wherenumber": "[0-9]+", "whereuuid": "[0-9a-fA-F-]{36}", "wherealpha": "[a-zA-Z]+",
                       "wherealphanumeric": "[a-zA-Z0-9]+", "whereulid": "[0-7][0-9A-HJKMNP-TV-Z]{25}"}[low]
            for p in as_strings(parts):
                mod["where"][p] = pattern
        elif low == "only":
            mod["only"] = as_strings(parts)
        elif low == "except":
            mod["except"] = as_strings(parts)
        elif low == "names" and parts and isinstance(parts[0], dict):
            mod["names"] = parts[0]
        elif low == "parameters" and parts and isinstance(parts[0], dict):
            mod["parameters"] = {k: str(v) for k, v in parts[0].items()}
    return mod


CTX_HEADS = {"prefix", "middleware", "controller", "name", "domain", "where", "namespace", "withoutmiddleware"}
ROUTE_HEADS = VERBS | {"resource", "apiresource", "redirect", "view"}


def _derive_ctx(chain, ctx: dict, ns: str, uses: dict) -> dict:
    """Context (prefix/middleware/name/controller/where) contributed by modifier calls in a Route:: chain."""
    g = {"prefix": list(ctx["prefix"]), "middleware": list(ctx["middleware"]), "without": list(ctx["without"]),
         "name": ctx["name"], "controller": ctx["controller"], "where": dict(ctx["where"])}
    for name, a, _ in chain:
        n, parts = name.lower(), [parse_value(x) for x in split_top_level(a)]
        if n == "prefix" and parts and isinstance(parts[0], str):
            g["prefix"].append(parts[0].strip("/"))
        elif n == "middleware":
            g["middleware"] += as_strings(parts)
        elif n == "withoutmiddleware":
            g["without"] += as_strings(parts)
        elif n == "name" and parts and isinstance(parts[0], str):
            g["name"] += parts[0]
        elif n == "controller" and parts and isinstance(parts[0], dict):
            g["controller"] = _resolve(parts[0]["$class"], ns, uses)
        elif n == "where":
            g["where"].update(_apply_modifiers([(name, a, 0)])["where"])
    return g


def build_routes_intelligence(root: str | Path, graph: dict | None = None, callable_ids: set[str] | None = None) -> dict:
    root = Path(root).resolve(strict=True)
    graph = graph or build_dependency_graph(root)
    aliases, mounts, mw_cache = _kernel_aliases(root), _mount_info(root), {}
    routes, unresolved = [], []
    route_files = [rel for rel in iter_php_files(root) if rel.startswith("routes/")]

    for rel in route_files:
        source = safe_read(root, rel)
        if not source:
            continue
        text, uses = mask_comments(source), None
        uses = _use_map(text)
        ns = ""
        mount = mounts.get(rel, {"prefix": "", "group": None, "evidence": "unmounted route file (no provider evidence)"})

        def handler_from(args: list, ctx: dict) -> dict:
            action = parse_value(args[1]) if len(args) > 1 else None
            def ctl(name):
                return _resolve(name, ns, uses)
            if isinstance(action, list) and len(action) == 2 and isinstance(action[0], dict):
                fq = ctl(action[0]["$class"])
                return {"type": "controller", "controller": fq, "action": action[1] if isinstance(action[1], str) else None}
            if isinstance(action, dict) and "$class" in action:
                return {"type": "invokable", "controller": ctl(action["$class"]), "action": "__invoke"}
            if isinstance(action, str) and "@" in action:
                c, a = action.split("@", 1)
                return {"type": "controller", "controller": ctl(c), "action": a}
            if isinstance(action, str) and ctx["controller"]:
                return {"type": "controller", "controller": ctx["controller"], "action": action}
            raw = args[1].strip() if len(args) > 1 else ""
            if re.match(r"(?:static\s+)?(?:function|fn)\b", raw):
                return {"type": "closure", "controller": None, "action": None, "inline_source": raw[:600]}
            return {"type": "unknown", "controller": None, "action": None, "raw": raw[:200]}

        def emit(method: str, uri: str, handler: dict, ctx: dict, mod: dict, pos: int, kind: str, action_name: str | None = None):
            where = {**ctx["where"], **mod["where"]}
            stack = [m for m in [*ctx["middleware"], *mod["middleware"]] if m not in set(ctx["without"] + mod["without"])]
            group = mount["group"]
            effective = _norm(mount["prefix"], *ctx["prefix"], uri)
            route_name = (ctx["name"] + (mod["name"] or "")) if mod["name"] else None
            routes.append({
                "id": stable_id(method, effective, str(handler.get("controller")), str(handler.get("action"))),
                "method": method, "uri": effective, "name": route_name, "kind": kind,
                "parameters": _params(effective, where), "handler": handler,
                "middleware_group": group, "group_default_middleware": GROUP_DEFAULTS.get(group or "", []),
                "middleware": [_resolve_middleware(m, aliases, root, graph, mw_cache) for m in stack],
                "source_path": rel, "source_line": line_of(source, pos),
                "mount_evidence": mount["evidence"], "resource_action": action_name,
            })

        def parse(start: int, end: int, ctx: dict) -> None:
            pos = start
            while True:
                m = re.compile(r"\bRoute\s*::\s*").search(text, pos, end)
                if not m:
                    return
                chain = _walk_chain(text, m.end(), True)
                if not chain:
                    pos = m.end(); continue
                stmt_end = chain[-1][2]
                head, head_args, _ = chain[0]
                if head.lower() in CTX_HEADS and not any(c[0].lower() == "group" for c in chain):
                    idx = next((k for k, c in enumerate(chain) if c[0].lower() in ROUTE_HEADS), None)
                    if idx:  # Route::middleware(...)->prefix(...)->get('/x', ...) without group()
                        ctx = _derive_ctx(chain[:idx], ctx, ns, uses)
                        chain = chain[idx:]
                        head, head_args, _ = chain[0]
                low, args = head.lower(), split_top_level(chain[0][1])
                group_call = next((c for c in chain if c[0].lower() == "group"), None)
                if group_call or low == "group":
                    gcall = group_call or chain[0]
                    gctx = _derive_ctx([c for c in chain if c is not gcall], ctx, ns, uses)
                    args_start = gcall[2] - 1 - len(gcall[1])
                    brace = text.find("{", args_start, gcall[2])
                    body_end = match_delim(text, brace) if brace != -1 and re.search(r"function", text[args_start:brace]) else None
                    if body_end is not None:
                        parse(brace + 1, body_end, gctx)
                    else:
                        unresolved.append({"file": rel, "line": line_of(source, m.start()), "reason": "group() argument is not an inline closure (file include or dynamic)", "evidence": gcall[1][:160]})
                elif low in {"prefix", "middleware", "controller", "name", "domain", "where", "namespace", "withoutmiddleware"}:
                    unresolved.append({"file": rel, "line": line_of(source, m.start()), "reason": f"Route::{head}() chain without group()", "evidence": text[m.start():stmt_end][:160]})
                elif low in VERBS:
                    mod = _apply_modifiers(chain[1:], ctx["where"])
                    uri = unquote(args[1] if low == "match" and len(args) > 2 else args[0]) if args else None
                    handler_args = args[2:] if low == "match" else args
                    if uri is None:
                        unresolved.append({"file": rel, "line": line_of(source, m.start()), "reason": "non-literal route URI", "evidence": text[m.start():stmt_end][:160]})
                    else:
                        methods = ([str(x).upper() for x in as_strings(parse_value(args[0]))] if low == "match"
                                   else ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] if low == "any" else [low.upper()])
                        for verb in methods:
                            emit(verb, uri.strip("/") if uri != "/" else "", handler_from(handler_args, ctx), ctx, mod, m.start(), "any" if low == "any" else "route")
                elif low in {"resource", "apiresource"}:
                    mod = _apply_modifiers(chain[1:], ctx["where"])
                    seg_path, ctl = unquote(args[0]) if args else None, parse_value(args[1]) if len(args) > 1 else None
                    if seg_path is None or not isinstance(ctl, dict):
                        unresolved.append({"file": rel, "line": line_of(source, m.start()), "reason": "non-literal resource definition", "evidence": text[m.start():stmt_end][:160]})
                    else:
                        segments = seg_path.strip("/").split("/")[-1].split(".")
                        base_parts = []
                        for i, seg in enumerate(segments):
                            base_parts.append(seg)
                            if i < len(segments) - 1:
                                base_parts.append("{" + mod["parameters"].get(seg, singular(seg)) + "}")
                        base = "/".join(base_parts)
                        prefix_in_path = "/".join(seg_path.strip("/").split("/")[:-1])
                        param = mod["parameters"].get(segments[-1], singular(segments[-1]))
                        for action, verb, suffix, _ in RESOURCE_ACTIONS:
                            if low == "apiresource" and action in {"create", "edit"}:
                                continue
                            if mod["only"] is not None and action not in mod["only"]:
                                continue
                            if mod["except"] and action in mod["except"]:
                                continue
                            verbs = ["PUT", "PATCH"] if action == "update" else [verb]
                            for v in verbs:
                                emit(v, "/".join(x for x in [prefix_in_path, base + suffix.replace("{id}", "{" + param + "}")] if x),
                                     {"type": "controller", "controller": _resolve(ctl["$class"], ns, uses), "action": action},
                                     ctx, {**mod, "name": None}, m.start(), low, action)
                elif low in {"redirect", "view", "fallback", "permanentredirect"}:
                    mod = _apply_modifiers(chain[1:], ctx["where"])
                    uri = unquote(args[0]) if args and low != "fallback" else "{fallbackPlaceholder}"
                    if uri is not None:
                        emit("GET", uri.strip("/"), {"type": low, "controller": None, "action": None, "target": args[1].strip()[:200] if len(args) > 1 else None}, ctx, mod, m.start(), low)
                else:
                    unresolved.append({"file": rel, "line": line_of(source, m.start()), "reason": f"unrecognised Route::{head}()", "evidence": text[m.start():stmt_end][:160]})
                pos = max(stmt_end, m.end())

        ns_match = re.search(r"\bnamespace\s+([\\A-Za-z0-9_]+)\s*;", text)
        ns = ns_match.group(1) if ns_match else ""
        parse(0, len(text), {"prefix": [], "middleware": [], "without": [], "name": "", "controller": None, "where": {}})
        for m in re.finditer(r"\b(?:foreach|for|while)\s*\([^)]*\)\s*\{[^}]*\bRoute\s*::", text):
            unresolved.append({"file": rel, "line": line_of(source, m.start()), "reason": "Route registration inside a loop (dynamic)", "evidence": text[m.start():m.end()][:160]})

    for r in routes:
        h = r["handler"]
        if h["type"] in {"controller", "invokable"} and callable_ids is not None:
            h["resolved"] = f"{h['controller']}::{h['action']}" in callable_ids
        r["handler_contract_id"] = f"{h.get('controller')}::{h.get('action')}" if h.get("controller") else None
    seen, duplicates = {}, []
    for r in routes:
        key = (r["method"], re.sub(r"\{\w+\??\}", "{}", r["uri"]))
        if key in seen:
            duplicates.append({"method": r["method"], "uri": r["uri"], "first": seen[key], "duplicate": r["id"]})
        seen.setdefault(key, r["id"])
    shadowed = []
    for i, a in enumerate(routes):
        for b in routes[i + 1:]:
            if a["method"] == b["method"] and re.search(r"\{\w+\??\}", a["uri"]) and not re.search(r"\{\w+\??\}", b["uri"]):
                pattern = "^" + re.sub(r"\\\{\w+\\\?\\\}|\\\{\w+\\\}", "[^/]+", re.escape(a["uri"])) + "$"
                if re.match(pattern, b["uri"]):
                    shadowed.append({"shadowed_route": b["id"], "shadowed_uri": b["uri"], "by_route": a["id"], "by_uri": a["uri"]})
    middleware_catalog = {}
    for r in routes:
        for mw in r["middleware"]:
            entry = middleware_catalog.setdefault(mw["name"], {"name": mw["name"], "category": mw["category"], "resolved_class": mw["resolved_class"],
                                                                  "behaviour": mw["behaviour"], "route_count": 0, "status": mw["status"]})
            entry["route_count"] += 1
    return {
        "engine": "routes_intelligence", "engine_version": ENGINE_VERSION, "graph_fingerprint": graph["fingerprint"],
        "route_files": [{"path": f, **mounts.get(f, {"prefix": "", "group": None, "evidence": "no mount evidence"})} for f in route_files],
        "middleware_aliases": dict(sorted(aliases.items())), "routes": sorted(routes, key=lambda r: (r["uri"], r["method"])),
        "middleware_catalog": dict(sorted(middleware_catalog.items())), "duplicates": duplicates, "shadowed_routes": shadowed,
        "unresolved": unresolved,
        "summary": {"route_count": len(routes), "unresolved_count": len(unresolved),
                    "unprotected_routes": sum(not any(m["category"] in {"authentication", "authorization"} for m in r["middleware"]) for r in routes),
                    "unresolved_middleware_aliases": sorted({m["name"] for r in routes for m in r["middleware"] if m["status"] != "RESOLVED"})},
        "policy": "Effective routes are static reconstructions; boot-time macros, dynamic registration and package routes are not resolved.",
    }
