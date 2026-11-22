"""V5.18 — Dependency Graph Engine.

Builds a deterministic, evidence-linked, symbol-level dependency graph of a PHP
project directly from source (no PHP execution, no tree-sitter requirement).

Edge direction: ``A -> B`` means *A depends on B*. Therefore a valid migration
order processes dependencies (sinks) first; :func:`build_dependency_graph`
returns that order as ``migration_layers``.
"""
from __future__ import annotations

from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re

from app.php_source import (IDENT, find_classes, find_methods, iter_php_files, line_of, mask_comments,
                            parse_parameters, safe_read, short_name)

ENGINE_VERSION = "5.18.0"

# Composer package -> Node/MERN equivalent. "DIRECT": drop-in role; "PARTIAL": needs
# adaptation; "MANUAL": no safe equivalent, human decision required.
COMPOSER_TO_NPM = {
    "laravel/framework": ("express", "PARTIAL", "Web framework; conventions are re-implemented explicitly."),
    "laravel/sanctum": ("jsonwebtoken", "PARTIAL", "Token auth re-implemented with signed JWTs; semantics must be reviewed."),
    "laravel/passport": ("jsonwebtoken", "MANUAL", "OAuth2 server has no drop-in Express equivalent."),
    "laravel/tinker": (None, "MANUAL", "Developer REPL; not migrated."),
    "spatie/laravel-permission": (None, "MANUAL", "Role/permission schema must be modelled explicitly."),
    "guzzlehttp/guzzle": ("axios", "DIRECT", "HTTP client."),
    "fakerphp/faker": ("@faker-js/faker", "DIRECT", "Test data generation."),
    "phpunit/phpunit": ("jest", "PARTIAL", "Tests must be re-written, not translated."),
    "mockery/mockery": ("jest", "PARTIAL", "Mocking via jest."),
    "predis/predis": ("ioredis", "DIRECT", "Redis client."),
    "league/flysystem": ("multer", "MANUAL", "File storage abstraction needs a design decision."),
    "intervention/image": ("sharp", "PARTIAL", "Image processing."),
    "nesbot/carbon": ("dayjs", "PARTIAL", "Date handling."),
    "monolog/monolog": ("pino", "DIRECT", "Logging."),
}
EXTERNAL_PREFIXES = ("Illuminate\\", "Laravel\\", "Symfony\\", "Carbon\\", "GuzzleHttp\\", "Spatie\\",
                     "PHPUnit\\", "Faker\\", "Monolog\\", "Psr\\", "Closure", "Exception", "Throwable")
ROLE_BY_PATH = [
    ("/Http/Controllers/", "controller"), ("/Http/Middleware/", "middleware"), ("/Http/Requests/", "form_request"),
    ("/Http/Resources/", "resource"), ("/Policies/", "policy"), ("/Providers/", "provider"),
    ("/Models/", "model"), ("/Services/", "service"), ("/Repositories/", "repository"),
    ("/Jobs/", "job"), ("/Events/", "event"), ("/Listeners/", "listener"), ("/Notifications/", "notification"),
    ("/Mail/", "mail"), ("/Console/", "console"), ("/Exceptions/", "exception"),
]


def _role(path: str, kind: str) -> str:
    probe = "/" + path
    if path.startswith("database/migrations/"):
        return "migration"
    if path.startswith("database/seeders/"):
        return "seeder"
    if path.startswith("database/factories/"):
        return "factory"
    if path.startswith("tests/"):
        return "test"
    if path.startswith("routes/"):
        return "route_file"
    for needle, role in ROLE_BY_PATH:
        if needle in probe:
            return role
    return {"interface": "contract", "trait": "trait"}.get(kind, "other")


def _use_map(code: str) -> dict[str, str]:
    """alias(lower) -> FQCN for simple and grouped ``use`` statements."""
    mapping: dict[str, str] = {}
    # Only file-level imports: trait ``use`` statements inside a class body must not
    # overwrite them.
    decl = re.search(r"^\s*(?:(?:abstract|final|readonly)\s+)*(?:class|interface|trait|enum)\s", code, re.M)
    prelude = code[:decl.start()] if decl else code
    for m in re.finditer(r"^\s*use\s+(?!function\b|const\b)([^;]+);", prelude, re.M):
        text = m.group(1).strip()
        group = re.fullmatch(r"([\\A-Za-z0-9_]+)\\\{(.+)\}", text, re.S)
        entries = ([f"{group.group(1)}\\{part.strip()}" for part in group.group(2).split(",") if part.strip()]
                   if group else [p.strip() for p in text.split(",") if p.strip()])
        for entry in entries:
            fqcn, _, alias = entry.partition(" as ")
            fqcn = fqcn.strip().lstrip("\\")
            mapping[(alias.strip() or short_name(fqcn)).lower()] = fqcn
    return mapping


def _resolve(name: str, namespace: str, uses: dict[str, str]) -> str:
    name = name.strip()
    if name.startswith("\\"):
        return name.lstrip("\\")
    head, _, rest = name.partition("\\")
    if head.lower() in uses:
        return uses[head.lower()] + (f"\\{rest}" if rest else "")
    return f"{namespace}\\{name}" if namespace else name


def _is_external(fqcn: str) -> bool:
    return fqcn.startswith(EXTERNAL_PREFIXES) or "\\" not in fqcn and fqcn[:1].isupper() and fqcn in {
        "Closure", "Exception", "Throwable", "DateTime", "stdClass", "Carbon"}


def load_composer(root: Path | str) -> dict:
    raw = safe_read(root, "composer.json")
    if raw is None:
        return {"present": False, "packages": [], "php_constraint": None}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {"present": True, "valid": False, "packages": [], "php_constraint": None}
    packages = []
    for scope in ("require", "require-dev"):
        for name, constraint in sorted((data.get(scope) or {}).items()):
            if name == "php" or name.startswith("ext-"):
                continue
            npm, level, note = COMPOSER_TO_NPM.get(name, (None, "MANUAL", "No known Node equivalent; manual decision required."))
            packages.append({"package": name, "constraint": str(constraint), "scope": scope,
                             "npm_equivalent": npm, "equivalence": level, "note": note})
    return {"present": True, "valid": True, "packages": packages,
            "php_constraint": (data.get("require") or {}).get("php"),
            "autoload_psr4": (data.get("autoload") or {}).get("psr-4", {})}


def tarjan_scc(nodes: list[str], adjacency: dict[str, set[str]]) -> list[list[str]]:
    """Iterative Tarjan strongly-connected components (safe for very deep graphs)."""
    index, low, on_stack, stack, result, counter = {}, {}, set(), [], [], [0]
    for start in nodes:
        if start in index:
            continue
        work = [(start, iter(sorted(adjacency.get(start, ()))))]
        index[start] = low[start] = counter[0]; counter[0] += 1
        stack.append(start); on_stack.add(start)
        while work:
            node, children = work[-1]
            advanced = False
            for child in children:
                if child not in index:
                    index[child] = low[child] = counter[0]; counter[0] += 1
                    stack.append(child); on_stack.add(child)
                    work.append((child, iter(sorted(adjacency.get(child, ()))))); advanced = True
                    break
                if child in on_stack:
                    low[node] = min(low[node], index[child])
            if advanced:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
            if low[node] == index[node]:
                component = []
                while True:
                    member = stack.pop(); on_stack.discard(member); component.append(member)
                    if member == node:
                        break
                result.append(sorted(component))
    return result


def _layers(nodes: list[str], adjacency: dict[str, set[str]], components: list[list[str]]) -> list[list[list[str]]]:
    """Dependency-first layers over the SCC condensation (cycles collapse to one step)."""
    comp_of = {n: i for i, comp in enumerate(components) for n in comp}
    deps = defaultdict(set)
    for src, targets in adjacency.items():
        for tgt in targets:
            if comp_of[src] != comp_of[tgt]:
                deps[comp_of[src]].add(comp_of[tgt])
    remaining, done, layers = set(range(len(components))), set(), []
    while remaining:
        ready = sorted(c for c in remaining if deps[c] <= done)
        if not ready:  # defensive: condensation of a graph is always acyclic
            ready = sorted(remaining)
        layers.append([components[c] for c in sorted(ready, key=lambda c: components[c][0])])
        done.update(ready); remaining.difference_update(ready)
    return layers


def build_dependency_graph(root: str | Path) -> dict:
    root = Path(root).resolve(strict=True)
    symbols: dict[str, dict] = {}
    parsed: list[tuple[str, str, str, dict[str, str], list[dict]]] = []
    for rel in iter_php_files(root):
        source = safe_read(root, rel)
        if source is None:
            continue
        code = mask_comments(source, mask_strings=True)
        ns = re.search(rf"\bnamespace\s+([\\A-Za-z0-9_]+)\s*[;{{]", code)
        namespace = ns.group(1) if ns else ""
        classes = find_classes(source)
        for cls in classes:
            fqcn = f"{namespace}\\{cls['name']}" if namespace else cls["name"]
            symbols[fqcn] = {"id": fqcn, "kind": cls["kind"], "file": rel, "line": cls["line"],
                             "role": _role(rel, cls["kind"])}
        parsed.append((rel, source, namespace, _use_map(code), classes))

    edges: dict[tuple[str, str, str], dict] = {}
    external: dict[str, dict] = {}
    unresolved: list[dict] = []

    def link(src: str, raw: str, namespace: str, uses: dict, relation: str, line: int, confidence: str) -> None:
        target = _resolve(raw, namespace, uses)
        if target == src:
            return
        if target in symbols:
            key = (src, target, relation)
            edge = edges.setdefault(key, {"from": src, "to": target, "type": relation, "confidence": confidence, "evidence": []})
            ev = {"file": symbols[src]["file"], "line": line}
            if ev not in edge["evidence"]:
                edge["evidence"].append(ev)
        elif _is_external(target):
            external.setdefault(target, {"id": target, "kind": "external", "used_by": set()})["used_by"].add(src)
        else:
            record = {"from": src, "reference": raw, "resolved_as": target, "relation": relation, "line": line}
            if record not in unresolved:
                unresolved.append(record)

    for rel, source, namespace, uses, classes in parsed:
        code = mask_comments(source, mask_strings=True)
        for cls in classes:
            src = f"{namespace}\\{cls['name']}" if namespace else cls["name"]
            for parent in cls["extends"]:
                link(src, parent, namespace, uses, "extends", cls["line"], "HIGH")
            for iface in cls["implements"]:
                link(src, iface, namespace, uses, "implements", cls["line"], "HIGH")
            for trait in cls["traits"]:
                link(src, trait, namespace, uses, "uses_trait", cls["line"], "HIGH")
            body = code[cls["body_start"]:cls["body_end"]]
            for m in re.finditer(rf"\bnew\s+\\?({IDENT}(?:\\{IDENT})*)", body):
                link(src, m.group(1), namespace, uses, "instantiates", line_of(source, cls["body_start"] + m.start()), "MEDIUM")
            for m in re.finditer(rf"(?<![\w$>])\\?({IDENT}(?:\\{IDENT})*)::(?!class\b)", body):
                if m.group(1).lower() not in {"self", "static", "parent"}:
                    link(src, m.group(1), namespace, uses, "static_reference", line_of(source, cls["body_start"] + m.start()), "MEDIUM")
            for m in re.finditer(rf"\\?({IDENT}(?:\\{IDENT})*)::class", body):
                link(src, m.group(1), namespace, uses, "class_reference", line_of(source, cls["body_start"] + m.start()), "MEDIUM")
            for method in find_methods(source, cls["body_start"], cls["body_end"]):
                relation = "injects" if method["name"] == "__construct" else "type_hint"
                for param in parse_parameters(method["params_text"]):
                    for part in re.split(r"[|&]", param["type"] or ""):
                        if part and part[0].isupper():
                            link(src, part, namespace, uses, relation, method["line"], "HIGH")
        if not classes:  # scripts: routes, migrations, config
            holder = f"file:{rel}"
            symbols.setdefault(holder, {"id": holder, "kind": "script", "file": rel, "line": 1, "role": _role(rel, "script")})
            for m in re.finditer(rf"\\?({IDENT}(?:\\{IDENT})*)::(?:class|\w+)", code):
                link(holder, m.group(1), namespace, uses, "references", line_of(source, m.start()), "MEDIUM")

    node_ids = sorted(symbols)
    adjacency: dict[str, set[str]] = {n: set() for n in node_ids}
    reverse: dict[str, set[str]] = {n: set() for n in node_ids}
    for (src, tgt, _), _edge in edges.items():
        adjacency[src].add(tgt); reverse[tgt].add(src)
    components = tarjan_scc(node_ids, adjacency)
    cycles = [c for c in components if len(c) > 1 or c[0] in adjacency[c[0]]]
    layers = _layers(node_ids, adjacency, components)
    fan_in = {n: len(reverse[n]) for n in node_ids}
    fan_out = {n: len(adjacency[n]) for n in node_ids}
    ordered_edges = [edges[k] for k in sorted(edges)]
    nodes = [dict(symbols[n], fan_in=fan_in[n], fan_out=fan_out[n]) for n in node_ids]
    canonical = json.dumps({"n": node_ids, "e": [[a, b, t] for a, b, t in sorted(edges)]}, sort_keys=True)
    composer = load_composer(root)
    return {
        "engine": "dependency_graph", "engine_version": ENGINE_VERSION,
        "fingerprint": hashlib.sha256(canonical.encode()).hexdigest(),
        "nodes": nodes, "edges": ordered_edges,
        "external_dependencies": [{"id": k, "used_by": sorted(v["used_by"])} for k, v in sorted(external.items())],
        "composer": composer,
        "unresolved_references": sorted(unresolved, key=lambda r: (r["from"], r["line"], r["reference"])),
        "cycles": cycles,
        "migration_layers": [[sorted(c) for c in layer] for layer in layers],
        "metrics": {"node_count": len(nodes), "edge_count": len(ordered_edges), "cycle_count": len(cycles),
                    "orphans": [n for n in node_ids if not fan_in[n] and not fan_out[n]],
                    "hubs": sorted(node_ids, key=lambda n: (-fan_in[n], n))[:5],
                    "role_counts": {r: sum(1 for x in nodes if x["role"] == r) for r in sorted({x["role"] for x in nodes})}},
        "policy": "Static source evidence only; reflection, container bindings and dynamic dispatch are not resolved.",
    }


def impact_of(graph: dict, node_id: str) -> dict:
    """Transitive dependents (what may break if ``node_id`` changes), with shortest paths."""
    reverse: dict[str, list[str]] = defaultdict(list)
    for edge in graph["edges"]:
        reverse[edge["to"]].append(edge["from"])
    paths, queue = {node_id: [node_id]}, [node_id]
    while queue:
        current = queue.pop(0)
        for parent in sorted(reverse[current]):
            if parent not in paths:
                paths[parent] = [parent, *paths[current]]
                queue.append(parent)
    paths.pop(node_id)
    return {"target": node_id, "dependent_count": len(paths), "dependents": dict(sorted(paths.items()))}


def to_mermaid(graph: dict, max_edges: int = 200) -> str:
    lines = ["graph LR"]
    safe = lambda s: re.sub(r"[^A-Za-z0-9_]", "_", s)
    for e in graph["edges"][:max_edges]:
        lines.append(f'  {safe(e["from"])}["{short_name(e["from"])}"] -->|{e["type"]}| {safe(e["to"])}["{short_name(e["to"])}"]')
    return "\n".join(lines)
