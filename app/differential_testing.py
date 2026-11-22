"""V5.23 — Safe differential (runtime) testing harness.

This module NEVER starts, builds or executes PHP/Node code. It only sends controlled HTTP requests to two
already-running, operator-provided instances (the original app and the migrated app, normally started in an
isolated sandbox/container with a throw-away database) and compares their observable responses.

Safety controls (all enforced in code):
* disabled unless ``enabled=True`` or ``CODEBRIDGE_RUNTIME_PARITY=1``;
* base URLs must be http(s) on loopback (127.0.0.1 / localhost / ::1) or an explicit allowlist host, with no
  embedded credentials; redirects are never followed; proxies are never used;
* mutating requests (POST/PUT/PATCH/DELETE) run only when ``allow_mutating=True`` (operator guarantees a disposable DB);
* hard limits: case count, timeout, response size; tokens are supplied by the operator and are never stored in results.

If the harness is not enabled or cannot reach an endpoint, the result is BLOCKED — never a pass.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urlsplit

ENGINE_VERSION = "5.23.0"
LOOPBACK = {"127.0.0.1", "localhost", "::1", "[::1]"}
MUTATING = {"POST", "PUT", "PATCH", "DELETE"}
SECRET_KEY = re.compile(r"(?i)(token|password|secret|authorization|api[_-]?key)")
DEFAULT_OPAQUE = ("token", "access_token", "refresh_token")


class RuntimeConfigError(ValueError):
    pass


@dataclass
class RuntimeConfig:
    source_base_url: str
    target_base_url: str
    enabled: bool = False
    allow_mutating: bool = False
    timeout_seconds: float = 5.0
    max_response_bytes: int = 1_000_000
    max_cases: int = 200
    compare_headers: tuple = ("content-type",)
    ignore_paths: tuple = ()           # explicitly declared non-semantic paths, e.g. "data.created_at", "data[].updated_at"
    opaque_keys: tuple = DEFAULT_OPAQUE  # compared by type/non-emptiness only (values are inherently unique secrets)
    path_params: dict = field(default_factory=dict)
    source_token: str | None = None
    target_token: str | None = None
    extra_allowed_hosts: tuple = ()


def validate_base_url(url: str, extra_hosts: tuple = ()) -> str:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise RuntimeConfigError("runtime URL must be http(s) with a host")
    if parts.username or parts.password:
        raise RuntimeConfigError("runtime URL must not embed credentials")
    if parts.hostname not in LOOPBACK and parts.hostname not in extra_hosts:
        raise RuntimeConfigError(f"host '{parts.hostname}' is not loopback or explicitly allowlisted; uncontrolled network access is refused")
    if parts.port is not None and not (1 <= parts.port <= 65535):
        raise RuntimeConfigError("invalid port")
    return f"{parts.scheme}://{parts.netloc}"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def http_transport(method: str, url: str, headers: dict, body: bytes | None, timeout: float, max_bytes: int) -> dict:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        resp = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as exc:
        resp = exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {"error": f"{type(exc).__name__}"}
    try:
        raw = resp.read(max_bytes + 1)
    finally:
        resp.close()
    if len(raw) > max_bytes:
        return {"error": "response exceeded size limit"}
    return {"status": resp.status if hasattr(resp, "status") else resp.code, "headers": {k.lower(): v for k, v in resp.headers.items()}, "body": raw.decode("utf-8", "replace")}


# ----------------------------------------------------------------------- cases
def _sample(field: dict):
    t, c = field["type"], field["constraints"]
    if c.get("in"):
        return c["in"][0]
    if c.get("email"):
        return "parity@example.test"
    if t in ("integer", "number"):
        return max(int(c.get("min", 1) or 1), 1)
    if t == "boolean":
        return True
    if t == "array":
        return []
    if t == "date":
        return "2030-01-01"
    n = max(int(c.get("min", 1) or 1), 1)
    return ("parity-test-value" * 10)[:max(n, min(int(c.get("max", 20) or 20), 20))]


def generate_cases(contracts: list[dict], cfg: RuntimeConfig) -> list[dict]:
    """Deterministic controlled cases from parity contracts (valid / invalid / unauthenticated / authenticated read)."""
    cases = []
    for c in contracts:
        path = c["uri"]
        params = re.findall(r"\{(\w+)\??\}", path)
        missing = [p for p in params if p not in cfg.path_params]
        base = {"route_id": c["contract_id"], "method": c["method"], "path": path}
        def add(name, headers_auth, body, note):
            cases.append({**base, "case": name, "auth": headers_auth, "body": body, "note": note, "missing_params": missing})
        if c["authentication"] == "REQUIRED":
            add("unauthenticated", False, None if c["method"] == "GET" else {}, "no credentials supplied")
        if c["validation_fields"] and c["method"] in MUTATING:
            add("invalid_payload", c["authentication"] == "REQUIRED", {}, "empty payload must be rejected identically")
            add("valid_payload", c["authentication"] == "REQUIRED", {f["field"]: _sample(f) for f in c["validation_fields"] if f["required"] or not f["sometimes"]}, "minimal valid payload")
        elif c["method"] == "GET":
            add("read", c["authentication"] == "REQUIRED", None, "plain read")
    return cases[:cfg.max_cases]


# ------------------------------------------------------------------ comparison
def _redact(value):
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if SECRET_KEY.search(k) else _redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v) for v in value]
    return value


def _ignored(path: str, patterns: tuple) -> bool:
    """Exact match against explicitly declared non-semantic paths ('*' matches one path segment)."""
    generic = re.sub(r"\[\d+\]", "[]", path)
    return any(re.fullmatch(re.escape(p).replace(r"\*", r"[^.]*"), generic) for p in patterns)


def diff_json(a, b, path: str, cfg: RuntimeConfig, out: list[str]) -> None:
    if _ignored(path, cfg.ignore_paths):
        return
    key = path.split(".")[-1].split("[")[0]
    if key in cfg.opaque_keys and isinstance(a, str) and isinstance(b, str):
        if bool(a) != bool(b):
            out.append(f"{path}: opaque value presence differs")
        return
    if type(a) is not type(b) and not (isinstance(a, (int, float)) and isinstance(b, (int, float)) and not isinstance(a, bool) and not isinstance(b, bool)):
        out.append(f"{path or '$'}: type differs ({type(a).__name__} vs {type(b).__name__})")
    elif isinstance(a, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a: out.append(f"{path}.{k}".lstrip(".") + ": only in target")
            elif k not in b: out.append(f"{path}.{k}".lstrip(".") + ": only in source")
            else: diff_json(a[k], b[k], f"{path}.{k}".lstrip("."), cfg, out)
    elif isinstance(a, list):
        if len(a) != len(b):
            out.append(f"{path or '$'}: list length {len(a)} vs {len(b)}")
        for i, (x, y) in enumerate(zip(a, b)):
            diff_json(x, y, f"{path}[{i}]", cfg, out)
    elif a != b:
        out.append(f"{path or '$'}: value differs ({_redact_scalar(path, a)!r} vs {_redact_scalar(path, b)!r})")


def _redact_scalar(path, v):
    return "[REDACTED]" if SECRET_KEY.search(path) else (v if not isinstance(v, str) else v[:80])


def compare_responses(src: dict, tgt: dict, cfg: RuntimeConfig) -> list[str]:
    diffs = []
    if src["status"] != tgt["status"]:
        diffs.append(f"status: {src['status']} (source) vs {tgt['status']} (target)")
    for h in cfg.compare_headers:
        if h == "content-type":
            a, b = src["headers"].get(h, "").split(";")[0].strip(), tgt["headers"].get(h, "").split(";")[0].strip()
        else:
            a, b = src["headers"].get(h), tgt["headers"].get(h)
        if a != b:
            diffs.append(f"header {h}: {a!r} vs {b!r}")
    try:
        sj, tj = json.loads(src["body"]), json.loads(tgt["body"])
        diff_json(sj, tj, "", cfg, diffs)
    except json.JSONDecodeError:
        if src["body"] != tgt["body"]:
            diffs.append("body: non-JSON bodies differ")
    return diffs


def run_differential(cases: list[dict], cfg: RuntimeConfig, transport=http_transport) -> dict:
    """Execute cases against both instances. Never raises on remote failure: returns BLOCKED/FAILED records."""
    if not (cfg.enabled or os.environ.get("CODEBRIDGE_RUNTIME_PARITY") == "1"):
        return {"engine": "differential_testing", "engine_version": ENGINE_VERSION, "status": "BLOCKED",
                "reason": "runtime verification is disabled (set enabled=True or CODEBRIDGE_RUNTIME_PARITY=1 for isolated, disposable environments)", "results": [], "summary": _summary([])}
    try:
        src_url = validate_base_url(cfg.source_base_url, cfg.extra_allowed_hosts)
        tgt_url = validate_base_url(cfg.target_base_url, cfg.extra_allowed_hosts)
    except RuntimeConfigError as exc:
        return {"engine": "differential_testing", "engine_version": ENGINE_VERSION, "status": "BLOCKED", "reason": str(exc), "results": [], "summary": _summary([])}
    results = []
    for case in cases[:cfg.max_cases]:
        rec = {"route_id": case["route_id"], "case": case["case"], "method": case["method"], "path": case["path"], "note": case["note"], "differences": []}
        if case["missing_params"]:
            results.append({**rec, "status": "SKIPPED", "differences": [f"no fixture value for path parameter(s) {case['missing_params']}"]}); continue
        if case["method"] in MUTATING and not cfg.allow_mutating:
            results.append({**rec, "status": "SKIPPED", "differences": ["mutating request skipped: allow_mutating is false"]}); continue
        if case["auth"] and not (cfg.source_token and cfg.target_token):
            results.append({**rec, "status": "SKIPPED", "differences": ["authenticated case skipped: no test tokens supplied"]}); continue
        path = case["path"]
        for k, v in cfg.path_params.items():
            path = re.sub(rf"\{{{k}\??\}}", re.sub(r"[^\w.\-]", "", str(v)), path)
        body = json.dumps(case["body"]).encode() if case["body"] is not None else None
        out = []
        for base, token in ((src_url, cfg.source_token), (tgt_url, cfg.target_token)):
            headers = {"Accept": "application/json", **({"Content-Type": "application/json"} if body else {}), **({"Authorization": f"Bearer {token}"} if case["auth"] else {})}
            out.append(transport(case["method"], base + path, headers, body, cfg.timeout_seconds, cfg.max_response_bytes))
        if any("error" in o for o in out):
            results.append({**rec, "status": "BLOCKED", "differences": [f"endpoint unreachable or invalid response: {[o.get('error') for o in out if 'error' in o]}"]}); continue
        diffs = compare_responses(out[0], out[1], cfg)
        results.append({**rec, "status": "FAILED" if diffs else "PASSED", "differences": diffs,
                        "observed": {"source_status": out[0]["status"], "target_status": out[1]["status"]}})
    normalisations = {"ignored_paths": list(cfg.ignore_paths), "opaque_keys": list(cfg.opaque_keys), "headers_compared": list(cfg.compare_headers)}
    return {"engine": "differential_testing", "engine_version": ENGINE_VERSION, "status": "COMPLETED", "reason": None,
            "results": results, "summary": _summary(results), "normalisations_applied": normalisations}


def _summary(results: list[dict]) -> dict:
    return {k.lower(): sum(r["status"] == k for r in results) for k in ("PASSED", "FAILED", "BLOCKED", "SKIPPED")} | {"executed": sum(r["status"] in ("PASSED", "FAILED") for r in results)}
