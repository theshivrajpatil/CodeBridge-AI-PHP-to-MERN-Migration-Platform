"""Final phase — Controlled MERN generation and deployment bundle.

Controls
* Nothing is generated unless (1) generation is enabled by configuration, and (2) a human approval record
  names a reviewer and reason, is bound to the *current* source fingerprint, and lists the approved contracts.
  Endpoints with unacknowledged HIGH-severity security findings are excluded.
* Only recognised, deterministic CRUD/auth recipes are translated. Everything else becomes an explicit
  501 stub carrying the reason; PHP business logic is never guessed.
* Every PHP-derived identifier is validated and every string is emitted as a JSON literal, so crafted PHP
  source cannot inject JavaScript. Output is confined to an allowed base directory (no traversal, no symlinks,
  no overwrite of unrelated content) and the project is generated as files only — nothing is deployed.
* The generated server is re-analysed with the V5.23 parity engine; results are reported, never auto-approved.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath

from app.contract_extraction import snake
from app.intelligence_pipeline import run_stage
from app.mern_templates import (CI, CLIENT_DOCKERFILE, CLIENT_FILES, CLIENT_PACKAGE, COMPOSE, DOCKERFILE_SERVER, ENV_JS,
                                NGINX, SERVER_PACKAGE, STATIC_SERVER)
from app.parity_engine import build_source_contracts, norm_path, run_parity
from app.php_source import match_delim, parse_value, short_name, split_top_level
from app.validation_response import closure_return_expression

ENGINE_VERSION = "5.24.0"
MARKER = ".codebridge-generated"
IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
HIGH_FLAGS = {"UNAUTHENTICATED_STATE_CHANGE", "BOUND_MODEL_WITHOUT_AUTHORIZATION"}
MAX_FILES, MAX_FILE_BYTES = 600, 1_000_000
INTENTIONAL_DIVERGENCES = [
    "Primary keys become MongoDB ObjectIds (24-hex strings) instead of auto-increment integers; clients must not assume numeric ids.",
    "Timestamps serialise as ISO-8601 with millisecond precision (Laravel emits microseconds).",
    "Sanctum tokens become signed JWTs backed by a revocable AccessToken collection (logout revokes server-side).",
    "422 bodies use the generic message 'The given data was invalid.' (Laravel builds the message from the first rule failure).",
    "Existing bcrypt password hashes remain verifiable (bcryptjs accepts $2y$), allowing user migration without password resets.",
    "Authorization is deny-by-default; rules that could not be translated deterministically are stubbed, not guessed.",
]


class GenerationError(ValueError):
    """Raised for unsafe input (identifiers, paths) or gate violations."""


class Unsupported(Exception):
    """A contract cannot be translated by a deterministic recipe (becomes a 501 stub)."""


def generation_enabled(config_path: str | Path, environ: dict) -> bool:
    """Two-key control: ``generation_enabled`` must be literally true in the config file AND CODEBRIDGE_GENERATION_ENABLED == "1"."""
    try:
        flag = json.loads(Path(config_path).read_text(encoding="utf-8")).get("generation_enabled") is True
    except (OSError, ValueError, AttributeError):
        flag = False
    return flag and environ.get("CODEBRIDGE_GENERATION_ENABLED") == "1"


def generation_status(config_path: str | Path, environ: dict) -> dict:
    """Why generation is (not) enabled, for display in the UI. Never reveals secrets."""
    try:
        cfg = json.loads(Path(config_path).read_text(encoding="utf-8")).get("generation_enabled") is True
    except (OSError, ValueError, AttributeError):
        cfg = False
    env = environ.get("CODEBRIDGE_GENERATION_ENABLED") == "1"
    missing = ([] if cfg else ['set "generation_enabled": true in config/models.json']) + ([] if env else ["set the environment variable CODEBRIDGE_GENERATION_ENABLED=1"])
    return {"enabled": cfg and env, "config_flag": cfg, "environment_flag": env,
            "instructions": ("Controlled generation is disabled. To enable it deliberately: " + " and ".join(missing) + ", then restart the server.") if missing else "Generation is enabled.",
            "also_required": "a fingerprint-bound human approval (reviewer + reason) for every generation run"}


def ident(name: str) -> str:
    if not isinstance(name, str) or not IDENT.fullmatch(name):
        raise GenerationError(f"unsafe identifier from source: {str(name)[:40]!r}")
    return name


def js(value) -> str:
    return json.dumps(value, ensure_ascii=True)


def comment(text: str, limit: int = 160) -> str:
    return re.sub(r"[^\x20-\x7e]", " ", str(text)).replace("*/", "* /")[:limit]


# ------------------------------------------------------------------- safe writer
class SafeWriter:
    def __init__(self, root: Path, overwrite: bool = False):
        self.root, self.files, self.overwrite = root, {}, overwrite
        if root.exists():
            if root.is_symlink() or not root.is_dir():
                raise GenerationError("output path must be a real directory")
            if any(root.iterdir()) and not (overwrite and (root / MARKER).is_file()):
                raise GenerationError("output directory is not empty (refusing to overwrite unrelated content)")
        root.mkdir(parents=True, exist_ok=True)
        (root / MARKER).write_text("generated by CodeBridge AI; safe to regenerate\n")

    def write(self, rel: str, text: str) -> None:
        p = PurePosixPath(rel)
        if (p.is_absolute() or ".." in p.parts
                or not re.fullmatch(r"\.?[A-Za-z0-9_@-][A-Za-z0-9_./@-]*", rel)):
            raise GenerationError(f"unsafe output path: {rel!r}")
        if len(self.files) >= MAX_FILES or len(text.encode()) > MAX_FILE_BYTES:
            raise GenerationError("generation size limit exceeded")
        target = self.root.joinpath(*p.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            target.resolve().relative_to(self.root.resolve())
        except ValueError:
            raise GenerationError("path escapes the output directory")
        if target.is_symlink():
            raise GenerationError("refusing to write through a symlink")
        if target.exists() and not self.overwrite:
            raise GenerationError(f"file already exists: {rel}")
        target.write_text(text, encoding="utf-8")
        self.files[rel] = hashlib.sha256(text.encode()).hexdigest()


def resolve_output_root(output: str | Path, source_root: str | Path, allowed_base: str | Path) -> Path:
    base = Path(allowed_base).resolve()
    base.mkdir(parents=True, exist_ok=True)
    out = Path(output)
    resolved = (out if out.is_absolute() else base / out).resolve()
    src = Path(source_root).resolve()
    if base not in resolved.parents:
        raise GenerationError("output must be inside the allowed generation directory")
    if resolved == src or src in resolved.parents or resolved in src.parents:
        raise GenerationError("output must not overlap the source repository")
    cur = resolved
    while cur != base:
        if cur.is_symlink():
            raise GenerationError("output path must not contain symlinks")
        cur = cur.parent
    return resolved


# -------------------------------------------------------------------------- gate
def source_fingerprint(src: dict) -> str:
    material = [src["graph_fingerprint"], [(c["contract_id"], c["method"], c["uri"], c["authentication"],
                [(f["field"], f["type"], f["required"]) for f in c["validation_fields"]],
                [(r.get("type"), r.get("status")) for r in c["responses"]], c["side_effects"]) for c in src["contracts"]]]
    return hashlib.sha256(json.dumps(material, sort_keys=True, default=str).encode()).hexdigest()


def evaluate_generation_gate(src: dict, risks: dict, approval: dict | None, enabled: bool) -> dict:
    reasons, approval = [], approval or {}
    if not enabled:
        reasons.append("code generation is disabled (set CODEBRIDGE_GENERATION_ENABLED=1 to allow it)")
    if not str(approval.get("reviewer", "")).strip() or not str(approval.get("reason", "")).strip():
        reasons.append("approval requires a non-empty reviewer and reason")
    fp = source_fingerprint(src)
    if approval.get("source_fingerprint") != fp:
        reasons.append("approval is not bound to the current analysis fingerprint (re-review required)")
    if reasons:
        return {"allowed": False, "reasons": reasons, "source_fingerprint": fp, "approved": [], "excluded": []}
    wanted = {c["contract_id"] for c in src["contracts"]} if approval.get("approve_all") else set(approval.get("approved_contract_ids", []))
    acknowledged, approved, excluded = set(approval.get("acknowledged_risks", [])), [], []
    for c in src["contracts"]:
        cid = c["contract_id"]
        if cid not in wanted:
            excluded.append({"contract_id": cid, "reason": "not approved"}); continue
        high = [f"{cid}:{f['flag']}" for f in risks.get(cid, []) if f["flag"] in HIGH_FLAGS]
        if set(high) - acknowledged:
            excluded.append({"contract_id": cid, "reason": f"unacknowledged HIGH-severity finding(s): {sorted(set(high) - acknowledged)}"}); continue
        approved.append(cid)
    return {"allowed": bool(approved), "reasons": [] if approved else ["no contract passed the gate"], "source_fingerprint": fp,
            "approved": approved, "excluded": excluded}


# ------------------------------------------------------------ model/resource emit
def _col_type(col: dict, models_by_table: dict) -> str:
    t = col["type"]
    base = {"string": "String", "text": "String", "uuid": "String", "integer": "Number", "bigint": "Number", "float": "Number",
            "decimal": "Number", "boolean": "Boolean", "json": "mongoose.Schema.Types.Mixed", "datetime": "Date", "date": "Date",
            "enum": "String", "foreign_key": "mongoose.Schema.Types.ObjectId"}.get(t, "mongoose.Schema.Types.Mixed")
    return base


def gen_model(m: dict, table: dict | None, models: dict, models_by_table: dict) -> tuple[str, list[str]]:
    name, notes, lines = ident(m["name"]), [], []
    hidden = [h for h in m["hidden"] if isinstance(h, str)]
    if table:
        for col in table["columns"]:
            cname = col["name"]
            if cname in {"id", "remember_token", "created_at", "updated_at", "deleted_at"} or not IDENT.fullmatch(cname):
                continue
            opts = [f"type: {_col_type(col, models_by_table)}"]
            if col["type"] == "foreign_key":
                ref = models_by_table.get((col.get("references") or {}).get("table"))
                if ref: opts.append(f"ref: {js(ref)}")
            if col["type"] == "enum" and col.get("enum_values"):
                opts.append(f"enum: {js(col['enum_values'])}")
            if "default" in col and not isinstance(col["default"], dict):
                opts.append(f"default: {js(col['default'])}")
            elif not col["nullable"]:
                opts.append("required: true")
            if col["unique"]: opts.append("unique: true")
            if cname in hidden and cname == "password": opts.append("select: false")
            lines.append(f"  {cname}: {{ {', '.join(opts)} }},")
    else:
        notes.append(f"{name}: no migration found; fields typed as Mixed from $fillable")
        for f in m["fillable"]:
            if isinstance(f, str) and IDENT.fullmatch(f):
                lines.append(f"  {f}: {{ type: mongoose.Schema.Types.Mixed }},")
            else:
                notes.append(f"{name}: field {str(f)[:40]!r} skipped (not a safe identifier)")
    if m["soft_deletes"]:
        lines.append("  deleted_at: { type: Date, default: null },")
    ts = "{ timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' }, " if (not table or table["timestamps"]) else "{ "
    hide = "".join(f"    delete ret.{ident(h)};\n" for h in hidden)
    virtuals = []
    for r in m["relationships"]:
        related = r["related"]
        if not related or related not in {short_name(i) for i in models}:
            continue
        extra = [e for e in r["extra_arguments"] if IDENT.fullmatch(e)]
        if r["type"] == "belongsTo":
            local, foreign, one = (extra[0] if extra else f"{snake(ident(r['name']))}_id"), "_id", True
        elif r["type"] in {"hasMany", "hasOne"}:
            local, foreign, one = "_id", (extra[0] if extra else f"{snake(name)}_id"), r["type"] == "hasOne"
        else:
            notes.append(f"{name}.{r['name']}: relationship type {r['type']} not generated"); continue
        virtuals.append(f"schema.virtual({js(ident(r['name']))}, {{ ref: {js(related)}, localField: {js(local)}, foreignField: {js(foreign)}, justOne: {js(one)} }});")
    hooks = ("for (const hook of ['find', 'findOne', 'countDocuments', 'findOneAndUpdate']) {\n"
             "  schema.pre(hook, function () { if (!this.getOptions().withTrashed) this.where({ deleted_at: null }); });\n}\n") if m["soft_deletes"] else ""
    body = f"""import mongoose from 'mongoose';

const schema = new mongoose.Schema({{
{chr(10).join(lines)}
}}, {ts}toJSON: {{ virtuals: false, transform: (_doc, ret) => {{
    ret.id = String(ret._id);
    delete ret._id;
    delete ret.__v;
{hide}    return ret;
  }} }} }});
{chr(10).join(virtuals)}
{hooks}
export const {name} = mongoose.models.{name} || mongoose.model({js(name)}, schema, {js(table['table'] if table else pluralize_name(name))});
{name}.fillable = {js([f for f in m['fillable'] if isinstance(f, str)])};
"""
    return body, notes


def pluralize_name(name: str) -> str:
    from app.contract_extraction import pluralize
    return pluralize(snake(name))


def gen_resource(name: str, spec: dict) -> tuple[str, list[str], list[str]]:
    rels, notes, fields = [], [], []
    for f in spec["fields"]:
        key = js(f["name"])
        if f["kind"] == "attribute" and IDENT.fullmatch(f["source"]):
            fields.append(f"    {key}: doc.{f['source']},")
        elif f["kind"] == "relation_attribute" and re.fullmatch(r"\w+\.\w+", f["source"]):
            rel, attr = f["source"].split(".")
            rels.append(ident(rel))
            fields.append(f"    {key}: doc.{rel}?.{ident(attr)} ?? null,")
        else:
            notes.append(f"{name}.{f['name']}: {f['kind']} field not translated (NEEDS_REVIEW)")
            fields.append(f"    {key}: null, // NEEDS_REVIEW: {comment(f['source'])}")
    return f"export function {ident(name)}(doc) {{\n  return {{\n" + "\n".join(fields) + "\n  };\n}\n", sorted(set(rels)), notes


# ------------------------------------------------------------- handler recipes
class Ctx:
    def __init__(self, root: str):
        self.contracts = run_stage(root, "contracts")
        self.vr = run_stage(root, "validation-response")
        self.auth = run_stage(root, "auth")
        self.models = {m["id"]: m for m in self.contracts["model_contracts"]}
        self.by_short = {short_name(i): i for i in self.models}
        self.tables = {t["table"]: t for t in self.contracts["schema_contracts"]}
        self.models_by_table = {m["table"]: short_name(i) for i, m in self.models.items()}
        self.resources = self.vr["resources"]
        self.resource_rels: dict[str, list[str]] = {}
        self.vr_by = {e["route_id"]: e for e in self.vr["endpoints"]}
        self.risks = {e["route_id"]: e["risk_flags"] for e in self.auth["endpoints"]}
        self.auth_model = next((short_name(i) for i, m in self.models.items() if m["authenticatable"]), None)


def js_value(expr: str, bound: dict) -> str:
    e = expr.strip()
    if re.fullmatch(r"\$request\s*->\s*user\(\)\s*->\s*id|auth\(\)\s*->\s*id\(\)|Auth::id\(\)", e):
        return "req.user.id"
    m = re.fullmatch(r"\$(\w+)\s*->\s*id", e)
    if m and m.group(1) in bound:
        return f"req.bound.{ident(m.group(1))}.id"
    raise Unsupported(f"unsupported payload expression: {comment(e, 80)}")


def js_payload(arg: str, bound: dict) -> str:
    parts, segments = split_top_level(arg, "+"), []
    for part in parts:
        p = part.strip()
        if re.fullmatch(r"\$request\s*->\s*validated\(\)|\$(?:data|validated)", p):
            segments.append("...req.valid")
        elif p.startswith("["):
            parsed = parse_value(p)
            if not isinstance(parsed, dict):
                raise Unsupported("payload array is not keyed")
            for k, v in parsed.items():
                segments.append(f"{ident(str(k))}: " + (js(v) if not hasattr(v, "text") else js_value(v.text, bound)))
        else:
            raise Unsupported(f"unsupported payload: {comment(p, 80)}")
    return "{ " + ", ".join(segments) + " }"


def op_argument(evidence: str, op_name: str) -> str:
    m = re.search(rf"\b{re.escape(op_name)}\s*\(", evidence)
    if not m:
        raise Unsupported("operation arguments not captured")
    close = match_delim(evidence, m.end() - 1)
    if close is None:
        raise Unsupported("operation arguments truncated")
    return evidence[m.end():close]


def build_chain_and_checks(c: dict, ctx: Ctx, notes: list, handler_authz: list, template_guards: bool = False) -> list[str]:
    """Route-level middleware (in source order) plus inline authorization lines for the handler."""
    chain = []
    for mw in c["middleware"]:
        if mw["status"] != "RESOLVED":
            raise Unsupported(f"middleware '{mw['name']}' could not be resolved")
        cat, args = mw["category"], mw["arguments"]
        if cat == "authentication":
            chain.append("authenticate")
        elif cat == "rate_limit":
            if len(args) == 2 and all(a.isdigit() for a in args):
                chain.append(f"rateLimit({{ max: {int(args[0])}, windowMinutes: {int(args[1])} }})")
            else:
                chain.append("rateLimit({ max: 60, windowMinutes: 1 })")
                notes.append(f"named rate limiter {args} replaced by default 60/min")
        elif cat == "authorization" and mw["name"] == "can":
            continue
        elif cat == "custom" and mw["role_check"]:
            chain.append(f"requireRole({', '.join(js(a) for a in args)})")
        elif cat in {"routing"}:
            continue
        else:
            raise Unsupported(f"middleware '{mw['name']}' ({cat}) has no deterministic translation")
    bound = {b["parameter"]: short_name(b["model"]) for b in c["bindings"]}
    for ctl in c["authorization_controls"]:
        t = ctl["type"]
        if t in {"middleware_check"}:
            continue
        if t == "can_middleware" or t in {"authorize_call", "form_request_authorize"}:
            rule = ctl.get("rule")
            if ctl.get("status") == "RULE_NOT_FOUND" or not rule:
                raise Unsupported(f"authorization rule for '{ctl.get('ability')}' is unresolved (Laravel denies by default)")
            if t == "can_middleware":
                if rule["kind"] == "role_equals":
                    chain.append(f"requireRole({js(rule['value'])})"); continue
                raise Unsupported("can: middleware rule requires manual translation")
            if t == "form_request_authorize":
                if rule["kind"] == "authenticated_only" and c["authentication"] == "REQUIRED":
                    continue
                raise Unsupported("FormRequest authorize() requires manual translation")
            param = next((p for p, m in bound.items() if m == ctl.get("subject_model")), None)
            expr = rule_to_js(rule, param)
            handler_authz.append(f"    if (!({expr})) throw new HttpError(403, 'This action is unauthorized.');")
        elif t == "inline_guard" and template_guards:
            continue  # credential failure (401) is produced by the auth recipe itself
        elif t == "inline_guard":
            m = re.search(r"\$(\w+)\s*->\s*(\w+)\s*(?:!==|!=)\s*(?:auth\(\)\s*->\s*id\(\)|\$request\s*->\s*user\(\)\s*->\s*id|Auth::id\(\))", ctl["condition"])
            if not m or m.group(1) not in bound or ctl["status_code"] not in (401, 403):
                raise Unsupported(f"inline guard not translatable: {comment(ctl['condition'], 80)}")
            handler_authz.append(f"    if (String(req.bound.{ident(m.group(1))}.{ident(m.group(2))}) !== String(req.user.id)) throw new HttpError({ctl['status_code']}, {js(guard_message(c, ctl))});")
        else:
            raise Unsupported(f"authorization control '{t}' not translatable")
    return chain


def guard_message(c: dict, ctl: dict) -> str:
    return "This action is unauthorized." if ctl["status_code"] == 403 else "Unauthenticated."


def rule_to_js(rule: dict, param: str | None) -> str:
    k = rule["kind"]
    if k == "owner":
        if not param:
            raise Unsupported("ownership rule without a bound resource")
        actor = "req.user.id" if rule["actor_field"] == "id" else f"req.user.{ident(rule['actor_field'])}"
        return f"String(req.bound.{ident(param)}.{ident(rule['resource_field'])}) === String({actor})"
    if k == "role_equals":
        return f"req.user.{ident(rule['field'])} === {js(rule['value'])}"
    if k in {"any_of", "all_of"}:
        return "(" + (" || " if k == "any_of" else " && ").join(rule_to_js(r, param) for r in rule["rules"]) + ")"
    if k == "constant":
        return "true" if rule["value"] else "false"
    if k == "authenticated_only":
        return "true"
    if k == "boolean_flag":
        return f"Boolean(req.user.{ident(rule['field'])})"
    raise Unsupported("authorization rule is not recognised")


def populate_line(resource: str | None, ctx: Ctx, target: str) -> str:
    rels = ctx.resource_rels.get(resource or "", [])
    return f"    await {target}.populate({js(rels)});" if rels else ""


def success(c: dict) -> dict:
    s = [r for r in c["responses"] if r.get("status", 200) < 400]
    if not s:
        raise Unsupported("no success response found")
    return s[0]


def handler_body(c: dict, ctx: Ctx, notes: list) -> tuple[list[str], list[str]]:
    """Return (route middleware chain additions, controller body lines) for a recognised recipe."""
    if c["complexity"] is None:
        raise Unsupported("handler contract not found in source analysis (check controller import/namespace in the route file)")
    effects = set(c["side_effects"]) - {"session_state", "logging"}
    authz: list[str] = []
    bound = {b["parameter"]: short_name(b["model"]) for b in c["bindings"]}
    ops, sr = c["model_operations"], success(c)
    fields = [f["field"] for f in c["validation_fields"]]
    # --- auth recipes ---------------------------------------------------------
    if "token_revoke" in effects:
        chain = build_chain_and_checks(c, ctx, notes, authz)
        if sr["type"] != "no_content":
            raise Unsupported("logout response is not 204")
        return chain, ["    await AccessToken.deleteOne({ jti: req.auth.jti });", "    return res.status(204).send();"]
    if {"token_issue"} <= effects and ({"session_login", "password_check"} & effects) and not ops:
        chain = build_chain_and_checks(c, ctx, notes, authz, template_guards=True)
        if not ctx.auth_model or not {"email", "password"} <= set(fields):
            raise Unsupported("login recipe needs an authenticatable model with email/password fields")
        U, msg = ctx.auth_model, "Invalid credentials"
        for r in c["responses"]:
            if r.get("status") == 401:
                m = re.search(r"'message'\s*=>\s*'([^']*)'", r["expression"]); msg = m.group(1) if m else msg
        if set(sr.get("shape", {}).get("keys", {})) != {"token"}:
            raise Unsupported("login response shape is not { token }")
        return chain, [f"    const user = await {U}.findOne({{ email: req.valid.email }}).select('+password');",
                       "    const ok = user ? await bcrypt.compare(req.valid.password, user.password) : false;",
                       f"    if (!ok) return res.status(401).json({{ message: {js(msg)} }});",
                       "    const token = await issueToken(user);", "    return res.json({ token });"]
    if {"password_hashing", "token_issue"} <= effects and len(ops) == 1 and ops[0]["kind"] == "write" and ctx.auth_model and short_name(ops[0]["model"]) == ctx.auth_model:
        chain = build_chain_and_checks(c, ctx, notes, authz)
        if set(sr.get("shape", {}).get("keys", {})) != {"user", "token"} or sr["status"] != 201 or "password" not in fields:
            raise Unsupported("register response/fields not recognised")
        U = ctx.auth_model
        return chain, [f"    const user = await {U}.create(pick({{ ...req.valid, password: await bcrypt.hash(req.valid.password, env.BCRYPT_ROUNDS) }}, {U}.fillable));",
                       "    const token = await issueToken(user);", "    return res.status(201).json({ user: user.toJSON(), token });"]
    # --- generic safety gates -------------------------------------------------
    if effects:
        raise Unsupported(f"side effects {sorted(effects)} have no deterministic translation")
    if c["rules"]:
        raise Unsupported("handler contains business rules: " + comment("; ".join(r["text"] for r in c["rules"][:2]), 100))
    owner_guards = [g for g in c["guard_clauses"]]
    for g in owner_guards:
        if not re.search(r"\$\w+\s*->\s*\w+\s*(?:!==|!=)\s*(?:auth\(\)\s*->\s*id\(\)|\$request\s*->\s*user\(\)\s*->\s*id|Auth::id\(\))", g["condition"]):
            raise Unsupported(f"guard clause not translatable: {comment(g['condition'], 80)}")
    chain = build_chain_and_checks(c, ctx, notes, authz)
    pre = list(authz)
    res_name = sr.get("resource")
    # --- JSON aggregate -------------------------------------------------------
    shape = sr.get("shape", {})
    if sr["type"] == "json" and shape.get("kind") == "object" and shape.get("expressions") and ops and all(o["operation"].lower() == "count" for o in ops):
        items = []
        for k, e in shape["expressions"].items():
            m = re.fullmatch(r"(\w+)::count\(\)", e.strip())
            if not m or m.group(1) not in ctx.by_short: raise Unsupported("aggregate expression not recognised")
            items.append(f"{js(k)}: await {ident(m.group(1))}.countDocuments()")
        return chain, pre + ["    return res.json({ " + ", ".join(items) + " });"]
    if len(ops) == 1:
        op, model = ops[0], short_name(ops[0]["model"])
        name = op["operation"].lower()
        if op["kind"] == "read" and op["via"] == "static" and name in {"get", "all", "paginate"}:
            filt = {x["field"]: x["value"] for x in op["conditions"] if x["operator"] == "=" and not isinstance(x["value"], dict)}
            if len(filt) != len(op["conditions"]):
                raise Unsupported("non-equality query conditions")
            sort = "latest" in op["modifiers"], "oldest" in op["modifiers"]
            q = f"{ident(model)}.find({js(filt)})" + (".sort({ created_at: -1 })" if sort[0] else ".sort({ created_at: 1 })" if sort[1] else "")
            rels = ctx.resource_rels.get(res_name or "", [])
            q += f".populate({js(rels)})" if rels else ""
            if sr["type"] == "resource_collection" and name == "paginate":
                size = op.get("page_size")
                if not isinstance(size, int): raise Unsupported("page size is not a literal")
                return chain, pre + [f"    const perPage = {size};", f"    const page = await paginate({q}, req, perPage);",
                                     f"    return res.json({{ data: page.data.map({ident(res_name)}), links: page.links, meta: page.meta }});"]
            if sr["type"] == "resource_collection" and name in {"get", "all"}:
                return chain, pre + [f"    const docs = await {q};", f"    return res.json({{ data: docs.map({ident(res_name)}) }});"]
            if sr["type"] == "json" and shape.get("kind") == "expression":
                return chain, pre + [f"    const docs = await {q};", "    return res.json(docs.map((d) => d.toJSON()));"]
        if op["kind"] == "read" and op["via"] == "bound_relation":
            param = next((p for p, m in bound.items() if short_name(c["model_operations"][0]["model"]) == m), None)
            rel = next((r for r in ctx.models[op["model"]]["relationships"] if r["name"] == op["relation"]), None)
            if param and rel and rel["type"] == "hasMany" and name in {"get", "all"} and sr["type"] == "json" and shape.get("kind") == "expression":
                fk = f"{snake(short_name(op['model']))}_id"
                sort = "latest" in op["modifiers"]
                return chain, pre + [f"    const docs = await {ident(rel['related'])}.find({{ {fk}: req.bound.{ident(param)}._id }}){'.sort({ created_at: -1 })' if sort else ''};",
                                     "    return res.json(docs.map((d) => d.toJSON()));"]
        if op["kind"] == "write" and name == "create" and op["via"] in {"static", "bound_relation"} and sr["type"] in {"resource", "json"}:
            arg = js_payload(op_argument(op["evidence"], "create"), bound)
            target, fk = ident(model), None
            if op["via"] == "bound_relation":
                param = next((p for p, m in bound.items() if m == model), None)
                rel = next((r for r in ctx.models[op["model"]]["relationships"] if r["name"] == op["relation"]), None)
                if not param or not rel or rel["type"] != "hasMany" or not rel["related"] or rel["related"] not in ctx.by_short:
                    raise Unsupported("relation create not recognised")
                target, fk = ident(rel["related"]), (f"{snake(model)}_id", f"req.bound.{ident(param)}._id")
            payload = f"pick({arg}, {target}.fillable)" if not fk else f"{{ ...pick({arg}, {target}.fillable), {fk[0]}: {fk[1]} }}"
            lines = pre + [f"    const doc = await {target}.create({payload});"]
            st = f".status({sr['status']})" if sr["status"] != 200 else ""
            if sr["type"] == "resource":
                p = populate_line(res_name, ctx, "doc"); lines += [p] if p else []
                lines.append(f"    return res{st}.json({{ data: {ident(res_name)}(doc) }});")
            else:
                if shape.get("kind") != "expression": raise Unsupported("create response shape not recognised")
                lines.append(f"    return res{st}.json(doc.toJSON());")
            return chain, lines
        if op["kind"] == "write" and op["via"] == "bound_instance" and name == "update" and sr["type"] == "resource":
            param = next((p for p, m in bound.items() if m == model), None)
            if not param: raise Unsupported("update target is not route-bound")
            arg = js_payload(op_argument(op["evidence"], "update"), bound)
            lines = pre + [f"    const doc = req.bound.{ident(param)};", f"    Object.assign(doc, pick({arg}, {ident(model)}.fillable));", "    await doc.save();"]
            p = populate_line(res_name, ctx, "doc"); lines += [p] if p else []
            return chain, lines + [f"    return res.json({{ data: {ident(res_name)}(doc) }});"]
        if op["kind"] == "delete" and op["via"] == "bound_instance" and sr["type"] == "no_content":
            param = next((p for p, m in bound.items() if m == model), None)
            if not param: raise Unsupported("delete target is not route-bound")
            soft = ctx.models[op["model"]]["soft_deletes"]
            act = [f"    req.bound.{ident(param)}.deleted_at = new Date();", f"    await req.bound.{ident(param)}.save();"] if soft else [f"    await req.bound.{ident(param)}.deleteOne();"]
            return chain, pre + act + ["    return res.status(204).send();"]
    if not ops and len(bound) == 1 and sr["type"] in {"resource"}:
        param = next(iter(bound))
        lines = pre[:]
        p = populate_line(res_name, ctx, f"req.bound.{ident(param)}"); lines += [p] if p else []
        return chain, lines + [f"    return res.json({{ data: {ident(res_name)}(req.bound.{ident(param)}) }});"]
    raise Unsupported("handler shape is not a recognised CRUD/auth recipe")


def closure_handler(c: dict) -> str:
    h = c["handler"]
    expr = closure_return_expression(h.get("inline_source", ""))
    m = re.fullmatch(r"response\(\)\s*->\s*json\((.*)\)", expr, re.S)
    if not m:
        raise Unsupported("inline closure is not a literal JSON response")
    parts = split_top_level(m.group(1))
    data = parse_value(parts[0])
    status = int(parts[1]) if len(parts) > 1 and parts[1].strip().isdigit() else 200
    def lit(v):
        if hasattr(v, "text"): raise Unsupported("closure response contains non-literal values")
        return {k: lit(x) for k, x in v.items()} if isinstance(v, dict) else [lit(x) for x in v] if isinstance(v, list) else v
    return f"(req, res) => res{f'.status({status})' if status != 200 else ''}.json({js(lit(data))})"


# ---------------------------------------------------------------------- project
def _client(contracts: list[dict], plan: dict, mount: str, name: str) -> dict:
    files = {k: v.replace("@@NAME@@", name).replace("@@MOUNT@@", mount) for k, v in CLIENT_FILES.items()}
    fns, seen = [], set()
    login = None
    for c in contracts:
        if plan[c["contract_id"]]["action"] != "IMPLEMENT":
            continue
        rel = re.sub(r"\{(\w+)\??\}", r"${\1}", c["uri"][len(mount):] if c["uri"].startswith(mount + "/") else c["uri"])
        params = re.findall(r"\{(\w+)\??\}", c["uri"])
        fn = snake(c["method"].lower() + "_" + re.sub(r"\{\w+\??\}", "by", c["uri"].strip("/").replace("/", "_").replace("-", "_")))
        fn = re.sub(r"[^a-z0-9_]", "", fn) or "call"
        if fn in seen: continue
        seen.add(fn)
        args = ", ".join([ident(p) for p in params] + (["body"] if c["method"] in {"POST", "PUT", "PATCH"} else []))
        call = f"http({js(c['method'])}, `{rel}`" + (", body" if c["method"] in {"POST", "PUT", "PATCH"} else "") + ")"
        fns.append(f"export const {fn} = ({args}) => {call};")
        if "token_issue" in c["side_effects"] and "session_login" in c["side_effects"]:
            login = fn
    files["src/api/endpoints.js"] = "import { http } from './http.js';\n\n" + "\n".join(fns) + "\n"
    lg = login or "null"
    files["src/App.jsx"] = f"""import {{ useState }} from 'react';
import {{ useAuth }} from './auth/AuthContext.jsx';
import * as api from './api/endpoints.js';

export default function App() {{
  const {{ isAuthenticated, signIn, signOut }} = useAuth();
  const [form, setForm] = useState({{ email: '', password: '' }});
  const [error, setError] = useState('');
  const login = {('api.' + lg) if login else 'null'};
  async function submit(event) {{
    event.preventDefault();
    try {{ const {{ token }} = await login(form); signIn(token); setError(''); }}
    catch (e) {{ setError(e.message); }}
  }}
  if (!isAuthenticated) {{
    return login ? (
      <form onSubmit={{submit}}>
        <h1>Sign in</h1>
        <input type="email" required value={{form.email}} onChange={{(e) => setForm({{ ...form, email: e.target.value }})}} />
        <input type="password" required value={{form.password}} onChange={{(e) => setForm({{ ...form, password: e.target.value }})}} />
        <button type="submit">Sign in</button>
        {{error && <p role="alert">{{error}}</p>}}
      </form>
    ) : <p>No login endpoint was generated; see MIGRATION_REPORT.md.</p>;
  }}
  return <div><h1>{name}</h1><button onClick={{signOut}}>Sign out</button><p>API client functions: {{Object.keys(api).join(', ')}}</p></div>;
}}
"""
    return files


def generate_mern_project(source_root: str | Path, output_root: Path, approval: dict | None, enabled: bool,
                          project_name: str = "migrated-app", overwrite: bool = False, run_parity_check: bool = True) -> dict:
    """Generate the project. ``output_root`` must already be validated with :func:`resolve_output_root`.

    On any failure after the output directory was created by this call, the partial output is removed.
    """
    existed = Path(output_root).exists()
    try:
        return _generate(source_root, output_root, approval, enabled, project_name, overwrite, run_parity_check)
    except Exception:
        if not existed and Path(output_root).is_dir() and (Path(output_root) / MARKER).is_file():
            import shutil
            shutil.rmtree(output_root, ignore_errors=True)
        raise


def preview_generation(source_root: str | Path) -> dict:
    """Read-only: the fingerprint an approval must bind to, plus per-contract risk information."""
    source_root = str(Path(source_root).resolve(strict=True))
    src, ctx = build_source_contracts(source_root), Ctx(source_root)
    return {"engine": "mern_generator", "engine_version": ENGINE_VERSION, "source_fingerprint": source_fingerprint(src),
            "contracts": [{"contract_id": c["contract_id"], "method": c["method"], "uri": c["uri"],
                           "risk_flags": ctx.risks.get(c["contract_id"], [])} for c in src["contracts"]],
            "excluded_web_contracts": src["excluded"],
            "high_risk_flags_requiring_acknowledgement": [f"{c['contract_id']}:{f['flag']}" for c in src["contracts"]
                                                          for f in ctx.risks.get(c["contract_id"], []) if f["flag"] in HIGH_FLAGS],
            "policy": {"generation_authorized": False, "note": "Preview only; nothing generated."}}


def _generate(source_root, output_root, approval, enabled, project_name, overwrite, run_parity_check) -> dict:
    source_root = str(Path(source_root).resolve(strict=True))
    name = re.sub(r"[^a-z0-9-]", "-", project_name.lower()).strip("-")[:40] or "migrated-app"
    src = build_source_contracts(source_root)
    ctx = Ctx(source_root)
    gate = evaluate_generation_gate(src, ctx.risks, approval, enabled)
    if not gate["allowed"]:
        return {"engine": "mern_generator", "engine_version": ENGINE_VERSION, "status": "REFUSED", "gate": gate, "files": {},
                "policy": {"deployment_authorized": False, "note": "Generation refused; nothing was written."}}
    approved = set(gate["approved"])
    for rn, spec in ctx.resources.items():
        _, rels, _ = gen_resource(rn, spec); ctx.resource_rels[rn] = rels
    w = SafeWriter(output_root, overwrite)
    plan, notes = {}, []
    for c in src["contracts"]:
        plan[c["contract_id"]] = {"action": "EXCLUDE", "reason": next((e["reason"] for e in gate["excluded"] if e["contract_id"] == c["contract_id"]), "not approved")}
    ctrls: dict[str, dict] = {}
    route_lines, validators, mount_prefix = [], [], ""
    impl = [c for c in src["contracts"] if c["contract_id"] in approved]
    mount_prefix = "/api" if impl and all(c["uri"].startswith("/api/") for c in impl) else ""
    rel_path = lambda c: re.sub(r"\{(\w+)\??\}", r":\1", c["uri"][len(mount_prefix):] if mount_prefix else c["uri"]) or "/"
    used_models, used_helpers = set(), {}
    for c in impl:
        cid, h = c["contract_id"], c["handler"]
        try:
            chain, async_mw, body = [], [], None
            if h["type"] == "closure":
                handler_ref = closure_handler(c)
                chain = [m for m in ("authenticate",) if c["authentication"] == "REQUIRED"]
            elif h["type"] in {"controller", "invokable"} and c["callable_contract_id"]:
                notes_local: list[str] = []
                chain, body = handler_body(c, ctx, notes_local); notes += notes_local
                ctl, action = ident(short_name(h["controller"])), ident(h["action"] or "handle")
                if h["type"] == "invokable": action = "invoke"
                handler_ref = f"{ctl}.{action}"
                for b in c["bindings"]:
                    chain.append(f"bind({js(b['parameter'])}, {ident(short_name(b['model']))}, {js(b['model'])})")
                    used_models.add(short_name(b["model"]))
                    if b["parameter"] not in re.findall(r"\{(\w+)\??\}", c["uri"]):
                        raise Unsupported(f"route-model binding parameter '{b['parameter']}' is not a URI segment")
                src_ep = ctx.vr_by[cid]
                target = next((s["target"] for s in src_ep["validation"]["sources"] if s.get("target")), None)
                if target and c["validation_fields"]:
                    if target["unsupported"]:
                        raise Unsupported("validation rules need review: " + comment(str(target["unsupported"][0]), 100))
                    if not re.fullmatch(r"[0-9a-f]{16}", cid):
                        raise GenerationError("unexpected contract id format")
                    sname = f"s_{cid}"
                    validators.append(f"export const {sname} = {target['zod_object']};")
                    conf = [r["field"] for r in target["refinements"]]
                    chain.append(f"validate({sname}" + (f", {{ confirmed: {js(conf)} }}" if conf else "") + ")")
                    for ac in target["async_checks"]:
                        model = ctx.models_by_table.get(ac["table"])
                        if not model or not ac["column"] or ac["extra_arguments"]:
                            raise Unsupported(f"{ac['type']} check on '{ac['table']}' not translatable")
                        async_mw.append(f"{ac['type']}({ident(model)}, {js(ac['column'])}, {js(ac['field'])})"); used_models.add(model)
                chain += async_mw
            else:
                raise Unsupported("handler could not be resolved")
            if h["type"] != "closure":
                entry = ctrls.setdefault(ctl, {"methods": {}, "contracts": []})
                if action not in entry["methods"]:
                    entry["methods"][action] = (cid, body)
                entry["contracts"].append(cid)
                plan[cid] = {"action": "IMPLEMENT", "reason": "recognised recipe"}
            else:
                plan[cid] = {"action": "IMPLEMENT", "reason": "literal JSON closure"}
            used_helpers[cid] = chain
            route_lines.append((c, chain, handler_ref if h["type"] == "closure" else f"{handler_ref}"))
        except Unsupported as exc:
            plan[cid] = {"action": "STUB", "reason": str(exc)}
            hn = h.get("controller")
            ctl = ident(short_name(hn)) if hn else "InlineStubs"
            action = ident(h.get("action") or f"route_{cid}")
            entry = ctrls.setdefault(ctl, {"methods": {}, "contracts": []})
            stub = [f"    // CODEBRIDGE:STUB {cid}", f"    // reason: {comment(str(exc))}",
                    f"    // PHP source: {comment(c['source_path'])}:{c['source_line']}",
                    f"    throw notImplemented({js('Not implemented: ' + comment(str(exc), 120))});"]
            entry["methods"].setdefault(action, (cid, stub)); entry["contracts"].append(cid)
            chain = ["authenticate"] if c["authentication"] == "REQUIRED" else []
            route_lines.append((c, chain, f"{ctl}.{action}"))
    # ---- static server -------------------------------------------------------
    user = ctx.auth_model or "User"
    for rel, text in STATIC_SERVER.items():
        if not ctx.auth_model and rel.endswith(("authenticate.js", "tokens.js")):
            continue
        w.write("server/" + rel, text.replace("@@MOUNT@@", mount_prefix or "/").replace("@@USER@@", user))
    w.write("server/src/config/env.js", ENV_JS)
    # ---- models ---------------------------------------------------------------
    model_notes = []
    for mid, m in ctx.models.items():
        text, n = gen_model(m, ctx.tables.get(m["table"]), ctx.models, ctx.models_by_table); model_notes += n
        w.write(f"server/src/models/{ident(m['name'])}.js", text)
    w.write("server/src/models/index.js", "".join(f"import './{ident(m['name'])}.js';\n" for m in ctx.models.values()) or "// no models\n")
    # ---- resources ------------------------------------------------------------
    for rn, spec in ctx.resources.items():
        text, _, rnotes = gen_resource(rn, spec); notes += rnotes
        w.write(f"server/src/resources/{ident(rn)}.js", text)
    # ---- validators -----------------------------------------------------------
    w.write("server/src/validators/index.js", "import { z } from 'zod';\n\nconst looseBoolean = z.union([z.boolean(), z.literal(1), z.literal(0), z.enum(['1', '0', 'true', 'false'])])\n"
            "  .transform((v) => v === true || v === 1 || v === '1' || v === 'true');\n\n" + "\n\n".join(validators) + ("\n" if validators else "export {};\n"))
    # ---- controllers ----------------------------------------------------------
    names_models, names_res = {short_name(i) for i in ctx.models}, set(ctx.resources)
    for ctl, entry in sorted(ctrls.items()):
        methods = []
        for action, (cid, lines) in sorted(entry["methods"].items()):
            methods.append(f"  async {action}(req, res) {{\n" + "\n".join(lines) + "\n  },")
        text = "export const " + f"{ctl} = {{\n" + "\n".join(methods) + "\n};\n"
        imports = ["import { HttpError, notImplemented } from '../lib/httpError.js';"]
        for mname in sorted(names_models):
            if re.search(rf"\b{mname}\b", text): imports.append(f"import {{ {mname} }} from '../models/{mname}.js';")
        for rn in sorted(names_res):
            if re.search(rf"\b{rn}\b", text): imports.append(f"import {{ {rn} }} from '../resources/{rn}.js';")
        if "bcrypt." in text: imports.append("import bcrypt from 'bcryptjs';")
        if "issueToken" in text: imports.append("import { issueToken } from '../lib/tokens.js';")
        if "AccessToken" in text: imports.append("import { AccessToken } from '../models/AccessToken.js';")
        if "pick(" in text: imports.append("import { pick } from '../lib/pick.js';")
        if "paginate(" in text: imports.append("import { paginate } from '../lib/paginate.js';")
        if "env." in text: imports.append("import { env } from '../config/env.js';")
        w.write(f"server/src/controllers/{ctl}.js", "\n".join(imports) + "\n\n" + text)
    # ---- routes ---------------------------------------------------------------
    r_imports = ["import { Router } from 'express';", "import { asyncHandler } from '../lib/asyncHandler.js';"]
    rl = []
    for c, chain, hr in route_lines:
        verb = c["method"].lower()
        handler = hr if hr.startswith("(") else f"asyncHandler({hr})"
        mws = ", ".join(chain + [handler])
        rl.append(f"// route:{c['contract_id']}\nrouter.{verb}({js(rel_path(c))}, {mws});")
    text = "\n".join(rl)
    for mw, imp in [("authenticate", "import { authenticate } from '../middleware/authenticate.js';"), ("requireRole(", "import { requireRole } from '../middleware/requireRole.js';"),
                    ("rateLimit(", "import { rateLimit } from '../middleware/rateLimit.js';"), ("validate(", "import { validate } from '../middleware/validate.js';"),
                    ("bind(", "import { bind } from '../middleware/bind.js';")]:
        if mw in text: r_imports.append(imp)
    if re.search(r"\b(?:unique|exists)\(", text): r_imports.append("import { unique, exists } from '../middleware/asyncChecks.js';")
    if "s_" in text: r_imports.append("import * as schemas from '../validators/index.js';"); text = re.sub(r"\b(s_[0-9a-f]{16})\b", r"schemas.\1", text)
    for mname in sorted(names_models):
        if re.search(rf"\b{mname}\b", text): r_imports.append(f"import {{ {mname} }} from '../models/{mname}.js';")
    for ctl in sorted(ctrls):
        if re.search(rf"\b{ctl}\b", text): r_imports.append(f"import {{ {ctl} }} from '../controllers/{ctl}.js';")
    w.write("server/src/routes/api.js", "\n".join(r_imports) + "\n\nexport const router = Router();\nexport const apiRouter = router;\n\n" + text + "\n")
    # ---- tests, packaging, deployment ----------------------------------------
    protected = [(c["method"], re.sub(r":\w+", "000000000000000000000000", rel_path(c))) for c, ch, _ in route_lines if "authenticate" in ch]
    w.write("server/tests/security.test.js", f"""import test from 'node:test';
import assert from 'node:assert/strict';
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET ??= 'test-only-secret-test-only-secret-0000';
process.env.MONGODB_URI ??= 'mongodb://127.0.0.1:1/unused';
const {{ createApp }} = await import('../src/app.js');
const request = (await import('supertest')).default;
const app = createApp();

for (const [method, path] of {js(protected)}) {{
  test(`${{method}} ${{path}} requires authentication`, async () => {{
    const res = await request(app)[method.toLowerCase()]('{mount_prefix}' + path);
    assert.equal(res.status, 401);
  }});
}}
test('health endpoint is public', async () => assert.equal((await request(app).get('/healthz')).status, 200));
test('unknown routes return 404 JSON', async () => assert.equal((await request(app).get('/nope')).status, 404));
test('malformed JSON is rejected with 400', async () => {{
  const res = await request(app).post('/healthz').set('Content-Type', 'application/json').send('{{bad');
  assert.equal(res.status, 400);
}});
""")
    sp = json.loads(json.dumps(SERVER_PACKAGE).replace("@@NAME@@", name)); cp = json.loads(json.dumps(CLIENT_PACKAGE).replace("@@NAME@@", name))
    w.write("server/package.json", json.dumps(sp, indent=2) + "\n"); w.write("client/package.json", json.dumps(cp, indent=2) + "\n")
    for rel, text in _client([c for c in src["contracts"]], plan, mount_prefix, name).items():
        w.write("client/" + rel, text)
    w.write("client/Dockerfile", CLIENT_DOCKERFILE); w.write("client/nginx.conf", NGINX.replace("@@MOUNT@@", mount_prefix or "/api"))
    w.write("server/Dockerfile", DOCKERFILE_SERVER); w.write("server/.dockerignore", "node_modules\n.env\ntests\n")
    w.write("docker-compose.yml", COMPOSE.replace("@@DB@@", name.replace("-", "_")))
    w.write(".github/workflows/ci.yml", CI)
    w.write(".gitignore", "node_modules\n.env\ndist\n*.log\n")
    env_ex = "# Copy to .env and fill in. Never commit real secrets.\nNODE_ENV=development\nPORT=3000\nMONGODB_URI=mongodb://127.0.0.1:27017/" + name.replace("-", "_") + "\n# generate with: openssl rand -hex 32\nJWT_SECRET=\nCORS_ORIGINS=http://localhost:5173\nMONGO_ROOT_USER=\nMONGO_ROOT_PASSWORD=\n"
    w.write("server/.env.example", env_ex); w.write(".env.example", env_ex)
    # ---- parity loop -----------------------------------------------------------
    parity = None
    if run_parity_check:
        try:
            parity = run_parity(source_root, output_root / "server")
        except (ValueError, OSError) as exc:
            parity = {"error": str(exc)}
    counts = {a: sum(p["action"] == a for p in plan.values()) for a in ("IMPLEMENT", "STUB", "EXCLUDE")}
    w.write("MIGRATION_REPORT.md", _report(name, gate, plan, src, notes + model_notes, parity, ctx))
    w.write("DEPLOYMENT.md", _deployment(name))
    w.write("README.md", f"# {name}\n\nGenerated by CodeBridge AI from a reviewed PHP/Laravel analysis.\n\n* `server/` Express + Mongoose API\n* `client/` React (Vite) client\n* `MIGRATION_REPORT.md` — what was implemented, stubbed or excluded, and why\n* `DEPLOYMENT.md` — manual, human-approved deployment checklist\n\n**Review before use:** stubs return 501; parity results are static evidence, not proof of equivalence.\n")
    manifest = {"engine": "mern_generator", "engine_version": ENGINE_VERSION, "status": "GENERATED", "project_name": name,
                "source_fingerprint": gate["source_fingerprint"], "approval": {"reviewer": approval["reviewer"], "reason": approval["reason"]},
                "plan": plan, "counts": counts, "files": dict(sorted(w.files.items())), "gate": gate,
                "parity": None if parity is None else ({"error": parity["error"]} if "error" in parity else {"metrics": parity["metrics"], "report_fingerprint": parity["report_fingerprint"]}),
                "policy": {"deployment_authorized": False, "auto_approval": False, "human_review_required": True,
                           "note": "Files only. Nothing was built, installed, executed or deployed."}}
    (output_root / "GENERATION_MANIFEST.json").write_text(json.dumps(manifest, indent=2, default=str) + "\n", encoding="utf-8")
    manifest["parity_report"] = parity
    return manifest


def _report(name, gate, plan, src, notes, parity, ctx) -> str:
    by_id = {c["contract_id"]: c for c in src["contracts"]}
    rows = "\n".join(f"| {by_id[i]['method']} | `{by_id[i]['uri']}` | {p['action']} | {p['reason'].replace('|', '/')} |" for i, p in plan.items())
    flags = "\n".join(f"* `{i}` {f['flag']} ({f['severity']})" for i, fl in ctx.risks.items() for f in fl if i in plan) or "* none"
    pm = parity["metrics"] if parity and "metrics" in parity else None
    par = (f"Static parity of the generated server against the PHP contracts: equivalent {pm['verified_equivalent']}, mismatch {pm['verified_mismatch']}, partial {pm['partially_verified']}, "
           f"not implemented {pm['not_implemented']}, unverified {pm['unverified']} of {pm['total_source_contracts']}. This is structural evidence, not proof of equivalence.") if pm else "Parity check was not run."
    return f"""# Migration report — {name}

Source fingerprint: `{gate['source_fingerprint']}`

## Endpoint plan
| Method | Path | Action | Reason |
|---|---|---|---|
{rows}

## Security findings carried over from analysis
{flags}

## Parity
{par}

## Intentional divergences
""" + "\n".join(f"* {d}" for d in INTENTIONAL_DIVERGENCES) + "\n\n## Notes requiring review\n" + ("\n".join(f"* {n}" for n in notes) or "* none") + "\n"


def _deployment(name) -> str:
    return f"""# Deployment checklist — {name}

CodeBridge AI generated these files only. **Nothing has been built or deployed.** A human must complete every step.

1. Review `MIGRATION_REPORT.md`; resolve or accept every STUB and every security finding.
2. Install and test: `cd server && npm ci && npm test`; run an `npm audit`.
3. Run differential tests against the original application in an isolated environment with disposable data (V5.23 runtime harness).
4. Create secrets outside the repository: `JWT_SECRET` (>= 32 random chars), `MONGO_ROOT_USER`, `MONGO_ROOT_PASSWORD`. Compose refuses to start without them.
5. Put the stack behind TLS (reverse proxy / load balancer); set `CORS_ORIGINS` to the exact client origin(s).
6. Migrate data with a reviewed script; existing bcrypt password hashes remain valid.
7. Deploy with `docker compose up --build` in a staging environment first; record approval before production.
"""
