"""V5.23 — Static analysis of a migrated Express/Mongoose (MERN) target.

Extracts, from a target project's JavaScript/TypeScript sources (never executed):
routes (with ``app.use``/``router.use`` mount prefixes), middleware chains, handler bodies,
zod/Joi validation schemas, HTTP statuses, response shapes, database operations,
side-effect indicators and numeric business rules.

Every record carries file/line evidence. Anything not resolvable is reported as
unresolved so the parity engine can classify it as UNVERIFIED instead of guessing.
"""
from __future__ import annotations

from pathlib import Path, PurePosixPath
import os
import re

from app.php_source import (Raw, line_of, mask_comments, match_delim, safe_read, split_top_level)

ENGINE_VERSION = "5.23.0"
JS_SUFFIXES = {".js", ".mjs", ".cjs", ".ts"}
SKIP_DIRS = {".git", "node_modules", "dist", "build", "coverage", ".next", "tests", "test", "__tests__", "__mocks__"}
MAX_FILES, MAX_BYTES = 5000, 500_000
VERBS = ("get", "post", "put", "patch", "delete")
READ_OPS = {"find", "findone", "findbyid", "countdocuments", "exists", "aggregate", "distinct", "estimateddocumentcount", "populate"}
WRITE_OPS = {"create", "insertmany", "insertone", "updateone", "updatemany", "findbyidandupdate", "findoneandupdate",
             "save", "replaceone", "bulkwrite", "findoneandreplace"}
DELETE_OPS = {"deleteone", "deletemany", "findbyidanddelete", "findoneanddelete", "remove", "findbyidandremove"}
EFFECTS = {
    "password_hashing": r"\b(?:bcrypt(?:js)?\s*\.\s*hash(?:Sync)?|argon2\s*\.\s*hash|hashPassword)\b",
    "password_check": r"\b(?:bcrypt(?:js)?\s*\.\s*compare(?:Sync)?|argon2\s*\.\s*verify|comparePassword)\b",
    "token_issue": r"\b(?:jwt\s*\.\s*sign|issueToken|signToken|generateToken|createToken)\b",
    "token_revoke": r"\b(?:revokeToken|AccessToken\s*\.\s*delete\w*|blacklist\w*|tokens?\s*\.\s*delete\w*)\b",
    "mail_or_notification": r"\b(?:sendMail|nodemailer|sendEmail|notify\w*)\b",
    "event_dispatch": r"\.\s*emit\s*\(|\bqueue\s*\.\s*add\s*\(|\bdispatch\s*\(",
    "outbound_http": r"\b(?:axios|got|fetch)\s*(?:\.|\()",
    "file_storage": r"\b(?:multer|putObject|writeFile\w*|createWriteStream)\b",
    "cache": r"\b(?:redis|cache)\s*\.\s*(?:get|set|del)\w*\s*\(",
    "transaction": r"\b(?:startSession|withTransaction)\b",
}


# ------------------------------------------------------------------ JS literals
def parse_js(text: str, depth: int = 0):
    text = text.strip()
    if depth > 10 or not text:
        return Raw(text)
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"`" and "${" not in text:
        return text[1:-1]
    low = text.lower()
    if low in {"true", "false"}:
        return low == "true"
    if low in {"null", "undefined"}:
        return None
    if re.fullmatch(r"-?\d+(?:\.\d+)?", text):
        return float(text) if "." in text else int(text)
    if text.startswith("[") and text.endswith("]") and match_delim(text, 0) == len(text) - 1:
        return [parse_js(p, depth + 1) for p in split_top_level(text[1:-1])]
    if text.startswith("{") and text.endswith("}") and match_delim(text, 0) == len(text) - 1:
        out = {}
        for item in split_top_level(text[1:-1]):
            if item.startswith("..."):
                out[item] = Raw(item); continue
            parts = split_top_level(item, ":")
            key = parts[0].strip()
            if len(parts) == 1:
                out[key] = Raw(key)  # shorthand property
            else:
                k = parse_js(key, depth + 1)
                out[k if isinstance(k, str) else key] = parse_js(":".join(parts[1:]), depth + 1)
        return out
    return Raw(text)


def js_chain(expr: str) -> tuple[str, list[tuple[str, str]]]:
    """``z.string().min(8)`` -> ("z", [("string",""),("min","8")])."""
    m = re.match(r"\s*([A-Za-z_$][\w$]*)", expr)
    if not m:
        return "", []
    calls, i = [], m.end()
    pat = re.compile(r"\s*\.\s*([A-Za-z_$][\w$]*)\s*(\()?")
    while True:
        c = pat.match(expr, i)
        if not c:
            break
        if not c.group(2):          # property access such as the `.coerce` in z.coerce.date()
            calls.append((c.group(1), ""))
            i = c.end()
            continue
        close = match_delim(expr, c.end() - 1)
        if close is None:
            break
        calls.append((c.group(1), expr[c.end():close]))
        i = close + 1
    return m.group(1), calls


# ---------------------------------------------------------------- file inventory
def _iter_files(root: Path):
    seen = 0
    for cur, dirs, names in os.walk(root, followlinks=False):
        here = Path(cur)
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not (here / d).is_symlink())
        for n in sorted(names):
            p = here / n
            if p.suffix in JS_SUFFIXES and not p.name.endswith((".test.js", ".spec.js", ".test.ts", ".spec.ts")) \
                    and not p.is_symlink():
                yield p.relative_to(root).as_posix()
                seen += 1
                if seen >= MAX_FILES:
                    return


def _imports(text: str, rel: str, files: set[str]) -> dict[str, tuple[str, str]]:
    """local name -> (resolved relative file, imported name | 'default' | '*')."""
    out: dict[str, tuple[str, str]] = {}
    def resolve(spec: str) -> str | None:
        if not spec.startswith("."):
            return None
        base = PurePosixPath(rel).parent
        parts: list[str] = []
        for seg in (base / spec).parts:
            if seg == "..":
                if parts: parts.pop()
            elif seg != ".":
                parts.append(seg)
        cand = "/".join(parts)
        for suffix in ("", ".js", ".mjs", ".cjs", ".ts", "/index.js", "/index.ts"):
            if cand + suffix in files:
                return cand + suffix
        return None
    for m in re.finditer(r"import\s+(?:(\w+)\s*,?\s*)?(?:\{([^}]*)\}|\*\s+as\s+(\w+))?\s*from\s*['\"]([^'\"]+)['\"]", text):
        target = resolve(m.group(4))
        if not target:
            continue
        if m.group(1): out[m.group(1)] = (target, "default")
        if m.group(3): out[m.group(3)] = (target, "*")
        for part in (m.group(2) or "").split(","):
            a, _, b = part.strip().partition(" as ")
            if a.strip(): out[(b or a).strip()] = (target, a.strip())
    for m in re.finditer(r"(?:const|let|var)\s+(?:(\w+)|\{([^}]*)\})\s*=\s*require\(\s*['\"]([^'\"]+)['\"]\s*\)", text):
        target = resolve(m.group(3))
        if not target:
            continue
        if m.group(1): out[m.group(1)] = (target, "default")
        for part in (m.group(2) or "").split(","):
            a, _, b = part.strip().partition(":")
            if a.strip(): out[(b or a).strip()] = (target, a.strip())
    return out


_FN_PATTERNS = [
    re.compile(r"(?:export\s+(?:default\s+)?)?(?:async\s+)?function\s*\*?\s*(\w+)\s*\("),
    re.compile(r"(?:export\s+)?(?:const|let|var)\s+(\w+)\s*(?::[^=]+)?=\s*(?:async\s*)?(?:function\s*\w*\s*)?\("),
    re.compile(r"(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\w+\s*=>"),
    re.compile(r"^[ \t]*(?:static\s+)?(?:async\s+)?(\w+)\s*\(", re.M),
    re.compile(r"^[ \t]*(\w+)\s*:\s*(?:async\s*)?(?:function\s*\w*\s*)?\(", re.M),
]
_KEYWORDS = {"if", "for", "while", "switch", "catch", "function", "return", "await", "super", "constructor", "require"}


def find_functions(text: str) -> list[dict]:
    """Function-like declarations with body text and line, owner when defined inside an object/class."""
    code = mask_comments(text, hash_comments=False)
    owners = []
    for m in re.finditer(r"(?:(?:const|let|var)\s+(\w+)\s*=\s*\{|class\s+(\w+)[^{]*\{|export\s+default\s*\{)", code):
        brace = code.find("{", m.start())
        end = match_delim(code, brace)
        if end:
            owners.append((m.group(1) or m.group(2) or "default", brace, end))
    funcs, seen = [], set()
    for i, pat in enumerate(_FN_PATTERNS):
        for m in pat.finditer(code, 0):
            name = m.group(1)
            if name in _KEYWORDS or (m.start(), name) in seen:
                continue
            open_paren = code.find("(", m.start()) if i != 2 else -1
            if i == 2:
                arrow = code.find("=>", m.end() - 3)
                params, body_start = "", arrow + 2
            else:
                close = match_delim(code, open_paren)
                if close is None:
                    continue
                params = code[open_paren + 1:close]
                after = re.match(r"\s*(?::\s*[\w<>\[\]|?. ]+)?\s*(=>)?\s*", code[close + 1:])
                body_start = close + 1 + after.end()
                if i in (1,) and not after.group(1) and not code[body_start - 1:body_start + 1].strip().startswith("{") and code[body_start:body_start + 1] != "{":
                    continue  # call expression, not a function
                if i in (3, 4) and code[body_start:body_start + 1] != "{" and not after.group(1):
                    continue
            rest = code[body_start:body_start + 1]
            while body_start < len(code) and code[body_start].isspace():
                body_start += 1
            if code[body_start:body_start + 1] == "{":
                end = match_delim(code, body_start)
                if end is None: continue
                body = text[body_start + 1:end]
            else:
                end = body_start
                depth = 0
                while end < len(code) and not (depth == 0 and code[end] in ";\n"):
                    depth += code[end] in "([{"
                    depth -= code[end] in ")]}"
                    end += 1
                body = "return " + text[body_start:end]
            owner = next((o[0] for o in owners if o[1] < m.start() < o[2]), None)
            seen.add((m.start(), name))
            funcs.append({"name": name, "owner": owner, "params": params.strip(), "body": body,
                          "line": line_of(text, m.start()), "start": m.start()})
    return sorted(funcs, key=lambda f: f["start"])


# --------------------------------------------------------------- body analysis
def _num(x: str):
    return float(x) if "." in x else int(x)


def extract_rules(body: str, php: bool = False) -> list[dict]:
    """Numeric business rules (assignments and comparisons) with canonical factors; deterministic."""
    code = mask_comments(body, hash_comments=php)
    rules = []
    var = r"\$?[\w]+(?:(?:->|\.)[\w]+)*(?:\[[^\]]+\])?"
    num = r"-?\d+(?:\.\d+)?"
    for m in re.finditer(rf"({var})\s*(===|!==|==|!=|>=|<=|>|<)\s*({num})\b", code):
        key = re.search(r"\[\s*['\"]?(\w+)['\"]?\s*\]$", m.group(1))
        subject = key.group(1) if key else re.split(r"->|\.", m.group(1))[-1].strip("$")
        op = {"===": "==", "!==": "!="}.get(m.group(2), m.group(2))
        if subject.lower() in {"status", "length", "statuscode"}:
            continue
        rules.append({"kind": "comparison", "subject": subject.replace("_", "").lower(), "operator": op,
                      "value": _num(m.group(3)), "text": m.group(0).strip(), "line": body.count("\n", 0, m.start()) + 1})
    for m in re.finditer(rf"(?:^|[;{{}}\n])\s*(?:(?:const|let|var)\s+)?\$?(\w+)\s*=\s*([^;=\n][^;\n]*);", code):
        rhs = m.group(2).strip()
        if not re.search(r"(?<![\w.])\d+(?:\.\d+)?", rhs) or re.search(r"['\"`]|=>|\(\s*\)", rhs):
            continue
        nums = [_num(n) for n in re.findall(r"(?<![\w.$])\d+(?:\.\d+)?", rhs)]
        if not [n for n in nums if n not in (0, 1)] and not re.search(r"[*/]", rhs):
            continue
        factor = None
        f = re.fullmatch(rf"\(?\s*{var}\s*\)?\s*\*\s*({num})(?:\s*/\s*({num}))?\s*|\s*({num})\s*\*\s*\(?\s*{var}\s*\)?\s*|\s*{var}\s*/\s*({num})\s*", rhs)
        if f:
            if f.group(1): factor = _num(f.group(1)) / (_num(f.group(2)) if f.group(2) else 1)
            elif f.group(3): factor = _num(f.group(3))
            elif f.group(4): factor = 1 / _num(f.group(4))
        rules.append({"kind": "assignment", "subject": m.group(1).replace("_", "").lower(), "factor": factor,
                      "literals": sorted(set(nums)), "text": f"{m.group(1)} = {rhs}", "line": body.count("\n", 0, m.start()) + 1})
    return rules


def analyse_body(body: str, filename: str, base_line: int) -> dict:
    code = mask_comments(body, hash_comments=False)
    statuses = sorted({int(x) for x in re.findall(r"\.\s*status\s*\(\s*(\d{3})\s*\)", code)} |
                      {int(x) for x in re.findall(r"\bsendStatus\s*\(\s*(\d{3})", code)} |
                      {int(x) for x in re.findall(r"new\s+(?:HttpError|ApiError|AppError|createError)\w*\s*\(\s*(\d{3})", code)} |
                      {int(x) for x in re.findall(r"\bcreateError\s*\(\s*(\d{3})", code)})
    implicit_ok = bool(re.search(r"\bres\s*\.\s*json\s*\(", code))
    responses = []
    for m in re.finditer(r"\bres\s*(?:\.\s*status\s*\(\s*(\d{3})\s*\))?\s*\.\s*(json|send|end|sendStatus)\s*\(", code):
        close = match_delim(code, m.end() - 1)
        arg = body[m.end():close].strip() if close else ""
        responses.append({"status": int(m.group(1)) if m.group(1) else (int(arg) if m.group(2) == "sendStatus" and arg.isdigit() else 200),
                          "via": m.group(2), "argument": arg[:400], "parsed": parse_js(arg) if arg and m.group(2) == "json" else None,
                          "line": base_line + body.count("\n", 0, m.start())})
    db = []
    for m in re.finditer(r"\b([A-Z][A-Za-z0-9_]*)\s*\.\s*(\w+)\s*\(", code):
        op = m.group(2).lower()
        kind = "read" if op in READ_OPS else "write" if op in WRITE_OPS else "delete" if op in DELETE_OPS else None
        if kind:
            db.append({"model": m.group(1), "operation": m.group(2), "kind": kind, "line": base_line + body.count("\n", 0, m.start())})
    for m in re.finditer(r"\b(\w+)\s*\.\s*(save|deleteOne|remove)\s*\(", code):
        db.append({"model": None, "operation": m.group(2), "kind": "delete" if m.group(2) != "save" else "write", "instance": m.group(1),
                   "line": base_line + body.count("\n", 0, m.start())})
    soft = bool(re.search(r"\b(?:deleted_?at|isDeleted|deletedAt)\b", code))
    effects = sorted(k for k, pat in EFFECTS.items() if re.search(pat, code))
    owner_checks = [m.group(0)[:160] for m in re.finditer(
        r"(?:String\()?[\w.\[\]?']*\.(\w*[uU]ser_?[iI]d|owner\w*|author\w*)\)?\s*(?:!==|===|!=|==)\s*(?:String\()?(?:req|request)\s*\.\s*user\s*\??\.\s*_?id\)?|"
        r"(?:String\()?(?:req|request)\s*\.\s*user\s*\??\.\s*_?id\)?\s*(?:!==|===|!=|==)\s*(?:String\()?[\w.\[\]?']*\.(\w*[uU]ser_?[iI]d|owner\w*|author\w*)\)?", code)]
    role_checks = [{"roles": [m.group(2)], "operator": m.group(1)} for m in re.finditer(
        r"req\s*\.\s*user\s*\??\.\s*role\s*(===|!==|==|!=)\s*['\"](\w+)['\"]", code)]
    for m in re.finditer(r"\[([^\]]+)\]\s*\.\s*includes\s*\(\s*req\s*\.\s*user\s*\??\.\s*role", code):
        role_checks.append({"roles": re.findall(r"['\"](\w+)['\"]", m.group(1)), "operator": "includes"})
    call_code = re.sub(r"\bnew\s+\w+", "new", code)  # constructors (new HttpError(...)) are not function calls
    calls = sorted({m.group(1) for m in re.finditer(r"(?<![\w.])(\w+)\s*\(", call_code) if m.group(1) not in _KEYWORDS | {"res", "String", "Number", "Boolean", "Array", "Object", "Date", "Math", "JSON", "Promise", "Error", "next", "async"}} |
                   {f"{m.group(1)}.{m.group(2)}" for m in re.finditer(r"\b([a-z]\w*(?:Service|Controller|Repository|Repo|Helper|Utils?))\s*\.\s*(\w+)\s*\(", call_code)})
    return {"statuses": statuses, "responses": responses, "db_operations": db, "soft_delete_marker": soft,
            "side_effects": effects, "owner_checks": owner_checks, "role_checks": role_checks, "calls": calls,
            "rules": extract_rules(body), "is_stub": bool(re.search(r"\b501\b|not\s*implemented|NotImplemented", body, re.I)),
            "inline_validation": sorted(set(re.findall(r"\b(\w+)\s*\.\s*(?:parse|safeParse|validate(?:Async)?)\s*\(\s*req\s*\.\s*body", code))),
            "file": filename, "implicit_200": implicit_ok}


def _parse_schema_field(expr: str, lib: str) -> dict:
    base, calls = js_chain(expr)
    field = {"type": "any", "required": lib == "zod", "nullable": False, "constraints": {}, "expression": expr.strip()[:200]}
    c = field["constraints"]
    names = [n for n, _ in calls]
    first = calls[0][0] if calls else ""
    if lib == "zod":
        field["type"] = {"string": "string", "number": "number", "boolean": "boolean", "date": "date", "array": "array",
                         "enum": "string", "object": "object", "any": "any", "unknown": "any", "bigint": "number"}.get(first, "any")
        if re.search(r"z\s*\.\s*coerce\s*\.\s*number", expr): field["type"] = "number"
        if re.search(r"z\s*\.\s*coerce\s*\.\s*date", expr): field["type"] = "date"
        if first == "enum":
            vals = parse_js(calls[0][1]); c["in"] = [str(v) for v in vals] if isinstance(vals, list) else []
        if first == "array":
            field["items"] = calls[0][1].strip()
        if "coerce" == first and len(calls) > 1:
            field["type"] = {"number": "number", "date": "date", "boolean": "boolean", "string": "string"}.get(calls[1][0], field["type"])
        if any(n in {"optional", "nullish"} for n in names) or "default" in names: field["required"] = False
        if any(n in {"nullable", "nullish"} for n in names): field["nullable"] = True
    else:  # joi / yup
        field["type"] = {"string": "string", "number": "number", "boolean": "boolean", "date": "date", "array": "array",
                         "object": "object", "any": "any"}.get(first, "any")
        field["required"] = "required" in names
        if "allow" in names and any("null" in a for n, a in calls if n == "allow"): field["nullable"] = True
        for n, a in calls:
            if n in {"valid", "oneOf"}:
                c["in"] = [str(parse_js(x)) for x in split_top_level(a)]
    for n, a in calls:
        v = parse_js(a) if a.strip() else None
        if n in {"min", "max"} and isinstance(v, (int, float)): c[n] = v
        elif n == "length" and isinstance(v, (int, float)): c["size"] = v
        elif n == "int" or n == "integer": field["type"] = "integer"
        elif n in {"email", "url", "uuid"}: c[n] = True
        elif n == "regex" or n == "pattern":
            rm = re.match(r"\s*new\s+RegExp\(\s*(\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*')", a)
            c["regex"] = rm.group(1)[1:-1] if rm else a.strip()[:120]
    return field


def find_schemas(text: str, filename: str) -> dict:
    schemas = {}
    code = mask_comments(text, hash_comments=False)
    for m in re.finditer(r"(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(z|Joi|yup)\s*\.\s*object\s*\(\s*\{", code):
        brace = code.find("{", m.end() - 1)
        end = match_delim(code, brace)
        if end is None:
            continue
        lib = "zod" if m.group(2) == "z" else m.group(2).lower()
        fields = {}
        for item in split_top_level(code[brace + 1:end]):
            parts = split_top_level(item, ":")
            if len(parts) >= 2:
                key = parse_js(parts[0]) if parts[0].strip()[:1] in "'\"" else parts[0].strip()
                fields[str(key)] = _parse_schema_field(":".join(parts[1:]), lib)
        schemas[m.group(1)] = {"lib": lib, "fields": fields, "file": filename, "line": line_of(text, m.start())}
    return schemas


# --------------------------------------------------------------------- project
def analyze_express_project(root: str | Path) -> dict:
    root = Path(root).resolve(strict=True)
    files, texts, skipped = [], {}, []
    for rel in _iter_files(root):
        text = safe_read(root, rel, MAX_BYTES)
        if text is None:
            skipped.append({"file": rel, "reason": "unreadable, symlink or larger than size limit"})
        else:
            files.append(rel); texts[rel] = text
    fileset = set(files)
    imports = {rel: _imports(t, rel, fileset) for rel, t in texts.items()}
    funcs = {rel: find_functions(t) for rel, t in texts.items()}
    schemas = {}
    for rel, t in texts.items():
        for name, s in find_schemas(t, rel).items():
            schemas[f"{rel}:{name}"] = s
            schemas.setdefault(name, s)
    all_funcs = [(rel, f) for rel, fs in funcs.items() for f in fs]

    def locate(rel: str, ref: str) -> dict | None:
        """Resolve a handler/middleware reference like ``create`` or ``PostController.create``."""
        owner, _, member = ref.rpartition(".")
        target_file, imported = rel, member or ref
        if owner:
            if owner in imports[rel]:
                target_file, imported = imports[rel][owner][0], member
            else:
                target_file = rel
        elif ref in imports[rel]:
            target_file, imported = imports[rel][ref][0], imports[rel][ref][1]
            if imported in ("default", "*"):
                imported = PurePosixPath(target_file).stem
        cands = [f for f in funcs.get(target_file, []) if f["name"] == imported]
        if owner:
            cands = [f for f in cands if f["owner"] in (owner, None, "default") or True]
        if not cands and imported == PurePosixPath(target_file).stem:
            cands = [f for f in funcs.get(target_file, []) if f["name"] in {"default", "handler"}]
        return {"file": target_file, **cands[0]} if cands else None

    def unwrap(expr: str) -> str:
        e = expr.strip()
        m = re.fullmatch(r"(?:asyncHandler|catchAsync|wrap|tryCatch|expressAsyncHandler)\s*\((.*)\)", e, re.S)
        return unwrap(m.group(1)) if m else e

    # mounts: file -> list of (prefix, child file)
    mounts: dict[str, list[tuple[str, str]]] = {}
    for rel, t in texts.items():
        code = mask_comments(t, hash_comments=False)
        for m in re.finditer(r"\b(\w+)\s*\.\s*use\s*\(\s*(['\"])([^'\"]*)\2\s*,\s*([^)]*?)\)", code):
            ident = re.split(r"[,\s]", m.group(4).strip())[-1] if m.group(4).strip() else ""
            child = imports[rel].get(ident, (None,))[0]
            if child is None:
                child = next((tf for tf, _ in [(rel, 0)] if re.search(rf"\b(?:const|let)\s+{re.escape(ident)}\s*=\s*(?:express\.)?Router\(", t)), None)
            if child:
                mounts.setdefault(rel, []).append((m.group(3), child))
    routers_files = {c for ms in mounts.values() for _, c in ms}
    roots = [f for f in files if re.search(r"\bexpress\s*\(\s*\)", texts[f]) and f not in routers_files] or \
            [f for f in files if f in mounts and f not in routers_files]
    prefix_of: dict[str, list[str]] = {}

    def walk(rel: str, prefix: str, seen: tuple = ()):
        prefix_of.setdefault(rel, []).append(prefix)
        for p, child in mounts.get(rel, []):
            if child not in seen and child != rel:
                walk(child, "/" + "/".join(x for x in [prefix.strip("/"), p.strip("/")] if x), seen + (rel,))
    for r in roots:
        walk(r, "")

    routes, unresolved = [], []
    for rel, t in texts.items():
        code = mask_comments(t, hash_comments=False)
        for m in re.finditer(r"\b(\w+)\s*\.\s*(get|post|put|patch|delete)\s*\(", code):
            if m.group(1) in {"axios", "http", "request", "supertest", "api", "client", "fetch", "map", "Map", "params", "headers", "cache", "redis"}:
                continue
            close = match_delim(code, m.end() - 1)
            args = split_top_level(t[m.end():close]) if close else []
            if len(args) < 2 or not re.fullmatch(r"['\"`][^'\"`]*['\"`]", args[0].strip()):
                continue
            path = args[0].strip()[1:-1]
            prefixes = prefix_of.get(rel) or ([""] if rel in roots else [None])
            mw, handler_expr = [], unwrap(args[-1])
            for a in args[1:-1]:
                if a.strip().startswith("["):
                    mw += split_top_level(a.strip()[1:-1])
                else:
                    mw.append(a.strip())
            for pre in prefixes:
                full = "/" + "/".join(x for x in [(pre or "").strip("/"), path.strip("/")] if x)
                handler = None
                if re.match(r"(?:async\s*)?(?:\(|function|\w+\s*=>)", handler_expr):
                    fm = re.match(r"(?:async\s*)?(?:function\s*\w*\s*)?\(([^)]*)\)\s*(?:=>)?\s*\{", handler_expr)
                    body = handler_expr[handler_expr.find("{") + 1:handler_expr.rfind("}")] if fm else "return " + handler_expr.split("=>", 1)[-1]
                    handler = {"ref": "<inline>", "file": rel, "name": "<inline>", "body": body, "line": line_of(t, m.start())}
                else:
                    handler = locate(rel, handler_expr)
                    if handler is None:
                        unresolved.append({"file": rel, "line": line_of(t, m.start()), "reason": f"handler '{handler_expr[:80]}' not resolved"})
                    else:
                        handler["ref"] = handler_expr
                mws = []
                for expr in mw:
                    e = unwrap(expr)
                    name, calls = js_chain(e) if "." in e.split("(")[0] else (re.match(r"[\w.]+", e).group(0) if re.match(r"[\w.]+", e) else e, [])
                    nm = re.match(r"([\w.]+)\s*(?:\((.*)\))?$", e, re.S)
                    nm_name, nm_args = (nm.group(1), nm.group(2) or "") if nm else (e, "")
                    arg_values = [parse_js(a) for a in split_top_level(nm_args)] if nm_args else []
                    resolved = locate(rel, nm_name)
                    mws.append({"raw": e[:160], "name": nm_name, "arguments": arg_values,
                                "resolved": bool(resolved), "body": resolved["body"] if resolved else None,
                                "file": resolved["file"] if resolved else None, "line": resolved["line"] if resolved else None})
                routes.append({"method": m.group(2).upper(), "path": full, "middleware": mws, "handler": handler,
                               "mount_resolved": pre is not None, "source_path": rel, "source_line": line_of(t, m.start())})
    return {"engine": "target_analysis", "engine_version": ENGINE_VERSION, "root": str(root), "files_analysed": len(files),
            "skipped_files": skipped, "routes": routes, "schemas": schemas, "unresolved": unresolved,
            "functions": {f"{rel}:{f['name']}": {"file": rel, "line": f["line"], "owner": f["owner"], "body": f["body"]} for rel, f in all_funcs},
            "texts": texts, "imports": imports, "mount_roots": roots,
            "policy": "Static extraction only; target code is never executed."}
