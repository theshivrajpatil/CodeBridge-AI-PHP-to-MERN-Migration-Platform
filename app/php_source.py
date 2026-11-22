"""Hardened, dependency-free PHP source helpers shared by the V5.18+ engines.

Design rules
------------
* Never executes PHP and never imports project code.
* Every read is confined to the repository root (no traversal, no symlinks,
  bounded size). Callers receive ``None`` instead of an exception for unreadable
  files so one bad file cannot abort a whole analysis.
* Comment masking preserves byte offsets so line numbers stay exact.
* Parsing helpers are deliberately conservative: anything that is not a plain
  literal is returned as :class:`Raw` and must be treated as ``NEEDS_REVIEW``.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import os
import re
from typing import Iterator

MAX_READ_BYTES = 1_000_000
PHP_SUFFIXES = {".php", ".phtml", ".inc"}
SKIP_DIRS = {".git", ".svn", ".hg", "node_modules", "vendor", "dist", "build", ".venv",
             "venv", "__pycache__", "coverage", "storage", "cache", "logs", "tmp"}
IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
QUOTED = r"(?:'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\")"


# --------------------------------------------------------------------------- IO
def safe_read(root: str | Path, relative: str, max_bytes: int = MAX_READ_BYTES) -> str | None:
    """Read a text file strictly inside ``root``; return ``None`` when unsafe."""
    try:
        base = Path(root).resolve(strict=True)
        rel = PurePosixPath(str(relative).replace("\\", "/"))
        if rel.is_absolute() or ".." in rel.parts:
            return None
        candidate = base.joinpath(*rel.parts)
        if candidate.is_symlink():
            return None
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(base)
        if not resolved.is_file() or resolved.stat().st_size > max_bytes:
            return None
        return resolved.read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return None


def iter_php_files(root: str | Path, limit: int = 20_000) -> Iterator[str]:
    """Yield repository-relative POSIX paths of PHP files in deterministic order."""
    base = Path(root).resolve(strict=True)
    count = 0
    for current, dirs, names in os.walk(base, followlinks=False):
        here = Path(current)
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not (here / d).is_symlink())
        for name in sorted(names):
            path = here / name
            if path.suffix.lower() in PHP_SUFFIXES and not path.is_symlink() and path.is_file():
                yield path.relative_to(base).as_posix()
                count += 1
                if count >= limit:
                    return


# ---------------------------------------------------------------------- masking
def mask_comments(source: str, mask_strings: bool = False, hash_comments: bool = True) -> str:
    """Blank out comments (and optionally string bodies) preserving offsets."""
    out, i, n, state = list(source), 0, len(source), "code"
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if state == "code":
            if ch in "'\"`":
                state = {"'": "single", '"': "double", "`": "backtick"}[ch]
            elif (ch == "/" and nxt == "/") or (hash_comments and ch == "#" and nxt != "["):
                state = "line"; out[i] = " "
                if ch == "/" and i + 1 < n:
                    out[i + 1] = " "; i += 1
            elif ch == "/" and nxt == "*":
                state = "block"; out[i] = " "
                if i + 1 < n:
                    out[i + 1] = " "
                i += 1
        elif state in {"single", "double", "backtick"}:
            closer = {"single": "'", "double": '"', "backtick": "`"}[state]
            if ch == "\\":
                if mask_strings:
                    out[i] = " "
                    if i + 1 < n and source[i + 1] != "\n":
                        out[i + 1] = " "
                i += 1
            elif ch == closer:
                state = "code"  # delimiters stay visible so bracket matching remains balanced
            elif mask_strings and ch != "\n":
                out[i] = " "
        elif state == "line":
            if ch == "\n":
                state = "code"
            else:
                out[i] = " "
        elif state == "block":
            if ch == "*" and nxt == "/":
                out[i] = " "
                if i + 1 < n:
                    out[i + 1] = " "
                i += 1; state = "code"
            elif ch != "\n":
                out[i] = " "
        i += 1
    return "".join(out)


def line_of(source: str, position: int) -> int:
    return source.count("\n", 0, max(0, position)) + 1


def match_delim(code: str, open_pos: int) -> int | None:
    """Return the index of the delimiter closing ``code[open_pos]`` (``(``/``[``/``{``).

    ``code`` should already be comment-masked; strings are skipped here.
    """
    pairs = {"(": ")", "[": "]", "{": "}"}
    if open_pos >= len(code) or code[open_pos] not in pairs:
        return None
    stack, i, n = [], open_pos, len(code)
    while i < n:
        c = code[i]
        if c in "'\"`":
            quote = c; i += 1
            while i < n and code[i] != quote:
                i += 2 if code[i] == "\\" else 1
        elif c in pairs:
            stack.append(pairs[c])
        elif c in pairs.values():
            if not stack or stack.pop() != c:
                return None
            if not stack:
                return i
        i += 1
    return None


def split_top_level(text: str, separator: str = ",") -> list[str]:
    """Split on ``separator`` outside of nesting and quotes; drops empty tails."""
    parts, depth, start, i, n = [], 0, 0, 0, len(text)
    while i < n:
        c = text[i]
        if c in "'\"`":
            quote = c; i += 1
            while i < n and text[i] != quote:
                i += 2 if text[i] == "\\" else 1
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif depth == 0 and text.startswith(separator, i):
            parts.append(text[start:i].strip()); start = i + len(separator); i += len(separator) - 1
        i += 1
    tail = text[start:].strip()
    if tail:
        parts.append(tail)
    return [p for p in parts if p != ""]


# ---------------------------------------------------------------- literal values
@dataclass(frozen=True)
class Raw:
    """A PHP expression that is not a plain literal (must be reviewed by a human)."""
    text: str

    def __str__(self) -> str:
        return self.text


def unquote(text: str) -> str | None:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        body = text[1:-1]
        if text[0] == "'":
            return body.replace("\\'", "'").replace("\\\\", "\\")
        if "$" in body or "{$" in body:
            return None  # interpolated string: not a literal
        return body.replace('\\"', '"').replace("\\\\", "\\")
    return None


def parse_value(text: str, depth: int = 0):
    """Parse a PHP literal: string/number/bool/null/array; otherwise :class:`Raw`.

    Associative arrays become ``dict`` (insertion ordered); lists become ``list``.
    ``Foo::class`` becomes ``{"$class": "Foo"}``.
    """
    text = text.strip()
    if depth > 12 or not text:
        return Raw(text)
    literal = unquote(text)
    if literal is not None:
        return literal
    low = text.lower()
    if low in {"true", "false"}:
        return low == "true"
    if low == "null":
        return None
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    if re.fullmatch(r"-?\d+\.\d+", text):
        return float(text)
    m = re.fullmatch(rf"\\?({IDENT}(?:\\{IDENT})*)::class", text)
    if m:
        return {"$class": m.group(1)}
    inner = None
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1]
    else:
        m = re.fullmatch(r"array\s*\((.*)\)", text, re.S | re.I)
        if m:
            inner = m.group(1)
    if inner is not None:
        items = split_top_level(inner)
        keyed = [split_top_level(item, "=>") for item in items]
        if keyed and all(len(k) == 2 for k in keyed):
            result: dict = {}
            for key_text, value_text in keyed:
                key = parse_value(key_text, depth + 1)
                result[key if isinstance(key, (str, int)) else str(key)] = parse_value(value_text, depth + 1)
            return result
        return [parse_value(item, depth + 1) for item in items]
    return Raw(text)


def as_strings(value) -> list[str]:
    """Flatten a parsed value to the list of literal strings it contains."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [s for item in value for s in as_strings(item)]
    if isinstance(value, dict) and "$class" in value:
        return [value["$class"]]
    return []


# --------------------------------------------------------------- declarations
def find_classes(source: str) -> list[dict]:
    """Locate class-like declarations with their body spans (comment-masked scan)."""
    code = mask_comments(source, mask_strings=True)
    pattern = re.compile(
        rf"\b(?P<kind>class|interface|trait|enum)\s+(?P<name>{IDENT})"
        rf"(?:\s+extends\s+(?P<extends>[\\A-Za-z0-9_, ]+?))?"
        rf"(?:\s+implements\s+(?P<implements>[\\A-Za-z0-9_, ]+?))?\s*\{{")
    result = []
    for m in pattern.finditer(code):
        brace = code.find("{", m.end() - 1)
        end = match_delim(code, brace)
        if end is None:
            continue
        body = source[brace + 1:end]
        uses = [u.strip().lstrip("\\") for chunk in re.findall(r"^\s*use\s+([^;{]+);", mask_comments(body), re.M)
                for u in chunk.split(",") if u.strip()]
        result.append({
            "kind": m.group("kind"), "name": m.group("name"),
            "extends": [x.strip().lstrip("\\") for x in (m.group("extends") or "").split(",") if x.strip()],
            "implements": [x.strip().lstrip("\\") for x in (m.group("implements") or "").split(",") if x.strip()],
            "traits": uses, "line": line_of(source, m.start()), "body_start": brace + 1, "body_end": end,
        })
    return result


def find_methods(source: str, start: int = 0, end: int | None = None) -> list[dict]:
    """Return method/function declarations with parameter list and body text."""
    code = mask_comments(source, mask_strings=True)
    end = len(source) if end is None else end
    pattern = re.compile(
        rf"(?P<mods>(?:\b(?:public|protected|private|static|abstract|final)\s+)*)function\s*&?\s*(?P<name>{IDENT})\s*\(")
    result = []
    for m in pattern.finditer(code, start, end):
        open_paren = code.find("(", m.end() - 1)
        close_paren = match_delim(code, open_paren)
        if close_paren is None:
            continue
        brace = code.find("{", close_paren)
        semicolon = code.find(";", close_paren)
        if brace == -1 or (semicolon != -1 and semicolon < brace):
            continue  # abstract/interface declaration without a body
        body_end = match_delim(code, brace)
        if body_end is None:
            continue
        mods = m.group("mods").split()
        visibility = next((x for x in mods if x in {"public", "protected", "private"}), "public")
        ret = re.match(r"\s*:\s*([?\\A-Za-z0-9_|&]+)", code[close_paren + 1:brace])
        result.append({
            "name": m.group("name"), "visibility": visibility, "static": "static" in mods,
            "params_text": source[open_paren + 1:close_paren], "return_type": ret.group(1) if ret else None,
            "body": source[brace + 1:body_end], "body_offset": brace + 1,
            "line": line_of(source, m.start()), "start": m.start(), "end": body_end,
        })
    return result


def parse_parameters(params_text: str) -> list[dict]:
    """Parse a PHP parameter list into typed parameter records."""
    result = []
    for raw in split_top_level(params_text):
        var = re.search(r"\$([A-Za-z_][A-Za-z0-9_]*)", raw)
        if not var:
            continue
        before = raw[:var.start()].replace("...", " ").strip()
        before = re.sub(r"\b(?:public|protected|private|readonly)\b", "", before).strip()
        result.append({"name": var.group(1), "type": before.lstrip("?").lstrip("\\") or None,
                       "nullable": before.startswith("?") or "=" in raw, "default_present": "=" in raw})
    return result


def short_name(qualified: str) -> str:
    return qualified.strip().strip("\\").split("\\")[-1]


def stable_id(*parts: str) -> str:
    import hashlib
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:16]
