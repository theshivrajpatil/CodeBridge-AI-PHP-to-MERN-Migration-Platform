"""Tree-sitter based PHP syntax analysis.

This module never executes PHP. It uses the tree-sitter-php grammar and returns
source-located syntax facts. If the optional parser dependency is unavailable,
callers receive an explicit unavailable result rather than an AST claim.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any


@dataclass
class ParserState:
    available: bool
    parser: Any = None
    error: str | None = None


def _create_parser() -> ParserState:
    try:
        from tree_sitter import Language, Parser
        import tree_sitter_php

        language_factory = getattr(tree_sitter_php, "language_php", None)
        if language_factory is None:
            return ParserState(False, error="tree-sitter-php does not expose language_php()")
        language = Language(language_factory())
        try:
            parser = Parser(language)
        except TypeError:  # Compatibility with tree-sitter versions using set_language.
            parser = Parser()
            parser.set_language(language)
        return ParserState(True, parser=parser)
    except Exception as exc:
        return ParserState(False, error=f"{type(exc).__name__}: {exc}")


def _text(node: Any, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace").strip()


def _field(node: Any, name: str) -> Any:
    try:
        return node.child_by_field_name(name)
    except Exception:
        return None


def _walk(node: Any):
    """Iterate the syntax tree without recursion (safe for deeply nested input)."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        # Reverse to preserve the parser's natural left-to-right source order.
        stack.extend(reversed(current.children))


def _name_from_node(node: Any, source: bytes) -> str | None:
    if node is None:
        return None
    value = _text(node, source).strip().strip("\\")
    if not value or value in {"{", "}", "(" , ")"}:
        return None
    return value


def _line(node: Any) -> int:
    return int(node.start_point.row) + 1


def _names_in_clause(node: Any, source: bytes) -> list[str]:
    # Clause descendants contain name/qualified_name nodes. Exclude punctuation
    # and preserve fully-qualified source spelling.
    result = []
    for child in _walk(node):
        if child.type in {"name", "qualified_name", "relative_name", "namespace_name"}:
            value = _name_from_node(child, source)
            if value and value not in result:
                result.append(value)
    if not result:
        raw = _text(node, source)
        raw = raw.split(None, 1)[-1].strip().strip("{}; ")
        result = [part.strip().lstrip("\\") for part in raw.split(",") if part.strip()]
    return result


def parse_php_source(source_text: str) -> dict:
    """Parse PHP and return AST facts, parser diagnostics, and source locations."""
    state = _create_parser()
    base = {
        "available": state.available,
        "parser": "tree-sitter-php" if state.available else None,
        "status": "PARSED" if state.available else "PARSER_UNAVAILABLE",
        "namespace": None,
        "classes": [], "interfaces": [], "traits": [], "functions": [],
        "methods": [], "imports": [], "extends": [], "implements": [],
        "instantiations": [], "includes": [], "route_calls": [],
        "database_calls": [], "syntax_errors": [], "has_syntax_errors": False,
    }
    if not state.available:
        base["parser_error"] = state.error
        return base

    source = source_text.encode("utf-8")
    try:
        tree = state.parser.parse(source)
    except Exception as exc:
        base.update(status="PARSE_FAILED", syntax_errors=[{"message": f"{type(exc).__name__}: {exc}"}])
        return base

    root = tree.root_node
    errors = []
    for node in _walk(root):
        if node.type == "ERROR" or node.is_missing:
            errors.append({"node_type": node.type, "line": _line(node),
                           "column": int(node.start_point.column) + 1,
                           "message": "Syntax error or missing syntax node"})
    base["syntax_errors"] = errors
    base["has_syntax_errors"] = bool(root.has_error or errors)
    if base["has_syntax_errors"]:
        base["status"] = "PARSED_WITH_ERRORS"

    for node in _walk(root):
        typ = node.type
        if typ == "namespace_definition":
            name = _field(node, "name")
            if name is None:
                name = next((c for c in node.named_children if c.type in {"namespace_name", "name", "qualified_name"}), None)
            value = _name_from_node(name, source)
            if value and base["namespace"] is None:
                base["namespace"] = value
        elif typ in {"class_declaration", "interface_declaration", "trait_declaration", "function_definition", "method_declaration"}:
            name = _field(node, "name")
            value = _name_from_node(name, source)
            if value:
                key = {"class_declaration": "classes", "interface_declaration": "interfaces",
                       "trait_declaration": "traits", "function_definition": "functions",
                       "method_declaration": "methods"}[typ]
                base[key].append({"name": value, "line": _line(node)})
            for clause in node.named_children:
                if clause.type == "base_clause":
                    base["extends"].extend({"name": x, "line": _line(clause)} for x in _names_in_clause(clause, source))
                elif clause.type == "class_interface_clause":
                    base["implements"].extend({"name": x, "line": _line(clause)} for x in _names_in_clause(clause, source))
        elif typ == "namespace_use_declaration":
            raw = _text(node, source).removeprefix("use").strip().rstrip(";").strip()
            if raw:
                base["imports"].append({"name": raw, "line": _line(node)})
        elif typ == "object_creation_expression":
            name_node = _field(node, "class") or _field(node, "name")
            value = _name_from_node(name_node, source)
            if value:
                base["instantiations"].append({"name": value, "line": _line(node)})
        elif typ in {
            "include_expression", "include_once_expression",
            "require_expression", "require_once_expression",
        }:
            # tree-sitter-php models the *_once forms as distinct expression
            # node types. Treat all four language constructs as dependencies,
            # while preserving the exact construct in the reported kind.
            include_kind = typ.removesuffix("_expression")
            base["includes"].append({
                "expression": _text(node, source),
                "kind": include_kind,
                "line": _line(node),
            })
        elif typ in {"scoped_call_expression", "member_call_expression", "function_call_expression"}:
            call_text = _text(node, source)
            low = call_text.lower()
            if re.search(r"\broute\s*::\s*(?:get|post|put|patch|delete|any|match|resource)\b", low):
                # Chained Laravel calls may appear as nested call-expression nodes.
                # Retain the complete node text; downstream code selects the longest
                # source-backed expression for a route line.
                base["route_calls"].append({"expression": call_text[:1200], "line": _line(node), "node_type": typ})
            if re.search(r"(?:->\s*(?:query|prepare|execute)\b|\bmysqli_\w+|\bpg_query\b|\bdb\s*::\s*table\b|::\s*table\b)", low):
                base["database_calls"].append({"expression": call_text[:240], "line": _line(node)})

    for key in ("classes", "interfaces", "traits", "functions", "methods", "imports", "extends", "implements", "instantiations", "includes", "route_calls", "database_calls"):
        seen, unique = set(), []
        for item in base[key]:
            marker = tuple(sorted(item.items()))
            if marker not in seen:
                seen.add(marker); unique.append(item)
        base[key] = unique
    return base
