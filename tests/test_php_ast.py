"""Focused contract tests for the Tree-sitter PHP analysis layer.

Parser-specific tests are skipped only when the declared Tree-sitter runtime is
not installed. The parser-unavailable contract remains covered independently.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from app import php_ast


class PhpAstAvailabilityTests(unittest.TestCase):
    def test_unavailable_parser_is_explicit_and_never_claims_ast_success(self):
        with patch.object(php_ast, "_create_parser", return_value=php_ast.ParserState(False, error="dependency missing")):
            result = php_ast.parse_php_source("<?php class Example {}")
        self.assertFalse(result["available"])
        self.assertEqual(result["status"], "PARSER_UNAVAILABLE")
        self.assertIsNone(result["parser"])
        self.assertEqual(result["parser_error"], "dependency missing")


@unittest.skipUnless(php_ast._create_parser().available, "Tree-sitter PHP dependency is not installed")
class PhpAstRuntimeTests(unittest.TestCase):
    def test_extracts_namespace_declarations_and_relationships(self):
        source = r'''<?php
namespace App\Services;
use App\Models\User;
interface RepositoryContract {}
trait LogsActivity {}
abstract class BaseService implements RepositoryContract {}
final class UserService extends BaseService {
    use LogsActivity;
    public function find(int $id): ?User { return new User(); }
}
function normalize_name(string $value): string { return trim($value); }
'''
        result = php_ast.parse_php_source(source)
        self.assertEqual(result["status"], "PARSED")
        self.assertEqual(result["namespace"], r"App\Services")
        self.assertIn("RepositoryContract", [x["name"] for x in result["interfaces"]])
        self.assertIn("LogsActivity", [x["name"] for x in result["traits"]])
        self.assertIn("UserService", [x["name"] for x in result["classes"]])
        self.assertIn("find", [x["name"] for x in result["methods"]])
        self.assertIn("normalize_name", [x["name"] for x in result["functions"]])
        self.assertIn("BaseService", [x["name"] for x in result["extends"]])
        self.assertIn("RepositoryContract", [x["name"] for x in result["implements"]])

    def test_detects_routes_and_database_calls_with_spacing_and_case_variants(self):
        source = '''<?php
Route :: get('/users', [UserController::class, 'index']);
$db -> prepare('SELECT * FROM users');
'''
        result = php_ast.parse_php_source(source)
        self.assertEqual(result["status"], "PARSED")
        self.assertTrue(result["route_calls"])
        self.assertTrue(result["database_calls"])

    def test_reports_malformed_php_with_source_locations(self):
        result = php_ast.parse_php_source("<?php\nclass Broken { function missing( {\n")
        self.assertEqual(result["status"], "PARSED_WITH_ERRORS")
        self.assertTrue(result["has_syntax_errors"])
        self.assertTrue(result["syntax_errors"])
        self.assertGreaterEqual(result["syntax_errors"][0]["line"], 1)

    def test_extracts_all_four_include_and_require_constructs(self):
        source = """<?php
require_once __DIR__ . '/bootstrap.php';
include 'helpers.php';
include_once 'config.php';
require 'vendor/autoload.php';
"""
        result = php_ast.parse_php_source(source)
        self.assertEqual(result["status"], "PARSED")
        self.assertEqual(len(result["includes"]), 4)
        self.assertEqual(
            [item["kind"] for item in result["includes"]],
            ["require_once", "include", "include_once", "require"],
        )

    def test_extracts_dynamic_include_expressions_without_inventing_a_path(self):
        result = php_ast.parse_php_source("<?php include $helperPath;")
        self.assertEqual(result["status"], "PARSED")
        self.assertEqual(len(result["includes"]), 1)
        self.assertEqual(result["includes"][0]["kind"], "include")
        self.assertEqual(result["includes"][0]["expression"], "include $helperPath")


if __name__ == "__main__":
    unittest.main()
