import tempfile
import unittest
from pathlib import Path
from app.analyzer import analyze_php_file, analyze_repository
from app.planner import build_plan
from app.migration_spec import build_migration_spec
from app.php_ast import parse_php_source

class AnalyzerTests(unittest.TestCase):
    def test_extracts_symbols_and_database_signal(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "UserService.php").write_text("<?php namespace Demo; function normalizeName($name) { return trim($name); } class UserService { public function findUser() {} } $db->query('SELECT * FROM users');")
            result = analyze_php_file(root, "UserService.php")
            self.assertEqual(result["namespace"], "Demo")
            self.assertIn("UserService", result["classes"])
            if result["analysis_mode"] == "TREE_SITTER_AST":
                self.assertIn("findUser", result["methods"])
                self.assertNotIn("findUser", result["functions"])
            else:
                # The explicitly labelled lexical fallback cannot reliably
                # distinguish methods from top-level functions.
                self.assertEqual(result["status"], "NEEDS REVIEW")
                self.assertIn("findUser", result["functions"])
            self.assertIn("normalizeName", result["functions"])
            self.assertTrue(result["database_signals"])

    def test_ignores_comment_false_positives(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "sample.php").write_text("<?php // class Fake {}\n/* Route::get('/bad'); */ echo 'ok';")
            result = analyze_php_file(root, "sample.php")
            self.assertNotIn("Fake", result["classes"])
            self.assertEqual(result["route_candidates"], [])
            (root / "sample.php").write_text('<?php $x = "Route::get(\'/fake\')"; echo "class Ghost {}";')
            result = analyze_php_file(root, "sample.php")
            self.assertEqual(result["route_candidates"], [])
            self.assertNotIn("Ghost", result["classes"])

    def test_dependency_edges_for_import_instantiation_and_include(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "User.php").write_text("<?php namespace App; class User {}")
            (root / "Service.php").write_text("<?php use App\\User; class Service { public function x() { return new User(); } }")
            (root / "bootstrap.php").write_text("<?php require_once 'User.php';")
            scan = {"root": str(root), "php_files": [{"path": x} for x in ("User.php", "Service.php", "bootstrap.php")], "file_count": 3, "php_file_count": 3, "framework_hints": []}
            result = analyze_repository(scan)
            pairs = {(e["from"], e["to"]) for e in result["dependency_edges"]}
            self.assertIn(("Service.php", "User.php"), pairs)
            self.assertIn(("bootstrap.php", "User.php"), pairs)


    def test_parser_reports_unavailable_explicitly_or_parses(self):
        result = parse_php_source("<?php class User {}")
        self.assertIn(result["status"], {"PARSED", "PARSER_UNAVAILABLE", "PARSE_FAILED", "PARSED_WITH_ERRORS"})
        if not result["available"]:
            self.assertEqual(result["status"], "PARSER_UNAVAILABLE")
            self.assertTrue(result.get("parser_error"))

    def test_analyzer_marks_lexical_fallback_when_ast_dependency_missing(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "sample.php").write_text("<?php class RealClass {}")
            result = analyze_php_file(root, "sample.php")
            self.assertIn(result["analysis_mode"], {"TREE_SITTER_AST", "LEXICAL_FALLBACK"})
            if result["analysis_mode"] == "LEXICAL_FALLBACK":
                self.assertEqual(result["status"], "NEEDS REVIEW")
                self.assertTrue(any("AST parser unavailable" in x for x in result["signals"]))

    def test_parser_does_not_claim_regex_fallback_is_ast(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "sample.php").write_text("<?php class RealClass { public function go() {} }")
            result = analyze_php_file(root, "sample.php")
            if result["analysis_mode"] == "LEXICAL_FALLBACK":
                self.assertNotEqual(result["analysis_mode"], "TREE_SITTER_AST")

    def test_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as temp:
            result = analyze_php_file(Path(temp), "../outside.php")
            self.assertEqual(result["status"], "BLOCKED")

    def test_plan_and_spec_preserve_database_policy(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "index.php").write_text("<?php echo 'hello';")
            scan = {"root": str(root), "file_count": 1, "php_file_count": 1, "framework_hints": [], "php_files": [{"path": "index.php"}], "warnings": []}
            analysis = analyze_repository(scan)
            plan = build_plan(scan, analysis)
            spec = build_migration_spec(scan, analysis, plan)
            self.assertIn("Preserve the existing database", plan["database_policy"])
            self.assertEqual(spec["status"], "DRAFT_REQUIRES_HUMAN_APPROVAL")
            self.assertTrue(spec["non_negotiable_constraints"])
            self.assertEqual(spec["scope"]["migration_units_in_spec"], 1)

if __name__ == "__main__": unittest.main()
