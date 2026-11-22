import tempfile
import unittest
from pathlib import Path
from app.dependency_intelligence import build_dependency_intelligence


class DependencyIntelligenceTests(unittest.TestCase):
    def _fixture(self, files_and_source):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        files = []
        for path, source, classes, role in files_and_source:
            full = root / path
            full.parent.mkdir(parents=True, exist_ok=True)
            full.write_text(source)
            files.append({"path": path, "classes": classes, "interfaces": [], "traits": [],
                          "classification": {"group": role}})
        result = build_dependency_intelligence({"files": files}, root)
        tmp.cleanup()
        return result

    def test_controller_instantiates_service_and_calls_it(self):
        result = self._fixture([
            ("app/Http/Controllers/UserController.php", "<?php class UserController { public function index() { $svc = new UserService(); return $svc->listUsers(); } }", ["UserController"], "Controllers"),
            ("app/Services/UserService.php", "<?php class UserService { public function listUsers() { return User::all(); } }", ["UserService"], "Services"),
            ("app/Models/User.php", "<?php class User {}", ["User"], "Models"),
        ])
        pairs = {(e["from"], e["to"], e["type"]) for e in result["edges"]}
        self.assertIn(("app/Http/Controllers/UserController.php", "app/Services/UserService.php", "instantiates"), pairs)
        self.assertIn(("app/Http/Controllers/UserController.php", "app/Services/UserService.php", "calls_service"), pairs)
        self.assertIn(("app/Services/UserService.php", "app/Models/User.php", "uses_model"), pairs)

    def test_extracts_eloquent_read_and_write_signals(self):
        result = self._fixture([
            ("app/Models/User.php", "<?php class User {}", ["User"], "Models"),
            ("app/Services/UserService.php", "<?php class UserService { function run() { User::find(1); User::create(['name'=>'A']); $u = new User(); $u->delete(); } }", ["UserService"], "Services"),
        ])
        ops = [x["operation"] for x in result["database_operations"]]
        self.assertIn("READ", ops)
        self.assertIn("INSERT", ops)
        self.assertIn("DELETE", ops)
        self.assertFalse(result["coverage"]["database_engine_identified"])


    def test_route_facade_get_is_not_a_database_read(self):
        result = self._fixture([
            ("routes/web.php", "<?php Route::get('/users', [UserController::class, 'index']);", [], "Routes"),
            ("app/Http/Controllers/UserController.php", "<?php class UserController {}", ["UserController"], "Controllers"),
        ])
        self.assertEqual(result["database_operation_count"], 0)
        self.assertFalse(any(e["to"] == "DATABASE:UNRESOLVED_ENGINE" for e in result["edges"]))

    def test_runtime_uncertainty_is_separate_from_unresolved_references(self):
        result = self._fixture([
            ("app/Services/Lookup.php", "<?php class Lookup { public function run() {} }", ["Lookup"], "Services"),
        ])
        self.assertEqual(result["unresolved_reference_count"], 0)
        self.assertFalse(result["coverage"]["runtime_call_order_verified"])
        self.assertIn("runtime_uncertainty", result)

    def test_ignores_comment_only_database_examples(self):
        result = self._fixture([
            ("app/Services/Example.php", "<?php class Example { // User::delete();\n public function ok() {} }", ["Example"], "Services"),
        ])
        self.assertEqual(result["database_operation_count"], 0)

    def test_ambiguous_short_class_name_is_unresolved(self):
        result = self._fixture([
            ("app/Models/Admin/User.php", "<?php class User {}", ["User"], "Models"),
            ("app/Models/Customer/User.php", "<?php class User {}", ["User"], "Models"),
            ("app/Services/Lookup.php", "<?php class Lookup { function run() { User::find(1); } }", ["Lookup"], "Services"),
        ])
        self.assertTrue(any(x["symbol"] == "User" for x in result["unresolved_relationships"]))


if __name__ == "__main__":
    unittest.main()
