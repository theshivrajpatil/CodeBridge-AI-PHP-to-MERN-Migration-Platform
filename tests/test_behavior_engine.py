import unittest
import tempfile
from pathlib import Path
from app.frameworks import detect_framework, classify_php_path
from app.behavior_analyzer import extract_route_contracts, build_behavior_report


class FrameworkAnalysisTests(unittest.TestCase):
    def test_detects_laravel_from_repository_markers(self):
        scan = {"root": "/tmp/demo", "files": [
            {"path": "artisan"}, {"path": "routes/web.php"},
            {"path": "app/Http/Controllers/UserController.php"}
        ]}
        result = detect_framework(scan)
        self.assertEqual(result["name"], "Laravel")
        self.assertEqual(result["confidence"], "HIGH")

    def test_laravel_path_classification(self):
        self.assertEqual(classify_php_path("app/Http/Controllers/UserController.php", "Laravel")["group"], "Controllers")
        self.assertEqual(classify_php_path("database/migrations/001_users.php", "Laravel")["group"], "Database migrations")
        self.assertEqual(classify_php_path("resources/views/users/index.blade.php", "Laravel")["group"], "Templates")
        self.assertEqual(classify_php_path("tests/Feature/UserTest.php", "Laravel")["group"], "Tests")

    def test_detects_symfony_without_laravel_assumptions(self):
        scan = {"files": [{"path": "symfony.lock"}, {"path": "config/bundles.php"}, {"path": "bin/console"}]}
        result = detect_framework(scan)
        self.assertEqual(result["name"], "Symfony")
        self.assertEqual(result["adapter_id"], "symfony")

    def test_detects_codeigniter(self):
        scan = {"files": [{"path": "spark"}, {"path": "app/Controllers/Home.php"}]}
        self.assertEqual(detect_framework(scan)["name"], "CodeIgniter")

    def test_plain_php_uses_generic_core(self):
        scan = {"files": [{"path": "index.php"}, {"path": "src/Controller/UserController.php"}]}
        result = detect_framework(scan)
        self.assertEqual(result["adapter_id"], "generic_php")
        self.assertEqual(classify_php_path("src/Controller/UserController.php", result["name"])["group"], "Controllers")

    def test_framework_unknown_file_is_not_forced_into_laravel_bucket(self):
        result = classify_php_path("odd/location/LegacyThing.php", "Core PHP / Unknown")
        self.assertEqual(result["group"], "Unclassified PHP")


class BehaviourContractTests(unittest.TestCase):
    def test_extracts_only_source_backed_route_facts(self):
        files = [{"path": "routes/api.php", "route_candidates": [{
            "line": 12,
            "evidence": "Route::get('/users/{id}', [UserController::class, 'show'])->middleware('auth');"
        }]}]
        contracts = extract_route_contracts(files)
        self.assertEqual(len(contracts), 1)
        contract = contracts[0]
        self.assertEqual(contract["http_method"], "GET")
        self.assertEqual(contract["path"], "/users/{id}")
        self.assertEqual(contract["controller"], "UserController")
        self.assertEqual(contract["action"], "show")
        self.assertEqual(contract["middleware_evidence"], ["auth"])
        self.assertEqual(contract["authentication"], "NEEDS_REVIEW")
        self.assertEqual(contract["database_operations"], "NEEDS_REVIEW")


    def test_extracts_closure_blade_view_response(self):
        files = [{"path": "routes/web.php", "route_candidates": [{
            "line": 5, "evidence": "Route::get('/', function () {\n    return view('welcome');\n});"
        }]}]
        contract = extract_route_contracts(files)[0]
        self.assertEqual(contract["route_type"], "CLOSURE")
        self.assertEqual(contract["response_type"], "BLADE_VIEW")
        self.assertEqual(contract["view_name"], "welcome")
        self.assertEqual(contract["response_status"], "DEFAULT_NOT_EXPLICIT")

    def test_resolves_literal_route_group_prefix_and_middleware(self):
        import tempfile
        from pathlib import Path
        source = "<?php\nRoute::prefix('admin')->middleware('auth')->group(function () {\n    Route::get('/users', [UserController::class, 'index']);\n});\n"
        with tempfile.TemporaryDirectory() as tmp:
            route_file = Path(tmp) / "routes" / "web.php"
            route_file.parent.mkdir()
            route_file.write_text(source)
            files = [{"path": "routes/web.php", "route_candidates": [{
                "line": 3, "evidence": "Route::get('/users', [UserController::class, 'index']);"
            }]}]
            from app.behavior_analyzer import extract_route_contracts
            contract = extract_route_contracts(files, tmp)[0]
        self.assertEqual(contract["effective_path"], "/admin/users")
        self.assertEqual(contract["middleware_inherited_evidence"], ["auth"])
        self.assertEqual(contract["middleware_evidence"], ["auth"])

    def test_dynamic_or_incomplete_route_is_not_invented(self):
        files = [{"path": "routes/web.php", "route_candidates": [{
            "line": 5, "evidence": "Route::get($dynamicPath, $handler);"
        }]}]
        contract = extract_route_contracts(files)[0]
        self.assertIsNone(contract["path"])
        self.assertIsNone(contract["controller"])
        self.assertEqual(contract["status"], "NEEDS_REVIEW")


    def test_route_group_declaration_is_not_emitted_as_endpoint(self):
        source = """<?php
Route::prefix('admin')->middleware('auth')->group(function () {
    Route::get('/users', [UserController::class, 'index']);
});
"""
        with tempfile.TemporaryDirectory() as tmp:
            route_file = Path(tmp) / "routes" / "web.php"
            route_file.parent.mkdir()
            route_file.write_text(source)
            files = [{"path": "routes/web.php", "route_candidates": [
                {"line": 2, "evidence": "Route::prefix("},
                {"line": 3, "evidence": "Route::get("},
            ]}]
            from app.behavior_analyzer import extract_route_contracts
            contracts = extract_route_contracts(files, tmp)
        self.assertEqual(len(contracts), 1)
        self.assertEqual(contracts[0]["http_method"], "GET")
        self.assertEqual(contracts[0]["effective_path"], "/admin/users")
        self.assertEqual(contracts[0]["controller"], "UserController")
        self.assertEqual(contracts[0]["action"], "index")

    def test_callable_contract_captures_request_response_transaction_and_external_io(self):
        from app.behavior_analyzer import build_behavior_report
        source = """<?php
        class UserController {
            public function store($request) {
                $payload = $request->only(['name']);
                DB::transaction(function () use ($payload) { User::create($payload); });
                return response()->json(['ok' => true]);
            }
        }
        """
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "UserController.php"
            file.write_text(source)
            report = build_behavior_report({"files": [{"path": "UserController.php"}]}, tmp)
        callable_contract = next(x for x in report["callable_contracts"] if x["callable_name"] == "store")
        self.assertTrue(callable_contract["signals"]["request_input"])
        self.assertTrue(callable_contract["signals"]["json_response"])
        self.assertTrue(callable_contract["signals"]["transaction"])
        self.assertTrue(callable_contract["signals"]["database_write"])
        self.assertEqual(report["coverage"]["callables_with_transaction_evidence"], 1)

    def test_report_counts_route_coverage(self):
        report = build_behavior_report({"files": [{"path": "routes/web.php", "route_candidates": [{
            "line": 1, "evidence": "Route::post('/users', [UserController::class, 'store']);"
        }]}]})
        self.assertEqual(report["route_contract_count"], 1)
        self.assertEqual(report["coverage"]["routes_with_controller_action"], 1)
        self.assertEqual(report["coverage"]["authentication_verified"], 0)


if __name__ == "__main__":
    unittest.main()
