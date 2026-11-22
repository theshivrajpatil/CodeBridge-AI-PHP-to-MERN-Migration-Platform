import tempfile
import unittest
from pathlib import Path
from app.dependency_intelligence import build_dependency_intelligence
from app.intermediate_representation import build_common_ir


class UniversalIntelligenceTests(unittest.TestCase):
    def test_database_driver_and_schema_are_separate_static_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config").mkdir()
            (root / "database/migrations").mkdir(parents=True)
            (root / "config/database.php").write_text("<?php return ['driver' => 'pgsql'];")
            (root / "database/migrations/001_create_users.php").write_text(
                "<?php Schema::create('users', function ($table) {});")
            files = [
                {"path": "config/database.php", "classification": {"group": "Configuration"}},
                {"path": "database/migrations/001_create_users.php", "classification": {"group": "Database migrations"}},
            ]
            result = build_dependency_intelligence({"files": files}, root)
            self.assertEqual(result["database_engine_candidates"], ["pgsql"])
            self.assertEqual(result["database_schema_evidence"][0]["table"], "users")
            self.assertFalse(result["coverage"]["database_engine_identified"])
            self.assertEqual(result["coverage"]["files_with_database_signals"], 2)


    def test_schema_columns_are_grouped_by_table_and_migration_direction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "database/migrations").mkdir(parents=True)
            source = """<?php
            return new class {
                public function up(): void {
                    Schema::create('users', function ($table) {
                        $table->id();
                        $table->string('email')->unique()->nullable();
                        $table->unsignedBigInteger('team_id')->index();
                    });
                }
                public function down(): void {
                    Schema::dropIfExists('users');
                }
            };
            """
            (root / "database/migrations/001_users.php").write_text(source)
            result = build_dependency_intelligence({"files": [{
                "path": "database/migrations/001_users.php",
                "classification": {"group": "Database migrations"}
            }]}, root)
            creates = [x for x in result["database_schema_evidence"] if x["operation"].lower() == "create"]
            drops = [x for x in result["database_schema_evidence"] if x["operation"].lower() == "dropifexists"]
            self.assertEqual(len(creates), 1)
            self.assertEqual(creates[0]["direction"], "UP")
            self.assertEqual([c["column_name_candidate"] for c in creates[0]["columns"]], ["email", "team_id"])
            self.assertEqual([m["macro"] for m in creates[0]["schema_macro_evidence"]], ["id"])
            email = creates[0]["columns"][0]
            self.assertIn("unique", email["modifiers"])
            self.assertIn("nullable", email["modifiers"])
            self.assertEqual(drops[0]["direction"], "DOWN")
            self.assertEqual(drops[0]["table"], "users")

    def test_factory_is_not_database_schema_component(self):
        scan = {"file_count": 1, "php_file_count": 1}
        analysis = {"files": [{
            "path": "database/factories/UserFactory.php",
            "classification": {"group": "Test data factories", "confidence": "HIGH"},
            "status": "ANALYZED", "analysis_mode": "TREE_SITTER_AST"
        }], "dependency_intelligence": {"nodes": [], "edges": []}}
        ir = build_common_ir(scan, analysis)
        self.assertEqual(len(ir["components"]["test_fixtures"]), 1)
        self.assertEqual(ir["components"]["database_schema"], [])


    def test_phpunit_external_testcase_is_not_linked_to_local_testcase(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tests").mkdir()
            (root / "src").mkdir()
            (root / "tests/TestCase.php").write_text("<?php namespace Tests; class TestCase {}")
            (root / "tests/UnitTest.php").write_text(
                "<?php namespace Tests\\Unit; use PHPUnit\\Framework\\TestCase; class UnitTest extends TestCase {}")
            files = [
                {"path": "tests/TestCase.php", "namespace": "Tests", "classes": ["TestCase"], "classification": {"group": "Tests"}},
                {"path": "tests/UnitTest.php", "namespace": "Tests\\Unit", "classes": ["UnitTest"], "classification": {"group": "Tests"}},
            ]
            result = build_dependency_intelligence({"files": files}, root)
            pairs = {(e["from"], e["to"], e["type"]) for e in result["edges"]}
            self.assertNotIn(("tests/UnitTest.php", "tests/TestCase.php", "extends"), pairs)
            self.assertNotIn(("tests/UnitTest.php", "tests/TestCase.php", "imports"), pairs)

    def test_namespace_alias_resolves_exact_local_class(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src/Services").mkdir(parents=True)
            (root / "src/Models").mkdir(parents=True)
            (root / "src/Models/User.php").write_text("<?php namespace App\\Models; class User {}")
            (root / "src/Services/UserService.php").write_text(
                "<?php namespace App\\Services; use App\\Models\\User as Account; class UserService { public function run() { new Account(); } }")
            files = [
                {"path": "src/Models/User.php", "namespace": "App\\Models", "classes": ["User"], "classification": {"group": "Models"}},
                {"path": "src/Services/UserService.php", "namespace": "App\\Services", "classes": ["UserService"], "classification": {"group": "Services"}},
            ]
            result = build_dependency_intelligence({"files": files}, root)
            self.assertTrue(any(e["from"] == "src/Services/UserService.php" and e["to"] == "src/Models/User.php" and e["type"] == "imports" for e in result["edges"]))
            self.assertTrue(any(e["from"] == "src/Services/UserService.php" and e["to"] == "src/Models/User.php" and e["type"] == "instantiates" for e in result["edges"]))

    def test_database_engine_is_never_claimed_from_static_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "config").mkdir()
            (root / "config/database.php").write_text(
                "<?php return ['default' => env('DB_CONNECTION', 'mysql'), 'connections' => ['sqlite' => ['driver' => 'sqlite'], 'mysql' => ['driver' => 'mysql']]];")
            result = build_dependency_intelligence({"files": [{"path": "config/database.php", "classification": {"group": "Configuration"}}]}, root)
            self.assertEqual(result["database_engine_candidates"], ["mysql", "sqlite"])
            self.assertEqual(result["database_default_connection_evidence"][0]["configured_default_candidate"], "mysql")
            self.assertFalse(result["coverage"]["database_engine_identified"])

    def test_ir_uses_canonical_dependency_graph(self):
        scan = {"file_count": 0, "php_file_count": 0}
        edge = {"from": "A.php", "to": "B.php", "type": "imports"}
        analysis = {"files": [], "dependency_intelligence": {"nodes": [], "edges": [edge]}}
        ir = build_common_ir(scan, analysis)
        self.assertEqual(ir["dependencies"], [edge])
        self.assertEqual(ir["dependency_graph"]["edges"], [edge])


    def test_schema_catalog_preserves_constraints_indexes_and_column_modifiers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "database/migrations").mkdir(parents=True)
            source = """<?php
            return new class {
                public function up(): void {
                    Schema::create('orders', function ($table) {
                        $table->id();
                        $table->string('reference')->unique()->nullable()->default('pending');
                        $table->foreignId('user_id')->constrained('users')->cascadeOnDelete();
                        $table->index(['created_at', 'status']);
                    });
                }
                public function down(): void { Schema::dropIfExists('orders'); }
            };
            """
            (root / "database/migrations/002_orders.php").write_text(source)
            result = build_dependency_intelligence({"files": [{
                "path": "database/migrations/002_orders.php",
                "classification": {"group": "Database migrations"}
            }]}, root)
            catalog = {x["table"]: x for x in result["database_schema_catalog"]}
            orders = catalog["orders"]
            reference = next(x for x in orders["column_evidence"] if x["column_name_candidate"] == "reference")
            self.assertTrue(reference["unique_candidate"])
            self.assertTrue(reference["nullable_candidate"])
            self.assertEqual(reference["default_candidate"], "pending")
            self.assertTrue(any(x["kind"] == "foreign_key_candidate" for x in orders["constraint_evidence"]))
            self.assertTrue(any(x["kind"] == "index" for x in orders["index_evidence"]))
            self.assertEqual(result["coverage"]["schema_table_candidate_count"], 1)
            self.assertFalse(result["coverage"].get("database_engine_identified"))

    def test_column_level_indexes_and_primary_constraints_are_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "database/migrations").mkdir(parents=True)
            source = """<?php
            function up() {
                Schema::create('accounts', function ($table) {
                    $table->string('email')->unique();
                    $table->string('handle')->index();
                    $table->string('external_id')->primary();
                    $table->foreign('owner_id')->references('id')->on('users')->onDelete('cascade')->onUpdate('restrict');
                });
            }
            """
            (root / "database/migrations/003_accounts.php").write_text(source)
            result = build_dependency_intelligence({"files": [{
                "path": "database/migrations/003_accounts.php",
                "classification": {"group": "Database migrations"}
            }]}, root)
            account = next(x for x in result["database_schema_catalog"] if x["table"] == "accounts")
            index_kinds = {x["kind"] for x in account["index_evidence"]}
            constraint_kinds = {x["kind"] for x in account["constraint_evidence"]}
            self.assertTrue({"unique", "index", "primary"}.issubset(index_kinds))
            self.assertIn("unique_constraint_candidate", constraint_kinds)
            fk = next(x for x in account["constraint_evidence"] if x["kind"] == "foreign_key_candidate")
            self.assertEqual(fk["referenced_table_candidate"], ["users"])
            self.assertEqual(fk["actions_candidate"], [
                {"method": "onDelete", "arguments": ["cascade"]},
                {"method": "onUpdate", "arguments": ["restrict"]},
            ])
            self.assertGreaterEqual(result["coverage"]["schema_index_candidate_count"], 3)

    def test_schema_catalog_keeps_multiple_migration_operations_as_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "database/migrations").mkdir(parents=True)
            (root / "database/migrations/001.php").write_text(
                "<?php function up(){ Schema::create('users', function($t){ $t->id(); }); }")
            (root / "database/migrations/002.php").write_text(
                "<?php function up(){ Schema::table('users', function($t){ $t->string('nickname'); }); }")
            files = [{"path": f"database/migrations/{name}", "classification": {"group": "Database migrations"}}
                     for name in ("001.php", "002.php")]
            result = build_dependency_intelligence({"files": files}, root)
            users = next(x for x in result["database_schema_catalog"] if x["table"] == "users")
            self.assertEqual([x["operation"].lower() for x in users["operations"]], ["create", "table"])
            self.assertEqual(len(users["column_evidence"]), 1)
            self.assertEqual(len(users["schema_macro_evidence"]), 1)


if __name__ == "__main__":
    unittest.main()

    def test_schema_macros_are_not_misreported_as_single_columns(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "database/migrations").mkdir(parents=True)
            source = """<?php
            function up() {
                Schema::create('members', function($table) {
                    $table->id();
                    $table->string('email')->unique();
                    $table->timestamps();
                    $table->softDeletes();
                    $table->rememberToken();
                });
            }
            """
            (root / "database/migrations/004_members.php").write_text(source)
            result = build_dependency_intelligence({"files": [{
                "path": "database/migrations/004_members.php",
                "classification": {"group": "Database migrations"}
            }]}, root)
            members = next(x for x in result["database_schema_catalog"] if x["table"] == "members")
            concrete_names = {x["column_name_candidate"] for x in members["column_evidence"]}
            macros = {x["macro"] for x in members["schema_macro_evidence"]}
            self.assertEqual(concrete_names, {"email"})
            self.assertTrue({"id", "timestamps", "softDeletes", "rememberToken"}.issubset(macros))

    def test_column_modifier_index_evidence_is_not_double_counted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "database/migrations").mkdir(parents=True)
            source = """<?php
            function up() {
                Schema::create('accounts', function($table) {
                    $table->string('email')->unique();
                    $table->string('handle')->index();
                    $table->string('external_id')->primary();
                });
            }
            """
            (root / "database/migrations/005_accounts.php").write_text(source)
            result = build_dependency_intelligence({"files": [{
                "path": "database/migrations/005_accounts.php",
                "classification": {"group": "Database migrations"}
            }]}, root)
            account = next(x for x in result["database_schema_catalog"] if x["table"] == "accounts")
            evidence = [(x["source_line"], x["kind"], tuple(x["columns"])) for x in account["index_evidence"]]
            self.assertEqual(len(evidence), len(set(evidence)))
            self.assertEqual(len(evidence), 3)

