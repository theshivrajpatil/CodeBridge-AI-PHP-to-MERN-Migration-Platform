import json
import tempfile
import unittest
from pathlib import Path

from app.auth_intelligence import build_auth_intelligence, summarize_rule
from app.contract_extraction import extract_behavioural_contracts, pluralize
from app.dependency_graph import build_dependency_graph, impact_of, tarjan_scc
from app.intelligence_pipeline import clear_cache, run_stage
from app.php_source import mask_comments, match_delim, parse_value, safe_read, split_top_level
from app.routes_intelligence import build_routes_intelligence
from app.validation_response import build_validation_response_analysis, rules_to_target

FIXTURE = Path(__file__).resolve().parents[1] / "examples" / "laravel_blog_fixture"
M = "App\\Models\\"


class PhpSourceTests(unittest.TestCase):
    def test_safe_read_blocks_traversal_and_symlinks(self):
        self.assertIsNone(safe_read(FIXTURE, "../README.md"))
        with tempfile.TemporaryDirectory() as tmp:
            outside = Path(tmp, "secret.php"); outside.write_text("<?php secret")
            root = Path(tmp, "repo"); root.mkdir(); (root / "link.php").symlink_to(outside)
            self.assertIsNone(safe_read(root, "link.php"))

    def test_masking_keeps_delimiters_balanced(self):
        code = mask_comments("f('a)b', // c)\n [1]);", mask_strings=True)
        self.assertEqual(match_delim(code, code.index("(")), len(code.rstrip(";")) - 1)

    def test_literal_parsing(self):
        self.assertEqual(parse_value("['a' => 1, 'b' => [true, null]]"), {"a": 1, "b": [True, None]})
        self.assertEqual(split_top_level("a, [b, c], 'd,e'"), ["a", "[b, c]", "'d,e'"])


class DependencyGraphTests(unittest.TestCase):
    def setUp(self): self.g = build_dependency_graph(FIXTURE)

    def test_deterministic_fingerprint(self):
        self.assertEqual(self.g["fingerprint"], build_dependency_graph(FIXTURE)["fingerprint"])

    def test_model_cycle_detected_and_collapsed(self):
        self.assertTrue(any({M + "User", M + "Post"} <= set(c) for c in self.g["cycles"]))
        flat = [n for layer in self.g["migration_layers"] for comp in layer for n in comp]
        self.assertEqual(sorted(flat), sorted(n["id"] for n in self.g["nodes"]))

    def test_composer_mapping_and_unresolved_empty(self):
        pk = {p["package"]: p for p in self.g["composer"]["packages"]}
        self.assertEqual(pk["guzzlehttp/guzzle"]["npm_equivalent"], "axios")
        self.assertEqual(pk["spatie/laravel-permission"]["equivalence"], "MANUAL")
        self.assertEqual(self.g["unresolved_references"], [])

    def test_impact_and_tarjan(self):
        self.assertIn("App\\Http\\Controllers\\PostController", impact_of(self.g, M + "Post")["dependents"])
        comps = tarjan_scc(["a", "b", "c"], {"a": {"b"}, "b": {"a"}, "c": set()})
        self.assertIn(["a", "b"], comps)


class ContractTests(unittest.TestCase):
    def setUp(self): self.c = extract_behavioural_contracts(FIXTURE)

    def test_contract_details(self):
        by = {k["id"].split("\\")[-1]: k for k in self.c["callable_contracts"]}
        index = by["PostController::index"]
        self.assertEqual(index["model_operations"][0]["page_size"], 15)
        self.assertEqual(index["model_operations"][0]["conditions"], [{"field": "status", "operator": "=", "value": "published"}])
        self.assertEqual(by["PostController::update"]["authorization_calls"][0]["ability"], "update")
        self.assertIn("password_hashing", by["AuthController::register"]["side_effects"])
        self.assertEqual(by["CommentController::destroy"]["guard_clauses"][0]["status"], 403)

    def test_models_and_schema(self):
        models = {m["name"]: m for m in self.c["model_contracts"]}
        self.assertTrue(models["Post"]["soft_deletes"])
        self.assertEqual(models["User"]["hidden"], ["password", "remember_token"])
        schema = {t["table"]: t for t in self.c["schema_contracts"]}
        self.assertTrue(schema["posts"]["soft_deletes"])
        fk = next(c for c in schema["posts"]["columns"] if c["name"] == "user_id")
        self.assertEqual(fk["references"]["table"], "users")
        self.assertEqual(pluralize("category"), "categories")


class RoutesTests(unittest.TestCase):
    def setUp(self):
        self.r = build_routes_intelligence(FIXTURE)
        self.by = {(x["method"], x["uri"]): x for x in self.r["routes"]}

    def test_effective_routes(self):
        self.assertEqual(self.r["summary"]["route_count"], 15)
        self.assertIn(("PATCH", "/api/posts/{post}"), self.by)
        self.assertNotIn(("GET", "/api/posts/create"), self.by)  # apiResource has no create/edit
        nested = self.by[("POST", "/api/posts/{post}/comments")]
        self.assertEqual([m["raw"] for m in nested["middleware"]], ["auth:sanctum", "can:create,App\\Models\\Comment"])

    def test_alias_resolution_and_constraints(self):
        stats = self.by[("GET", "/api/admin/stats")]
        role = next(m for m in stats["middleware"] if m["name"] == "role")
        self.assertTrue(role["resolved_class"].endswith("RoleMiddleware"))
        self.assertEqual(role["behaviour"]["denies_with_status"], [403])
        destroy = self.by[("DELETE", "/api/comments/{comment}")]
        self.assertEqual(destroy["parameters"][0]["constraint"], "[0-9]+")
        self.assertEqual(destroy["name"], "comments.destroy")

    def test_modifier_chain_directly_on_route_without_group(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "routes").mkdir()
            (root / "routes" / "api.php").write_text(
                "<?php\nuse App\\Http\\Controllers\\ReportController;\n"
                "Route::middleware(['auth:sanctum', 'throttle:5,1'])->prefix('admin')->name('admin.')->get('/report', [ReportController::class, 'index'])->name('report');\n")
            routes = build_routes_intelligence(root)
            self.assertEqual(routes["unresolved"], [])
            route = routes["routes"][0]
            self.assertEqual((route["method"], route["uri"]), ("GET", "/api/admin/report"))
            self.assertEqual([m["raw"] for m in route["middleware"]], ["auth:sanctum", "throttle:5,1"])
            self.assertEqual(route["name"], "admin.report")

    def test_no_unresolved_in_fixture(self):
        self.assertEqual(self.r["unresolved"], []); self.assertEqual(self.r["duplicates"], [])


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.a = build_auth_intelligence(FIXTURE)
        self.by = {(e["method"], e["uri"]): e for e in self.a["endpoints"]}

    def test_system_and_rules(self):
        self.assertIn("token_sanctum", self.a["authentication_system"]["mechanisms"])
        self.assertEqual(self.a["roles_observed"], ["admin"])
        delete = next(p for p in self.a["policies"] if p["model"] == "Post")["abilities"]["delete"]["rule"]
        self.assertEqual(delete["kind"], "any_of")
        self.assertEqual(summarize_rule("$user->id === $post->user_id")["kind"], "owner")

    def test_endpoint_access(self):
        self.assertEqual(self.by[("POST", "/api/login")]["authentication"], "PUBLIC")
        self.assertEqual(self.by[("DELETE", "/api/posts/{post}")]["authentication"], "REQUIRED")
        controls = self.by[("PATCH", "/api/posts/{post}")]["authorization_controls"]
        self.assertTrue(any(c["type"] == "authorize_call" and c["status"] == "RESOLVED" for c in controls))

    def test_security_findings(self):
        flags = {f["flag"] for e in self.a["endpoints"] for f in e["risk_flags"]}
        self.assertIn("CREDENTIAL_ENDPOINT_WITHOUT_RATE_LIMIT", flags)   # /register
        self.assertIn("AUTHORIZATION_RULE_UNRESOLVED", flags)            # can:create without CommentPolicy
        self.assertEqual(self.a["summary"]["high_severity_flags"], 0)


class ValidationResponseTests(unittest.TestCase):
    def setUp(self):
        self.v = build_validation_response_analysis(FIXTURE)
        self.by = {(e["method"], e["uri"]): e for e in self.v["endpoints"]}

    def test_register_validation(self):
        t = self.by[("POST", "/api/register")]["validation"]["sources"][0]["target"]
        self.assertIn('"password": z.string().min(8)', t["zod_object"])
        self.assertEqual(t["async_checks"][0]["type"], "unique")
        self.assertEqual(t["refinements"], [{"field": "password", "rule": "confirmed"}])

    def test_form_request_and_array_items(self):
        t = self.by[("POST", "/api/posts")]["validation"]["sources"][0]["target"]
        self.assertIn('"status": z.enum(["draft", "published"]).nullish()', t["zod_object"])
        self.assertIn('"tags": z.array(z.string().max(30)).max(10).optional()', t["zod_object"])

    def test_resource_envelope_and_hidden_fields(self):
        index = self.by[("GET", "/api/posts")]["responses"][0]
        self.assertEqual((index["type"], index["envelope"], index["paginated"]), ("resource_collection", ["data", "links", "meta"], True))
        store = self.by[("POST", "/api/posts")]["responses"][0]
        self.assertEqual(store["status"], 201)
        reg = self.by[("POST", "/api/register")]["responses"][0]
        self.assertEqual(reg["hidden_fields_removed"]["user"], ["password", "remember_token"])
        self.assertEqual(self.by[("DELETE", "/api/posts/{post}")]["responses"][0]["status"], 204)

    def test_error_contracts(self):
        self.assertEqual([e["status"] for e in self.by[("POST", "/api/login")]["error_contracts"]], [422, 429])

    def test_generated_js_cannot_be_injected_via_regex_rule(self):
        out = rules_to_target({"x": "required|regex:/a/); process.exit(1); /b/"})["zod_object"]
        self.assertNotIn("process.exit(1); /b/)", out.replace('\\"', ""))
        safe = rules_to_target({"slug": "required|regex:/^a$/i"})["zod_object"]
        self.assertIn('new RegExp("^a$", "i")', safe)


class PipelineTests(unittest.TestCase):
    def test_stage_runner_and_cache(self):
        clear_cache()
        a = run_stage(FIXTURE, "auth"); b = run_stage(FIXTURE, "auth")
        self.assertIs(a, b)
        self.assertEqual(run_stage(FIXTURE, "validation-response")["engine"], "validation_response")
        with self.assertRaises(ValueError): run_stage(FIXTURE, "nope")
        json.dumps(a)  # reports must be JSON-serialisable


if __name__ == "__main__":
    unittest.main()
