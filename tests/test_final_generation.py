import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from app.intelligence_pipeline import clear_cache
from app.mern_generator import (GenerationError, SafeWriter, generate_mern_project, preview_generation, resolve_output_root,
                                source_fingerprint, evaluate_generation_gate, ident, Ctx, generation_enabled, generation_status)
from app.parity_engine import build_source_contracts, run_parity
from tests.test_v523_parity import PHP, controller, php_repo, write

BLOG = Path(__file__).resolve().parents[1] / "examples" / "laravel_blog_fixture"
NODE = shutil.which("node")


def tree_hash(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        if p.is_file():
            h.update(p.relative_to(root).as_posix().encode()); h.update(p.read_bytes())
    return h.hexdigest()


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(); self.tmp = Path(self._tmp.name); self.base = self.tmp / "generated"; clear_cache()
    def tearDown(self): self._tmp.cleanup(); clear_cache()
    def approval(self, src, **kw):
        a = {"reviewer": "reviewer@example.test", "reason": "reviewed analysis", "source_fingerprint": source_fingerprint(build_source_contracts(src)), "approve_all": True}
        a.update(kw); return a
    def generate(self, src=BLOG, name="blog", enabled=True, approval=None, **kw):
        out = resolve_output_root(name, src, self.base)
        return generate_mern_project(src, out, approval if approval is not None else self.approval(src), enabled, name, **kw), out


class GateTests(Base):
    def test_refused_when_disabled_without_approval_or_with_stale_fingerprint(self):
        for kwargs in ({"enabled": False}, {"approval": {}}, {"approval": {"reviewer": "x", "reason": "y", "source_fingerprint": "0" * 64, "approve_all": True}},
                       {"approval": {"reviewer": " ", "reason": "y", "source_fingerprint": source_fingerprint(build_source_contracts(BLOG)), "approve_all": True}}):
            out = self.base / "refused"
            m, _ = self.generate(name="refused", **kwargs)
            self.assertEqual(m["status"], "REFUSED"); self.assertFalse(m["gate"]["allowed"]); self.assertTrue(m["gate"]["reasons"])
            self.assertFalse(out.exists())                       # nothing written

    def test_only_approved_contracts_are_generated(self):
        src = build_source_contracts(BLOG)
        ids = [c["contract_id"] for c in src["contracts"] if c["uri"] == "/api/health"]
        m, out = self.generate(approval=self.approval(BLOG, approve_all=False, approved_contract_ids=ids))
        self.assertEqual(m["counts"], {"IMPLEMENT": 1, "STUB": 0, "EXCLUDE": 13})
        routes = (out / "server/src/routes/api.js").read_text()
        self.assertEqual(routes.count("router.get(") + routes.count("router.post("), 1)

    def test_high_risk_endpoint_needs_explicit_acknowledgement(self):
        root = self.tmp / "php_notes"
        write(root, {"routes/api.php": "<?php\nuse App\\Http\\Controllers\\NoteController;\nRoute::post('/notes', [NoteController::class, 'store']);\n",
                     "app/Http/Controllers/Controller.php": "<?php\nnamespace App\\Http\\Controllers;\nabstract class Controller {}\n",
                     "app/Http/Controllers/NoteController.php": "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Note;\nuse Illuminate\\Http\\Request;\nclass NoteController extends Controller\n{\n    public function store(Request $request)\n    {\n        $data = $request->validate(['text' => 'required|string']);\n        $note = Note::create($data);\n        return response()->json($note, 201);\n    }\n}\n",
                     "app/Models/Note.php": "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass Note extends Model\n{\n    protected $fillable = ['text'];\n}\n"})
        pv = preview_generation(root)
        self.assertEqual(len(pv["high_risk_flags_requiring_acknowledgement"]), 1)
        m, _ = self.generate(src=root, name="notes_blocked")
        self.assertEqual((m["status"], m["gate"]["excluded"][0]["reason"][:14]), ("REFUSED", "unacknowledged"))
        m2, out = self.generate(src=root, name="notes_ok", approval=self.approval(root, acknowledged_risks=pv["high_risk_flags_requiring_acknowledgement"]))
        self.assertEqual(m2["counts"]["IMPLEMENT"], 1)
        self.assertIn("UNAUTHENTICATED_STATE_CHANGE", (out / "MIGRATION_REPORT.md").read_text())   # finding stays visible


class GenerationTests(Base):
    def test_blog_generation_plan_manifest_and_policy(self):
        m, out = self.generate()
        self.assertEqual((m["status"], m["counts"]), ("GENERATED", {"IMPLEMENT": 13, "STUB": 1, "EXCLUDE": 0}))
        self.assertFalse(m["policy"]["deployment_authorized"]); self.assertFalse(m["policy"]["auto_approval"])
        manifest = json.loads((out / "GENERATION_MANIFEST.json").read_text())
        for rel, digest in manifest["files"].items():
            self.assertEqual(hashlib.sha256((out / rel).read_bytes()).hexdigest(), digest, rel)
        for must in ("server/src/app.js", "server/src/routes/api.js", "server/Dockerfile", "docker-compose.yml", ".github/workflows/ci.yml",
                     "client/src/App.jsx", "MIGRATION_REPORT.md", "DEPLOYMENT.md", "server/tests/security.test.js"):
            self.assertTrue((out / must).is_file(), must)

    def test_unsupported_logic_becomes_explicit_stub_never_guessed(self):
        shop = php_repo(self.tmp)               # store() has business rules (discount, quantity condition)
        m, out = self.generate(src=shop, name="shop")
        by = {(c["method"], c["uri"]): m["plan"][c["contract_id"]] for c in build_source_contracts(shop)["contracts"]}
        self.assertEqual(by[("POST", "/api/orders")]["action"], "STUB"); self.assertIn("business rules", by[("POST", "/api/orders")]["reason"])
        ctl = (out / "server/src/controllers/OrderController.js").read_text()
        self.assertIn("CODEBRIDGE:STUB", ctl)
        self.assertNotIn("const discount", ctl); self.assertNotIn("Order.create", ctl)   # logic is flagged for review, never re-implemented
        self.assertEqual(by[("DELETE", "/api/orders/{order}")]["action"], "IMPLEMENT")

    def test_models_and_controllers_encode_security_semantics(self):
        _, out = self.generate()
        post = (out / "server/src/models/Post.js").read_text(); user = (out / "server/src/models/User.js").read_text()
        self.assertIn("deleted_at", post); self.assertIn("schema.pre(hook", post); self.assertIn("Post.fillable", post)
        self.assertIn("delete ret.password;", user); self.assertIn("select: false", user)
        ctl = (out / "server/src/controllers/PostController.js").read_text()
        self.assertIn("pick(", ctl)                                           # mass-assignment protection
        self.assertIn("req.user.role === \"admin\"", ctl)                     # translated policy rule
        self.assertIn("throw new HttpError(403", ctl)
        routes = (out / "server/src/routes/api.js").read_text()
        self.assertIn('rateLimit({ max: 5, windowMinutes: 1 })', routes)      # source throttle preserved
        self.assertIn('router.get("/admin/stats", authenticate, requireRole("admin")', routes)

    def test_deployment_artifacts_are_hardened_and_contain_no_secrets(self):
        _, out = self.generate()
        compose = (out / "docker-compose.yml").read_text(); docker = (out / "server/Dockerfile").read_text()
        self.assertIn("${JWT_SECRET:?", compose); self.assertIn("cap_drop", compose); self.assertIn("no-new-privileges", compose)
        self.assertNotRegex(compose, r"JWT_SECRET:\s*['\"]?[A-Za-z0-9]{8,}")
        self.assertIn("USER node", docker); self.assertIn("npm ci --omit=dev", docker); self.assertNotIn("mongo:27017\n", compose)
        self.assertRegex((out / "server/.env.example").read_text(), r"JWT_SECRET=\n")
        app = (out / "server/src/app.js").read_text()
        for needle in ("helmet()", "limit: '100kb'", "noSqlSanitize", "x-powered-by"):
            self.assertIn(needle, app)
        self.assertIn("generated files only" if False else "Nothing has been built or deployed", (out / "DEPLOYMENT.md").read_text())

    def test_deterministic_output_and_source_untouched(self):
        before = tree_hash(BLOG)
        m1, _ = self.generate(name="one")
        out2 = resolve_output_root("two", BLOG, self.base)
        m2 = generate_mern_project(BLOG, out2, self.approval(BLOG), True, "one")          # same project name, different directory
        self.assertEqual(m1["files"], m2["files"])                                         # byte-identical content hashes
        self.assertEqual(tree_hash(BLOG), before)

    @unittest.skipUnless(NODE, "node not available")
    def test_every_generated_server_file_is_valid_javascript(self):
        _, out = self.generate()
        files = [p for p in (out / "server").rglob("*.js")]
        self.assertGreater(len(files), 25)
        for f in files:
            r = subprocess.run([NODE, "--check", str(f)], capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 0, f"{f.name}: {r.stderr[:300]}")


class ParityLoopTests(Base):
    def test_generated_project_is_statically_verified_against_source(self):
        m, out = self.generate()
        met = m["parity_report"]["metrics"]
        self.assertEqual((met["verified_equivalent"], met["verified_mismatch"], met["not_implemented"]), (13, 0, 1))
        self.assertEqual(m["parity"]["metrics"]["verified_equivalent"], 13)
        self.assertTrue(all(c["evidence_level"] == "STATIC_ONLY" and c["human_review_required"] for c in m["parity_report"]["contracts"]))

    def test_parity_detects_tampering_with_generated_code(self):
        _, out = self.generate()
        ctl = out / "server/src/controllers/PostController.js"
        ctl.write_text(ctl.read_text().replace("    if (!(String(req.bound.post.user_id) === String(req.user.id))) throw new HttpError(403, 'This action is unauthorized.');\n", ""))
        routes = out / "server/src/routes/api.js"
        routes.write_text(routes.read_text().replace('router.delete("/comments/:comment", authenticate, ', 'router.delete("/comments/:comment", '))
        r = run_parity(BLOG, out / "server")
        by = {(c["method"], c["uri"]): c for c in r["contracts"]}
        self.assertEqual(by[("PATCH", "/api/posts/{post}")]["status"], "VERIFIED_MISMATCH")
        self.assertEqual(by[("DELETE", "/api/comments/{comment}")]["status"], "VERIFIED_MISMATCH")
        self.assertEqual(by[("DELETE", "/api/comments/{comment}")]["max_severity"], "critical")


class InjectionAndFilesystemSafetyTests(Base):
    def test_hostile_source_strings_cannot_inject_javascript(self):
        root = self.tmp / "php_evil"
        rules = ("['a\"b' => 'required|in:x\"y,z', 'c' => 'nullable|string|max:9', "
                 "'d' => 'regex:/a\\/); process.exit(3); (/'] ")
        write(root, {"routes/api.php": "<?php\nuse App\\Http\\Controllers\\ThingController;\nRoute::middleware('auth:sanctum')->post('/x\"y', [ThingController::class, 'store']);\n",
                     "app/Http/Controllers/Controller.php": "<?php\nnamespace App\\Http\\Controllers;\nabstract class Controller {}\n",
                     "app/Http/Controllers/ThingController.php": "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Thing;\nuse Illuminate\\Http\\Request;\nclass ThingController extends Controller\n{\n    public function store(Request $request)\n    {\n        $data = $request->validate(" + rules + ");\n        $thing = Thing::create($data);\n        return response()->json($thing, 201);\n    }\n}\n",
                     "app/Models/Thing.php": "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass Thing extends Model\n{\n    protected $fillable = ['a\"b', 'c'];\n}\n"})
        m, out = self.generate(src=root, name="evil")
        self.assertEqual(m["status"], "GENERATED")
        files = {p: p.read_text() for p in (out / "server/src").rglob("*.js")}
        generated = "".join(t for p, t in files.items() if p.parent.name in ("validators", "controllers", "routes", "models"))
        self.assertIn('"a\\"b"', generated)                       # hostile key survives only as an escaped JSON string
        self.assertIn('"/x\\"y"', generated)
        if NODE:
            for f in files:
                r = subprocess.run([NODE, "--check", str(f)], capture_output=True, text=True, timeout=30)
                self.assertEqual(r.returncode, 0, f"{f}: {r.stderr[:200]}")

    def test_unsafe_identifiers_abort_generation_and_clean_up(self):
        self.assertEqual(ident("PostController"), "PostController")
        for bad in ["Post-Controller", "a b", "1abc", "Pöst", "x;y", ""]:
            with self.assertRaises(GenerationError): ident(bad)
        root = self.tmp / "php_bad"
        write(root, {"routes/api.php": "<?php\nuse App\\Http\\Controllers\\ZController;\nRoute::get('/z', [ZController::class, 'index']);\n",
                     "app/Http/Controllers/ZController.php": "<?php\nnamespace App\\Http\\Controllers;\nclass ZController\n{\n    public function index() { return response()->json(['a' => 1]); }\n}\n",
                     "app/Models/Pöst.php": "<?php\nnamespace App\\Models;\nclass Pöst extends \\Illuminate\\Database\\Eloquent\\Model {}\n"})
        out = resolve_output_root("bad", root, self.base)
        try:
            generate_mern_project(root, out, self.approval(root), True, "bad")
        except GenerationError:
            self.assertFalse(out.exists())                        # partial output removed
        except Exception:
            self.assertFalse(out.exists())

    def test_safe_writer_and_output_root_restrictions(self):
        src = self.tmp / "src"; src.mkdir()
        for bad in ["../escape", "/etc/passwd", str(self.tmp / "elsewhere"), str(src), str(src / "inner")]:
            with self.assertRaises(GenerationError): resolve_output_root(bad, src, self.base)
        self.base.mkdir(exist_ok=True); real = self.tmp / "real"; real.mkdir(); (self.base / "lnk").symlink_to(real)
        with self.assertRaises(GenerationError): resolve_output_root("lnk/x", src, self.base)
        d = self.base / "w"; d.mkdir(); (d / "keep.txt").write_text("user data")
        with self.assertRaises(GenerationError): SafeWriter(d)                    # non-empty, not ours
        w = SafeWriter(self.base / "fresh")
        for bad in ["../x.js", "/abs.js", "a/../../b.js", "a b.js", "x\n.js"]:
            with self.assertRaises(GenerationError): w.write(bad, "x")
        w.write("ok/file.js", "x")
        with self.assertRaises(GenerationError): w.write("ok/file.js", "y")        # no silent overwrite
        with self.assertRaises(GenerationError): SafeWriter(self.base / "fresh")   # already generated, overwrite not requested


class RegexRobustnessTests(Base):
    def test_uncompilable_or_hostile_regex_is_never_emitted_and_endpoint_is_stubbed(self):
        from app.validation_response import rules_to_target
        t = rules_to_target({"x": "required|regex:/a\\/); process.exit(3); (/"})
        self.assertEqual(t["status"], "REVIEW_REQUIRED"); self.assertNotIn("process.exit", t["zod_object"])
        ok = rules_to_target({"x": "required|regex:/^[a-z]+$/i"})["zod_object"]
        self.assertIn('new RegExp("^[a-z]+$", "i")', ok)
        root = self.tmp / "php_rx"
        write(root, {"routes/api.php": "<?php\nuse App\\Http\\Controllers\\TController;\nRoute::middleware('auth:sanctum')->post('/t', [TController::class, 'store']);\n",
                     "app/Http/Controllers/Controller.php": "<?php\nnamespace App\\Http\\Controllers;\nabstract class Controller {}\n",
                     "app/Http/Controllers/TController.php": "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\T;\nuse Illuminate\\Http\\Request;\nclass TController extends Controller\n{\n    public function store(Request $request)\n    {\n        $data = $request->validate(['d' => 'required|regex:/a\\\\/); process.exit(3); (/']);\n        $t = T::create($data);\n        return response()->json($t, 201);\n    }\n}\n",
                     "app/Models/T.php": "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass T extends Model\n{\n    protected $fillable = ['d'];\n}\n"})
        m, out = self.generate(src=root, name="rx")
        self.assertEqual(list(m["plan"].values())[0]["action"], "STUB")
        self.assertNotIn("process.exit(3)", "".join(p.read_text() for p in (out / "server/src").rglob("*.js")))


class TwoKeyEnablementTests(Base):
    def test_both_config_flag_and_environment_variable_are_required(self):
        cfg = self.tmp / "models.json"
        on, off = {"CODEBRIDGE_GENERATION_ENABLED": "1"}, {}
        cfg.write_text('{"generation_enabled": false}'); self.assertFalse(generation_enabled(cfg, on))
        cfg.write_text('{"generation_enabled": true}');  self.assertFalse(generation_enabled(cfg, off))
        self.assertFalse(generation_enabled(cfg, {"CODEBRIDGE_GENERATION_ENABLED": "true"}))
        self.assertTrue(generation_enabled(cfg, on))
        cfg.write_text('{"generation_enabled": "yes"}'); self.assertFalse(generation_enabled(cfg, on))   # must be literal true
        cfg.write_text("not json");                       self.assertFalse(generation_enabled(cfg, on))
        self.assertFalse(generation_enabled(self.tmp / "missing.json", on))
        cfg.write_text('{"generation_enabled": false}')
        st = generation_status(cfg, {})
        self.assertFalse(st["enabled"]); self.assertIn("config/models.json", st["instructions"]); self.assertIn("CODEBRIDGE_GENERATION_ENABLED=1", st["instructions"])
        cfg.write_text('{"generation_enabled": true}')
        self.assertEqual(generation_status(cfg, on)["instructions"], "Generation is enabled.")
        repo_cfg = Path(__file__).resolve().parents[1] / "config" / "models.json"
        self.assertFalse(generation_enabled(repo_cfg, on))        # shipped default stays disabled


class PreviewTests(Base):
    def test_preview_is_read_only_and_matches_gate_fingerprint(self):
        before = tree_hash(BLOG)
        pv = preview_generation(BLOG)
        self.assertEqual(pv["source_fingerprint"], source_fingerprint(build_source_contracts(BLOG)))
        self.assertFalse(pv["policy"]["generation_authorized"]); self.assertEqual(tree_hash(BLOG), before)
        self.assertFalse(self.base.exists())


if __name__ == "__main__":
    unittest.main()
