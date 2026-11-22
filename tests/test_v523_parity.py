import http.server
import json
import tempfile
import threading
import unittest
from pathlib import Path

from app.differential_testing import (RuntimeConfig, RuntimeConfigError, compare_responses, generate_cases, run_differential,
                                      validate_base_url)
from app.intelligence_pipeline import clear_cache, run_stage
from app.parity_engine import (build_source_contracts, classify, redact, resolve_target_root, run_parity)
from app.target_analysis import analyze_express_project, extract_rules, find_schemas

PHP = {
"composer.json": '{"require":{"laravel/framework":"^11.0","laravel/sanctum":"^4.0"}}',
"bootstrap/app.php": "<?php\nreturn Application::configure(basePath: dirname(__DIR__))\n->withRouting(api: __DIR__.'/../routes/api.php')\n"
                     "->withMiddleware(function (Middleware $middleware) {\n$middleware->alias(['role' => \\App\\Http\\Middleware\\RoleMiddleware::class]);\n})->create();\n",
"routes/api.php": """<?php
use Illuminate\\Support\\Facades\\Route;
use App\\Http\\Controllers\\OrderController;
use App\\Http\\Controllers\\ReportController;
Route::get('/ping', fn () => response()->json(['status' => 'ok']));
Route::middleware('auth:sanctum')->group(function () {
    Route::post('/orders', [OrderController::class, 'store']);
    Route::get('/orders/{order}', [OrderController::class, 'show']);
    Route::delete('/orders/{order}', [OrderController::class, 'destroy']);
});
Route::middleware(['auth:sanctum', 'role:admin'])->get('/admin/report', [ReportController::class, 'index']);
""",
"app/Http/Controllers/Controller.php": "<?php\nnamespace App\\Http\\Controllers;\nabstract class Controller {}\n",
"app/Http/Controllers/ReportController.php": """<?php
namespace App\\Http\\Controllers;
use App\\Models\\Order;
class ReportController extends Controller
{
    public function index()
    {
        return response()->json(['orders' => Order::count()]);
    }
}
""",
"app/Http/Middleware/RoleMiddleware.php": """<?php
namespace App\\Http\\Middleware;
use Closure;
class RoleMiddleware
{
    public function handle($request, Closure $next, string $role)
    {
        if (!$request->user() || $request->user()->role !== $role) {
            abort(403, 'Insufficient role');
        }
        return $next($request);
    }
}
""",
"app/Models/Order.php": "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\nclass Order extends Model\n{\n    protected $fillable = ['item', 'quantity', 'user_id', 'total'];\n}\n",
"app/Models/User.php": "<?php\nnamespace App\\Models;\nuse Illuminate\\Foundation\\Auth\\User as Authenticatable;\nclass User extends Authenticatable {}\n",
"app/Policies/OrderPolicy.php": """<?php
namespace App\\Policies;
use App\\Models\\Order;
use App\\Models\\User;
class OrderPolicy
{
    public function delete(User $user, Order $order): bool
    {
        return $user->id === $order->user_id;
    }
}
""",
}

STORE_OK = """        $data = $request->validate([
            'item' => 'required|string|max:50',
            'quantity' => 'required|integer|min:1|max:100',
        ]);
        if ($data['quantity'] > 50) {
            abort(422, 'Bulk orders need approval');
        }
        $total = $data['quantity'] * 20;
        $discount = $total * 0.10;
        $order = Order::create($data + ['user_id' => $request->user()->id, 'total' => $total - $discount]);
        return response()->json(['order' => $order], 201);
"""


def controller(store=STORE_OK, show="        return response()->json(['order' => $order]);\n"):
    return f"""<?php
namespace App\\Http\\Controllers;
use App\\Models\\Order;
use Illuminate\\Http\\Request;
class OrderController extends Controller
{{
    public function store(Request $request)
    {{
{store}    }}

    public function show(Order $order)
    {{
{show}    }}

    public function destroy(Order $order)
    {{
        $this->authorize('delete', $order);
        $order->delete();
        return response()->noContent();
    }}
}}
"""


def write(root: Path, files: dict):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def php_repo(tmp, store=STORE_OK, show="        return response()->json(['order' => $order]);\n"):
    root = Path(tmp) / "php_shop"
    write(root, {**PHP, "app/Http/Controllers/OrderController.php": controller(store, show)})
    return root


def js_target(tmp, name="mern_shop", discount="0.10", cmp="> 50", qmin=1, created=201, key="order", auth="authenticate, ",
              role="admin", destroy=True, owner=True, stub=False, extra="", item_field=True, hash_secret=False):
    root = Path(tmp) / name
    files = {
        "package.json": '{"type":"module"}',
        "src/app.js": "import express from 'express';\nimport { apiRouter } from './routes/api.js';\nconst app = express();\napp.use('/api', apiRouter);\nexport default app;\n",
        "src/middleware/auth.js": """import jwt from 'jsonwebtoken';
export function authenticate(req, res, next) {
  const token = (req.headers.authorization || '').split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Unauthenticated.' });
  req.user = jwt.verify(token, process.env.JWT_SECRET);
  next();
}
export const requireRole = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) return res.status(403).json({ message: 'This action is unauthorized.' });
  next();
};
""",
        "src/middleware/validate.js": "export const validate = (schema) => (req, res, next) => {\n  const r = schema.safeParse(req.body);\n  if (!r.success) return res.status(422).json({ message: 'invalid', errors: {} });\n  req.valid = r.data;\n  next();\n};\n",
        "src/validators/order.js": "import { z } from 'zod';\nexport const orderSchema = z.object({\n" + ("  item: z.string().min(1).max(50),\n" if item_field else "") +
                                  f"  quantity: z.number().int().min({qmin}).max(100),\n}});\n",
        "src/controllers/ReportController.js": "import { Order } from '../models/Order.js';\nexport const ReportController = {\n  async index(req, res) {\n    const orders = await Order.countDocuments();\n    return res.json({ orders });\n  },\n};\n",
        "src/routes/api.js": f"""import {{ Router }} from 'express';
import {{ authenticate, requireRole }} from '../middleware/auth.js';
import {{ validate }} from '../middleware/validate.js';
import {{ orderSchema }} from '../validators/order.js';
import {{ OrderController }} from '../controllers/OrderController.js';
import {{ ReportController }} from '../controllers/ReportController.js';
export const apiRouter = Router();
apiRouter.get('/ping', (req, res) => res.json({{ status: 'ok' }}));
apiRouter.post('/orders', {auth}validate(orderSchema), OrderController.store);
apiRouter.get('/orders/:id', {auth}OrderController.show);
{"apiRouter.delete('/orders/:id', " + auth + "OrderController.destroy);" if destroy else ""}
apiRouter.get('/admin/report', authenticate, requireRole('{role}'), ReportController.index);
{extra}
""",
    }
    owner_line = "    if (String(order.user_id) !== String(req.user.id)) return res.status(403).json({ message: 'This action is unauthorized.' });\n" if owner else ""
    store_body = ("    throw new Error('not implemented'); // 501\n" if stub else
                  f"""    const {{ item, quantity }} = req.valid;
    if (quantity {cmp}) return res.status(422).json({{ message: 'Bulk orders need approval' }});
    const total = quantity * 20;
    const discount = total * {discount};
    {"const JWT_SECRET = 'hunter2-super-secret-value';" if hash_secret else ""}
    const order = await Order.create({{ item, quantity, user_id: req.user.id, total: total - discount }});
    return res.status({created}).json({{ {key if key == 'order' else key + ': order'} }});
""")
    files["src/controllers/OrderController.js"] = f"""import {{ Order }} from '../models/Order.js';
export const OrderController = {{
  async store(req, res) {{
{store_body}  }},
  async show(req, res) {{
    const order = await Order.findById(req.params.id);
    if (!order) return res.status(404).json({{ message: 'Not found' }});
    return res.json({{ order }});
  }},
  async destroy(req, res) {{
    const order = await Order.findById(req.params.id);
    if (!order) return res.status(404).json({{ message: 'Not found' }});
{owner_line}    await order.deleteOne();
    return res.status(204).send();
  }},
}};
"""
    write(root, files)
    return root


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(); self.tmp = self._tmp.name; clear_cache()
    def tearDown(self): self._tmp.cleanup(); clear_cache()
    def run_pair(self, php=None, **js):
        src = php or php_repo(self.tmp)
        return run_parity(src, js_target(self.tmp, **js))
    @staticmethod
    def by(report):
        return {(c["method"], c["uri"]): c for c in report["contracts"]}
    @staticmethod
    def dims(contract, result="MISMATCH"):
        return {k["dimension"] for k in contract["checks"] if k["result"] == result}


class IdenticalBehaviourTests(Base):
    def test_1_identical_behaviour_is_verified_equivalent_statically(self):
        r = self.run_pair(); by = self.by(r)
        for key in [("POST", "/api/orders"), ("GET", "/api/orders/{order}"), ("DELETE", "/api/orders/{order}"), ("GET", "/api/admin/report"), ("GET", "/api/ping")]:
            self.assertEqual(by[key]["status"], "VERIFIED_EQUIVALENT", (key, [k for k in by[key]["checks"] if k["result"] != "MATCH"]))
            self.assertEqual(by[key]["evidence_level"], "STATIC_ONLY")
            self.assertTrue(by[key]["human_review_required"])
        self.assertEqual(r["extra_target_routes"], [])


class MismatchDetectionTests(Base):
    def test_2_business_rule_value_mismatch(self):
        c = self.by(self.run_pair(discount="0.15"))[("POST", "/api/orders")]
        self.assertEqual(c["status"], "VERIFIED_MISMATCH")
        chk = next(k for k in c["checks"] if k["dimension"] == "business_rule" and k["result"] == "MISMATCH")
        self.assertIn("0.1", chk["difference"]); self.assertIn("0.15", chk["difference"])
        self.assertIn("discount", chk["source_evidence"]["detail"]); self.assertIn("discount", chk["target_evidence"]["detail"])
        self.assertEqual(chk["source_evidence"]["contract"], c["callable_contract_id"])

    def test_3_conditional_logic_mismatch(self):
        c = self.by(self.run_pair(cmp=">= 50"))[("POST", "/api/orders")]
        self.assertEqual(c["status"], "VERIFIED_MISMATCH")
        self.assertTrue(any("quantity > 50" in k["difference"] for k in c["checks"] if k["result"] == "MISMATCH"))

    def test_4_validation_rule_mismatch(self):
        c = self.by(self.run_pair(qmin=2))[("POST", "/api/orders")]
        self.assertIn("validation", self.dims(c)); self.assertIn("min=1, target min=2", " ".join(c["differences"]))
        missing = self.by(self.run_pair(item_field=False))[("POST", "/api/orders")]
        self.assertTrue(any("'item' missing" in d for d in missing["differences"]))

    def test_5_http_status_mismatch(self):
        c = self.by(self.run_pair(created=200))[("POST", "/api/orders")]
        self.assertIn("status", self.dims(c)); self.assertTrue(any("201" in d and "200" in d for d in c["differences"]))

    def test_6_response_structure_mismatch(self):
        c = self.by(self.run_pair(key="data"))[("POST", "/api/orders")]
        self.assertIn("response", self.dims(c)); self.assertTrue(any("'order'" in d and "'data'" in d for d in c["differences"]))

    def test_7_authentication_mismatch(self):
        r = self.run_pair(auth="")
        c = self.by(r)[("POST", "/api/orders")]
        chk = next(k for k in c["checks"] if k["dimension"] == "authentication")
        self.assertEqual((chk["result"], chk["severity"]), ("MISMATCH", "critical")); self.assertEqual(c["max_severity"], "critical")

    def test_8_authorization_mismatch(self):
        r = self.run_pair(role="editor"); by = self.by(r)
        self.assertIn("authorization", self.dims(by[("GET", "/api/admin/report")]))
        d = self.by(self.run_pair(owner=False))[("DELETE", "/api/orders/{order}")]
        self.assertEqual(d["status"], "VERIFIED_MISMATCH"); self.assertIn("authorization", self.dims(d))


class MissingAndUnverifiedTests(Base):
    def test_9_missing_and_stubbed_target_implementation(self):
        by = self.by(self.run_pair(destroy=False))
        self.assertEqual(by[("DELETE", "/api/orders/{order}")]["status"], "NOT_IMPLEMENTED")
        self.assertEqual(self.by(self.run_pair(stub=True))[("POST", "/api/orders")]["status"], "NOT_IMPLEMENTED")

    def test_10_incomplete_source_evidence_is_never_equivalent(self):
        php = php_repo(self.tmp, store="        $data = $request->validate($this->rules());\n        $order = Order::create($data + ['user_id' => $request->user()->id]);\n        return response()->json(['order' => $order], 201);\n")
        c = self.by(self.run_pair(php=php))[("POST", "/api/orders")]
        self.assertNotIn(c["status"], ("VERIFIED_EQUIVALENT",))
        self.assertTrue(any(k["dimension"] == "source_evidence" and k["result"] == "UNVERIFIED" for k in c["checks"]))

    def test_11_dynamic_or_unsupported_behaviour_is_unverified(self):
        store = STORE_OK.replace("        $total =", "        $rows = DB::select('select 1');\n        $total =")
        c = self.by(self.run_pair(php=php_repo(self.tmp, store=store)))[("POST", "/api/orders")]
        self.assertTrue(any(k["dimension"] == "unsupported_dynamic_behaviour" and k["result"] == "UNVERIFIED" for k in c["checks"]))
        self.assertNotEqual(c["status"], "VERIFIED_EQUIVALENT")

    def test_unresolved_target_middleware_downgrades_to_unverified_not_mismatch(self):
        r = self.run_pair(auth="mysteryGuard, ", extra="")
        c = self.by(r)[("GET", "/api/orders/{order}")]
        self.assertNotEqual(c["status"], "VERIFIED_EQUIVALENT")
        self.assertFalse(any(k["dimension"] == "authentication" and k["result"] == "MATCH" for k in c["checks"]))


class ClassificationAndMetricsTests(Base):
    def test_14_status_classification(self):
        M = lambda d, r: {"dimension": d, "result": r}
        self.assertEqual(classify([M("route", "MATCH"), M("validation", "MATCH")], True, False, False), "VERIFIED_EQUIVALENT")
        self.assertEqual(classify([M("validation", "MATCH"), M("status", "MISMATCH")], True, False, False), "VERIFIED_MISMATCH")
        self.assertEqual(classify([M("validation", "MATCH"), M("status", "UNVERIFIED")], True, False, False), "PARTIALLY_VERIFIED")
        self.assertEqual(classify([M("status", "UNVERIFIED")], True, False, False), "UNVERIFIED")
        self.assertEqual(classify([M("route", "MATCH")], True, False, False), "UNVERIFIED")  # route existence alone is not behaviour
        self.assertEqual(classify([], False, False, False), "NOT_IMPLEMENTED")
        self.assertEqual(classify([M("validation", "MATCH")], True, True, False), "NOT_IMPLEMENTED")
        self.assertEqual(classify([M("validation", "MATCH")], True, False, True), "BLOCKED")

    def test_15_coverage_calculation_is_transparent(self):
        m = self.run_pair(destroy=False, discount="0.15")["metrics"]
        parts = sum(m[k] for k in ("verified_equivalent", "verified_mismatch", "partially_verified", "not_implemented", "unverified", "blocked"))
        self.assertEqual(parts, m["total_source_contracts"])
        self.assertEqual(m["static_verification_coverage"], round(m["verified_equivalent"] / m["total_source_contracts"], 4))
        self.assertIn("verified_equivalent contracts / total_source_contracts", m["coverage_definition"])
        self.assertIn("not proof", m["coverage_warning"])
        self.assertEqual(m["runtime_tests_executed"], 0)

    def test_blocked_when_handler_file_is_unreadable(self):
        tgt = js_target(self.tmp)
        (tgt / "src/controllers/OrderController.js").write_text("x" * 600_000)   # exceeds analysis size limit
        r = run_parity(php_repo(self.tmp), tgt)
        self.assertEqual(self.by(r)[("POST", "/api/orders")]["status"], "BLOCKED")


class ReportAndIntegrationTests(Base):
    def test_16_report_structure_and_determinism(self):
        r1, r2 = self.run_pair(), run_parity(php_repo(self.tmp), Path(self.tmp) / "mern_shop")
        json.dumps(r1)
        for k in ("project_id", "source", "target", "contracts", "metrics", "runtime", "policy", "report_fingerprint", "extra_target_routes"):
            self.assertIn(k, r1)
        c = r1["contracts"][0]
        for k in ("contract_id", "status", "checks", "differences", "max_severity", "verification_method", "limitations", "recommendation", "human_review_required", "source", "target"):
            self.assertIn(k, c)
        self.assertEqual(r1["report_fingerprint"], r2["report_fingerprint"])
        self.assertFalse(r1["policy"]["auto_approval"]); self.assertFalse(r1["policy"]["generation_authorized"])

    def test_18_uses_actual_v5_19_to_v5_22_outputs(self):
        src = php_repo(self.tmp); r = run_parity(src, js_target(self.tmp))
        callables = {c["id"] for c in run_stage(src, "contracts")["callable_contracts"]}
        routes = {x["id"] for x in run_stage(src, "routes")["routes"]}
        ids = {c["contract_id"] for c in r["contracts"]}
        self.assertEqual(ids, routes)
        self.assertTrue({c["callable_contract_id"] for c in r["contracts"] if c["callable_contract_id"]} <= callables)
        self.assertEqual(r["source"]["stages_used"], ["dependency-graph", "contracts", "routes", "auth", "validation-response"])
        self.assertEqual(r["source"]["graph_fingerprint"], run_stage(src, "dependency-graph")["fingerprint"])

    def test_laravel_blog_fixture_end_to_end(self):
        root = Path(__file__).resolve().parents[1] / "examples"
        r = run_parity(root / "laravel_blog_fixture", root / "express_blog_target_fixture")
        by = self.by(r)
        self.assertEqual(by[("DELETE", "/api/posts/{post}")]["status"], "VERIFIED_MISMATCH")   # admin branch missing in target
        self.assertEqual(by[("POST", "/api/login")]["status"], "NOT_IMPLEMENTED")
        self.assertEqual(r["metrics"]["excluded_web_contracts"], 1)


class SecurityTests(Base):
    def test_17_target_path_validation(self):
        src = php_repo(self.tmp)
        for bad in ["", str(Path(self.tmp) / "missing"), str(src), str(src / "app")]:
            with self.assertRaises((ValueError, FileNotFoundError)): resolve_target_root(bad, str(src))
        real = js_target(self.tmp); link = Path(self.tmp) / "link"; link.symlink_to(real)
        with self.assertRaises(ValueError): resolve_target_root(str(link), str(src))

    def test_17_symlinked_target_files_are_never_read(self):
        tgt = js_target(self.tmp); outside = Path(self.tmp) / "outside.js"; outside.write_text("export const leaked = 1;")
        (tgt / "src/leak.js").symlink_to(outside)
        t = analyze_express_project(tgt)
        self.assertNotIn("src/leak.js", t["texts"])

    def test_17_secrets_are_redacted_and_code_is_never_executed(self):
        tgt = js_target(self.tmp, hash_secret=True)
        (tgt / "src/evil.js").write_text("import { execSync } from 'child_process';\nexecSync('touch " + str(Path(self.tmp) / "PWNED") + "');\n")
        r = run_parity(php_repo(self.tmp), tgt)
        self.assertNotIn("hunter2", json.dumps(r)); self.assertFalse((Path(self.tmp) / "PWNED").exists())
        self.assertEqual(redact("Authorization: Bearer abcdefghijklmnop"), "Authorization: Bearer [REDACTED]")
        self.assertIn("[REDACTED]", redact("const password = 'topsecretvalue'"))


class DifferentialRuntimeTests(Base):
    @staticmethod
    def server(routes):
        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def _go(self):
                status, body = routes.get((self.command, self.path), (404, {"message": "nf"}))
                data = json.dumps(body).encode()
                self.send_response(status); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
            do_GET = do_POST = do_DELETE = _go
        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv, f"http://127.0.0.1:{srv.server_address[1]}"

    def cases(self, cfg):
        return generate_cases(build_source_contracts(php_repo(self.tmp))["contracts"], cfg)

    def test_12_runtime_unavailable_is_blocked_not_passed(self):
        cfg = RuntimeConfig("http://127.0.0.1:1", "http://127.0.0.1:2")
        out = run_differential(self.cases(cfg), cfg)
        self.assertEqual((out["status"], out["results"]), ("BLOCKED", []))
        r = run_parity(php_repo(self.tmp), js_target(self.tmp), out)
        self.assertFalse(r["runtime"]["performed"]); self.assertEqual(r["runtime"]["status"], "BLOCKED")
        self.assertTrue(all(c["evidence_level"] == "STATIC_ONLY" for c in r["contracts"]))
        unreachable = RuntimeConfig("http://127.0.0.1:1", "http://127.0.0.1:2", enabled=True, timeout_seconds=0.5)
        res = run_differential(self.cases(unreachable), unreachable)["results"]
        self.assertTrue(res and all(x["status"] in ("BLOCKED", "SKIPPED") for x in res))

    def test_13_differential_mismatch_and_pass(self):
        same = {("GET", "/api/ping"): (200, {"status": "ok"}), ("GET", "/api/admin/report"): (401, {"message": "Unauthenticated."})}
        diff = {**same, ("GET", "/api/ping"): (200, {"status": "OK"})}
        s1, src_url = self.server(same); s2, ok_url = self.server(same); s3, bad_url = self.server(diff)
        try:
            cfg = RuntimeConfig(src_url, ok_url, enabled=True)
            passed = run_differential(self.cases(cfg), cfg)
            self.assertEqual(passed["summary"]["failed"], 0); self.assertGreaterEqual(passed["summary"]["passed"], 2)
            r = run_parity(php_repo(self.tmp), js_target(self.tmp), passed)
            ping = self.by(r)[("GET", "/api/ping")]
            self.assertEqual((ping["status"], ping["evidence_level"]), ("VERIFIED_EQUIVALENT", "STATIC_AND_RUNTIME"))
            self.assertGreaterEqual(r["metrics"]["runtime_tests_passed"], 2)
            cfg2 = RuntimeConfig(src_url, bad_url, enabled=True)
            failed = run_differential(self.cases(cfg2), cfg2)
            self.assertEqual(failed["summary"]["failed"], 1)
            r2 = run_parity(php_repo(self.tmp), js_target(self.tmp), failed)
            ping2 = self.by(r2)[("GET", "/api/ping")]
            self.assertEqual(ping2["status"], "VERIFIED_MISMATCH"); self.assertIn("status", ping2["differences"][0])
            self.assertEqual(r2["metrics"]["runtime_tests_failed"], 1)
        finally:
            for s in (s1, s2, s3):
                s.shutdown(); s.server_close()

    def test_17_runtime_safety_controls(self):
        for bad in ["http://example.com", "http://user:pw@127.0.0.1:80", "ftp://127.0.0.1", "http://10.0.0.5"]:
            with self.assertRaises(RuntimeConfigError): validate_base_url(bad)
        self.assertEqual(validate_base_url("http://localhost:3000"), "http://localhost:3000")
        calls = []
        cfg = RuntimeConfig("http://127.0.0.1:9", "http://127.0.0.1:9", enabled=True, path_params={"order": "1"}, source_token="t1", target_token="t2")
        cases = [{"route_id": "x", "case": "valid_payload", "method": "POST", "path": "/api/orders", "auth": True, "body": {}, "note": "", "missing_params": []}]
        out = run_differential(cases, cfg, transport=lambda *a: calls.append(a) or {"status": 200, "headers": {}, "body": "{}"})
        self.assertEqual((out["results"][0]["status"], calls), ("SKIPPED", []))          # mutating refused without allow_mutating
        cfg.allow_mutating = True
        out = run_differential(cases, cfg, transport=lambda *a: calls.append(a) or {"status": 200, "headers": {}, "body": "{\"token\": \"abc\"}"})
        self.assertEqual(out["results"][0]["status"], "PASSED"); self.assertNotIn("t1", json.dumps(out))
        self.assertEqual(run_differential(cases, RuntimeConfig("http://8.8.8.8", "http://127.0.0.1:1", enabled=True))["status"], "BLOCKED")

    def test_response_comparison_does_not_normalise_meaningful_differences(self):
        cfg = RuntimeConfig("", "", ignore_paths=("data.created_at",))
        a = {"status": 200, "headers": {"content-type": "application/json"}, "body": json.dumps({"data": {"id": 1, "amount": 10, "created_at": "x", "token": "aaa"}})}
        b = {"status": 200, "headers": {"content-type": "application/json; charset=utf-8"}, "body": json.dumps({"data": {"id": 2, "amount": 15, "created_at": "y", "token": "bbb"}})}
        diffs = compare_responses(a, b, cfg)
        self.assertTrue(any("data.id" in d for d in diffs)); self.assertTrue(any("data.amount" in d for d in diffs))
        self.assertFalse(any("created_at" in d for d in diffs)); self.assertFalse(any("data.token" in d for d in diffs))


class TargetAnalysisTests(unittest.TestCase):
    def test_rules_and_schemas(self):
        self.assertEqual(extract_rules("$discount = $total * 0.10;", php=True)[0]["factor"], 0.1)
        self.assertEqual(extract_rules("const d = total * 10 / 100;")[0]["factor"], 0.1)
        s = find_schemas("export const s = z.object({ a: z.string().min(2).optional(), b: z.enum(['x','y']) });", "f.js")["s"]["fields"]
        self.assertFalse(s["a"]["required"]); self.assertEqual(s["b"]["constraints"]["in"], ["x", "y"])


if __name__ == "__main__":
    unittest.main()
