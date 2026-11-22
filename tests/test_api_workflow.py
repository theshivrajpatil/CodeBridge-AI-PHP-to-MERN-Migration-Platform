import unittest
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient
import app.main as main_module
from app.main import app


class ApiWorkflowTests(unittest.TestCase):
    def setUp(self):
        # API integration tests must never write test approvals/reports into the
        # developer's real workspace or contaminate a later local session.
        self.workspace_context = tempfile.TemporaryDirectory()
        self.original_workspace = main_module.WORKSPACE
        self.original_session_file = main_module.SESSION_FILE
        main_module.WORKSPACE = Path(self.workspace_context.name)
        main_module.WORKSPACE.mkdir(parents=True, exist_ok=True)
        main_module.SESSION_FILE = main_module.WORKSPACE / "latest_session.json"

    def tearDown(self):
        main_module.WORKSPACE = self.original_workspace
        main_module.SESSION_FILE = self.original_session_file
        main_module.LATEST_SCAN = None
        main_module.LATEST_ANALYSIS = None
        main_module.LATEST_PLAN = None
        main_module.LATEST_SPECIFICATION = None
        self.workspace_context.cleanup()

    def test_laravel_fixture_full_workflow_does_not_fail(self):
        fixture = Path(__file__).resolve().parents[1] / "examples" / "laravel_dependency_fixture"
        client = TestClient(app)
        scan = client.post("/api/scan", json={"path": str(fixture)})
        self.assertEqual(scan.status_code, 200, scan.text)
        for endpoint in ("/api/analyze", "/api/behavior", "/api/dependencies", "/api/plan", "/api/specification"):
            response = client.post(endpoint)
            self.assertEqual(response.status_code, 200, f"{endpoint}: {response.text}")
        specification = response.json()
        self.assertTrue(specification["generation_metadata"]["validated"])
        self.assertEqual(specification["generation_metadata"]["migration_unit_count"], len(specification["migration_units"]))
        saved_spec = Path(specification["report_file"])
        self.assertTrue(saved_spec.is_file())
        import json
        persisted_spec = json.loads(saved_spec.read_text(encoding="utf-8"))
        self.assertEqual(persisted_spec["report_file"], str(saved_spec))
        self.assertFalse(persisted_spec["generation_metadata"]["generation_enabled"])

        # Session metadata restores the latest project/specification after process restart.
        state_before = client.get("/api/state")
        self.assertEqual(state_before.status_code, 200)
        self.assertTrue(state_before.json()["specification_ready"])
        main_module.LATEST_SCAN = None
        main_module.LATEST_ANALYSIS = None
        main_module.LATEST_PLAN = None
        main_module.LATEST_SPECIFICATION = None
        main_module._restore_session()
        state_after = client.get("/api/state").json()
        self.assertTrue(state_after["scanned"])
        self.assertTrue(state_after["specification_ready"])

        units_response = client.get("/api/migration-units")
        self.assertEqual(units_response.status_code, 200, units_response.text)
        units = units_response.json()["units"]
        self.assertGreaterEqual(len(units), 1)
        self.assertTrue(all(u["generation_authorized"] is False for u in units))
        first = units[0]
        missing_confirmation = client.post(f"/api/migration-units/{first['unit_id']}/decision", json={
            "decision": "APPROVED", "actor": "test-reviewer", "reason": "Reviewed evidence in API workflow test",
            "expected_fingerprint": first["spec_fingerprint"], "confirm_reviewed": False})
        self.assertEqual(missing_confirmation.status_code, 422)
        stale_fingerprint = client.post(f"/api/migration-units/{first['unit_id']}/decision", json={
            "decision": "APPROVED", "actor": "test-reviewer", "reason": "Reviewed evidence in API workflow test",
            "expected_fingerprint": "0" * 64, "confirm_reviewed": True})
        self.assertEqual(stale_fingerprint.status_code, 409)
        decision = client.post(f"/api/migration-units/{first['unit_id']}/decision", json={
            "decision": "APPROVED", "actor": "test-reviewer", "reason": "Reviewed evidence in API workflow test",
            "expected_fingerprint": first["spec_fingerprint"], "confirm_reviewed": True})
        self.assertEqual(decision.status_code, 200, decision.text)
        self.assertFalse(decision.json()["generation_authorized"])
        audit = client.get("/api/migration-approvals/audit")
        self.assertEqual(audit.status_code, 200, audit.text)
        self.assertGreaterEqual(audit.json()["count"], 1)
        self.assertEqual(audit.json()["integrity"], "VERIFIED")
        self.assertTrue(decision.json()["approval"].get("event_hash"))
        refreshed_units = client.get("/api/migration-units")
        self.assertEqual(refreshed_units.status_code, 200, refreshed_units.text)
        refreshed_first = next(unit for unit in refreshed_units.json()["units"] if unit["unit_id"] == first["unit_id"])
        self.assertEqual(refreshed_first["status"], "APPROVED")
        self.assertEqual(refreshed_first["approval"]["event_hash"], decision.json()["approval"]["event_hash"])
        self.assertFalse(refreshed_first["generation_authorized"])
        dependency = client.post("/api/dependencies").json()
        self.assertFalse(any(
            op.get("source_path") == "routes/web.php" and op.get("model_or_facade") == "Route"
            for op in dependency.get("database_operations", [])
        ))


if __name__ == "__main__":
    unittest.main()
