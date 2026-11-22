import tempfile
import unittest
from pathlib import Path
from app.migration_units import build_migration_units, apply_decision, load_approval_store, save_approval_store, validate_unit_sources, approval_store_lock

class MigrationUnitTests(unittest.TestCase):
    def fixture(self, root):
        for name in ("Route.php", "Controller.php", "Model.php", "Standalone.php"):
            (root / name).write_text("<?php // " + name)
        files = [{"path":n,"status":"ANALYZED","analysis_mode":"TREE_SITTER_AST","classification":{"group":"Other PHP"},"classes":[],"methods":[],"signals":[]} for n in ("Route.php","Controller.php","Model.php","Standalone.php")]
        analysis = {"files":files,"dependency_graph":{"edges":[
            {"from":"Route.php","to":"Controller.php","type":"imports","evidence":["use Controller"]},
            {"from":"Controller.php","to":"Model.php","type":"uses_model","evidence":["new Model"]}]},
            "behavior_report":{"route_contracts":[{"source_path":"Route.php","http_method":"GET","path":"/"}],"callable_contracts":[]}}
        scan={"root":str(root)}; plan={"php_file_groups":{"Routes":["Route.php"],"Controllers":["Controller.php"],"Models":["Model.php"],"Other PHP":["Standalone.php"]}}
        return scan,analysis,plan

    def test_connected_files_grouped_and_singleton_retained(self):
        with tempfile.TemporaryDirectory() as d:
            scan,analysis,plan=self.fixture(Path(d)); units=build_migration_units(scan,analysis,plan)
            self.assertEqual(sorted(u["source_file_count"] for u in units),[1,3])
            connected=next(u for u in units if u["source_file_count"]==3)
            self.assertEqual(connected["dependency_edge_count"],2)
            self.assertEqual(len(connected["route_contracts"]),1)
            self.assertFalse(connected["generation_authorized"])

    def test_source_changes_invalidate_review_unit(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); scan,analysis,plan=self.fixture(root)
            unit=next(u for u in build_migration_units(scan,analysis,plan) if u["source_file_count"]==3)
            valid,changed=validate_unit_sources(unit,str(root))
            self.assertTrue(valid); self.assertEqual(changed,[])
            (root/"Route.php").write_text("<?php class Changed {}")
            valid,changed=validate_unit_sources(unit,str(root))
            self.assertFalse(valid); self.assertIn("Route.php",changed)

    def test_approval_requires_actor_reason_and_never_authorizes_generation(self):
        unit={"unit_id":"unit-test","spec_fingerprint":"abc","status":"PENDING_REVIEW"}
        store={"decisions":{},"audit_log":[]}
        with self.assertRaises(ValueError): apply_decision(unit,store,"APPROVED","","ok")
        record=apply_decision(unit,store,"APPROVED","reviewer","Reviewed source evidence")
        self.assertEqual(record["decision"],"APPROVED")
        self.assertFalse(record["generation_authorized"])
        self.assertFalse(unit["generation_authorized"])
        self.assertEqual(len(store["audit_log"]),1)
        changed = dict(unit, spec_fingerprint="new-version")
        apply_decision(changed, store, "CHANGES_REQUESTED", "reviewer", "Re-review changed source")
        self.assertEqual(len(store["audit_log"]), 2)


    def test_audit_chain_detects_modified_event(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); source=root/"A.php"; source.write_text("<?php class A {}")
            scan={"root":str(root)}
            analysis={"files":[{"path":"A.php","status":"ANALYZED","analysis_mode":"TREE_SITTER_AST","classification":{"group":"Other PHP"},"classes":["A"],"methods":[]}],"dependency_graph":{"edges":[]}}
            unit=build_migration_units(scan,analysis,{"php_file_groups":{}})[0]
            unit["source_validation"]={"valid":True,"changed_paths":[]}
            store={"store_version":2,"decisions":{},"audit_log":[]}
            apply_decision(unit,store,"APPROVED","reviewer","Checked source")
            path=root/"approvals.json"; save_approval_store(path,store)
            loaded=load_approval_store(path)
            self.assertEqual(loaded["audit_log"][0]["event_hash"],store["audit_log"][0]["event_hash"])
            loaded["audit_log"][0]["reason"]="tampered"
            save_approval_store(path,loaded)
            with self.assertRaisesRegex(ValueError,"integrity check failed"):
                load_approval_store(path)


    def test_decision_index_tampering_is_detected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); source=root/"A.php"; source.write_text("<?php class A {}")
            analysis={"files":[{"path":"A.php","status":"ANALYZED","analysis_mode":"TREE_SITTER_AST","classification":{"group":"Other PHP"},"classes":["A"],"methods":[]}],"dependency_graph":{"edges":[]}}
            unit=build_migration_units({"root":str(root)},analysis,{"php_file_groups":{}})[0]
            unit["source_validation"]={"valid":True,"changed_paths":[]}
            store={"store_version":2,"decisions":{},"audit_log":[]}
            apply_decision(unit,store,"APPROVED","reviewer","Checked source")
            store["decisions"][f"{unit['unit_id']}:{unit['spec_fingerprint']}"]["reason"]="changed without audit"
            path=root/"approvals.json"; save_approval_store(path,store)
            with self.assertRaisesRegex(ValueError,"decision index"):
                load_approval_store(path)

    def test_lock_file_is_created_and_store_roundtrips_inside_lock(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"approvals.json"
            with approval_store_lock(path):
                save_approval_store(path,{"store_version":2,"decisions":{},"audit_log":[]})
                self.assertEqual(load_approval_store(path)["store_version"],2)
            self.assertTrue(Path(str(path)+".lock").exists())

    def test_fingerprint_changes_when_review_evidence_changes(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); scan,analysis,plan=self.fixture(root)
            first=build_migration_units(scan,analysis,plan)
            analysis["behavior_report"]["route_contracts"][0]["path"]="/changed"
            second=build_migration_units(scan,analysis,plan)
            unit_a=next(u for u in first if u["source_file_count"]==3)
            unit_b=next(u for u in second if u["source_file_count"]==3)
            self.assertNotEqual(unit_a["spec_fingerprint"],unit_b["spec_fingerprint"])

    def test_fingerprint_changes_when_target_mapping_changes(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); scan,analysis,plan=self.fixture(root)
            first=build_migration_units(scan,analysis,plan)
            plan["php_file_groups"]["Controllers"]=["Standalone.php"]
            plan["php_file_groups"]["Other PHP"]=[]
            second=build_migration_units(scan,analysis,plan)
            unit_a=next(u for u in first if "Standalone.php" in u["source_paths"])
            unit_b=next(u for u in second if "Standalone.php" in u["source_paths"])
            self.assertNotEqual(unit_a["spec_fingerprint"],unit_b["spec_fingerprint"])

    def test_missing_source_fingerprint_invalidates_unit(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); scan,analysis,plan=self.fixture(root)
            unit=next(u for u in build_migration_units(scan,analysis,plan) if u["source_file_count"]==3)
            unit["file_fingerprints"].pop("Route.php")
            valid,changed=validate_unit_sources(unit,str(root))
            self.assertFalse(valid)
            self.assertIn("Route.php",changed)

    def test_approval_store_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"approvals.json"; store={"store_version":1,"decisions":{},"audit_log":[]}
            save_approval_store(path,store)
            self.assertEqual(load_approval_store(path)["store_version"],2)

if __name__ == "__main__": unittest.main()
