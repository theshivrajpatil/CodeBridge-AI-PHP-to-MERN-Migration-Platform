import unittest
from app.architecture_intelligence import enrich_dependency_intelligence

class ArchitectureIntelligenceTests(unittest.TestCase):
    def test_subsystems_and_transitive_impact(self):
        dep = {"nodes": [
            {"id":"routes/web.php","kind":"SOURCE_FILE","role":"Routes","symbols":[]},
            {"id":"app/Controller.php","kind":"SOURCE_FILE","role":"Controllers","symbols":["UserController"]},
            {"id":"app/Service.php","kind":"SOURCE_FILE","role":"Services","symbols":["UserService"]},
            {"id":"app/Repo.php","kind":"SOURCE_FILE","role":"Repositories","symbols":["UserRepo"]}],
            "edges": [
                {"from":"routes/web.php","to":"app/Controller.php","type":"route_dispatches_to","evidence":["line 8: controller UserController"]},
                {"from":"app/Controller.php","to":"app/Service.php","type":"instantiates","evidence":["line 12: new UserService"]},
                {"from":"app/Service.php","to":"app/Repo.php","type":"instantiates","evidence":["line 4: new UserRepo"]}]}
        result = enrich_dependency_intelligence(dep, {"framework_detection":{"adapter_id":"generic_php"}})
        self.assertEqual(result["impact_index"]["app/Repo.php"], ["app/Controller.php", "app/Service.php", "routes/web.php"])
        self.assertEqual(result["architecture_summary"]["subsystem_count"], 1)
        self.assertEqual(result["edges"][0]["evidence_records"][0]["line"], 8)


    def test_duplicate_edges_merge_all_source_evidence(self):
        dep = {"nodes": [{"id":"a.php","role":"Controllers"},{"id":"b.php","role":"Services"}],
               "edges": [
                   {"from":"a.php","to":"b.php","type":"calls","evidence":["line 4: new ServiceA"]},
                   {"from":"a.php","to":"b.php","type":"calls","evidence":["line 9: invoke execute"]}]}
        result = enrich_dependency_intelligence(dep, {})
        self.assertEqual(result["edge_count"], 1)
        self.assertEqual({x["line"] for x in result["edges"][0]["evidence_records"]}, {4, 9})

    def test_impact_paths_preserve_dependency_direction(self):
        dep = {"nodes": [{"id":"route.php","role":"Routes"},
                         {"id":"controller.php","role":"Controllers"},
                         {"id":"service.php","role":"Services"},
                         {"id":"repo.php","role":"Repositories"}],
               "edges": [
                   {"from":"route.php","to":"controller.php","type":"dispatches"},
                   {"from":"controller.php","to":"service.php","type":"calls"},
                   {"from":"service.php","to":"repo.php","type":"calls"}]}
        result = enrich_dependency_intelligence(dep, {})
        self.assertEqual(result["impact_paths"]["repo.php"]["route.php"],
                         ["route.php", "controller.php", "service.php", "repo.php"])
        self.assertEqual(result["impact_index"]["repo.php"],
                         ["controller.php", "route.php", "service.php"])

    def test_ambiguous_route_controller_is_not_linked(self):
        dep = {"nodes":[
            {"id":"routes/web.php","role":"Routes","symbols":[]},
            {"id":"A/UserController.php","role":"Controllers","symbols":["UserController"]},
            {"id":"B/UserController.php","role":"Controllers","symbols":["UserController"]}], "edges":[]}
        analysis = {"behavior_report":{"route_contracts":[{"source_path":"routes/web.php","source_line":4,"controller":"UserController@index"}]}}
        result = enrich_dependency_intelligence(dep, analysis)
        self.assertEqual(result["edges"], [])

if __name__ == "__main__": unittest.main()
