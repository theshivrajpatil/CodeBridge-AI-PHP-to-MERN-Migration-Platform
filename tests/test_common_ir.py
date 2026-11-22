import unittest
from app.intermediate_representation import build_common_ir

class CommonIRTests(unittest.TestCase):
    def test_common_ir_is_framework_neutral_and_keeps_unknowns(self):
        scan = {"root": "/tmp/project", "file_count": 2, "php_file_count": 2, "warnings": []}
        analysis = {
            "framework_detection": {"name": "Symfony", "confidence": "HIGH", "adapter_id": "symfony"},
            "php_files_analyzed": 2,
            "files": [
                {"path": "src/Controller/UserController.php", "status": "ANALYZED", "analysis_mode": "TREE_SITTER_AST",
                 "classification": {"group": "Controllers", "confidence": "HIGH"}, "classes": ["UserController"],
                 "interfaces": [], "traits": [], "functions": [], "methods": ["index"], "route_candidates": [],
                 "database_signals": [], "output_signals": [], "includes": []},
                {"path": "templates/user.html.twig", "status": "ANALYZED", "analysis_mode": "TREE_SITTER_AST",
                 "classification": {"group": "Templates", "confidence": "HIGH"}, "classes": [],
                 "interfaces": [], "traits": [], "functions": [], "methods": [], "route_candidates": [],
                 "database_signals": [], "output_signals": [], "includes": []}
            ],
            "dependency_intelligence": {"edges": [], "unresolved_relationships": [], "coverage": {"runtime_call_order_verified": False}},
            "behavior_report": {"route_contracts": []}, "limitations": ["static only"]
        }
        ir = build_common_ir(scan, analysis)
        self.assertEqual(ir["schema"], "codebridge.common_application_representation")
        self.assertEqual(len(ir["components"]["controllers"]), 1)
        self.assertEqual(len(ir["components"]["templates"]), 1)
        self.assertFalse(ir["uncertainties"]["runtime_call_order_verified"])
        self.assertFalse(ir["safety"]["generation_authorized"])

if __name__ == "__main__": unittest.main()
