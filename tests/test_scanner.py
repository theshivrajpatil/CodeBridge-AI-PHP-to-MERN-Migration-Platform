import tempfile
import unittest
from pathlib import Path
from app.scanner import scan_repository
from app.planner import build_plan

class ScannerTests(unittest.TestCase):
    def test_inventory_and_php_detection(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); (root/"index.php").write_text("<?php echo 'hello';"); (root/"readme.md").write_text("test")
            result=scan_repository(str(root))
            self.assertEqual(result["file_count"],2); self.assertEqual(result["php_file_count"],1)
            self.assertEqual(result["php_files"][0]["path"],"index.php")
    def test_skips_vendor(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); (root/"index.php").write_text("<?php")
            (root/"vendor").mkdir(); (root/"vendor"/"ignored.php").write_text("<?php")
            self.assertEqual(scan_repository(str(root))["file_count"],1)
    def test_plan_preserves_database_default(self):
        scan={"root":"/sample","file_count":1,"php_file_count":1,"framework_hints":[],"php_files":[{"path":"app/Models/User.php"}]}
        self.assertIn("Preserve the existing database",build_plan(scan)["database_policy"])
if __name__=="__main__": unittest.main()
