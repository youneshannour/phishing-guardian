import json
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
EXT = BASE / "extension"


class TestExtensionAPI(unittest.TestCase):
    def test_extension_folder_exists(self):
        self.assertTrue(EXT.is_dir())

    def test_manifest_valid(self):
        manifest_path = EXT / "manifest.json"
        self.assertTrue(manifest_path.is_file())
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(data.get("manifest_version"), 3)
        self.assertEqual(data.get("name"), "Phishing Guardian OSINT")
        self.assertIn("background", data)
        self.assertIn("action", data)

    def test_required_extension_files(self):
        required = [
            "manifest.json",
            "background.js",
            "popup.html",
            "popup.js",
            "popup.css",
            "content.js",
            "icons/icon16.png",
            "icons/icon48.png",
            "icons/icon128.png",
        ]
        for rel in required:
            self.assertTrue((EXT / rel).is_file(), f"Missing {rel}")

    def test_extension_status_endpoint_defined(self):
        source = (BASE / "web_phishing_guardian.py").read_text(encoding="utf-8")
        self.assertIn("/api/extension/status", source)
        self.assertIn("CORSMiddleware", source)
        self.assertIn("browser_extension", source)

    def test_popup_references_api_endpoints(self):
        popup_js = (EXT / "popup.js").read_text(encoding="utf-8")
        self.assertIn("/api/health", popup_js)
        self.assertIn("/api/analyze", popup_js)
        self.assertIn("/api/playbooks/run", popup_js)


if __name__ == "__main__":
    unittest.main()
