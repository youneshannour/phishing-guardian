import unittest
from unittest.mock import MagicMock, patch

from services.nl_target_extractor import (
    extract_targets,
    pick_best_target,
    wants_investigation,
)
from services.ai_investigator import AIInvestigator


class TestNLTargetExtractor(unittest.TestCase):
    def test_extract_email(self):
        targets = extract_targets("Investigue john@company.com s'il te plaît")
        self.assertIn("john@company.com", targets)

    def test_extract_ip(self):
        targets = extract_targets("OSINT sur l'IP 8.8.8.8")
        self.assertIn("8.8.8.8", targets)

    def test_extract_domain(self):
        targets = extract_targets("Analyse le domaine example.com")
        self.assertIn("example.com", targets)

    def test_pick_best_prefers_email(self):
        target = pick_best_target("Compare example.com et test@mail.org")
        self.assertEqual(target, "test@mail.org")

    def test_wants_investigation_keyword(self):
        self.assertTrue(wants_investigation("Peux-tu investiguer cette cible ?"))

    def test_wants_investigation_with_target(self):
        self.assertTrue(wants_investigation("john@company.com"))

    def test_extract_username_from_pseudo_phrase(self):
        targets = extract_targets("Recherche le pseudo johndoe sur les réseaux")
        self.assertIn("johndoe", targets)

    def test_extract_username_from_handle(self):
        targets = extract_targets("OSINT sur @cyber_analyst")
        self.assertIn("cyber_analyst", targets)

    def test_pick_best_username(self):
        target = pick_best_target("Recherche le pseudo johndoe sur les réseaux")
        self.assertEqual(target, "johndoe")


class TestAIInvestigator(unittest.TestCase):
    def setUp(self):
        self.ai = AIInvestigator(base_url="http://localhost:11434", model="mistral")

    def test_fallback_summary(self):
        result = {
            "target": "test@example.com",
            "target_type": "email",
            "playbook_name": "Person OSINT",
            "duration_ms": 1200,
            "synthesis": {
                "overall_risk": "medium",
                "tools_run": 3,
                "tools_success": 2,
                "entities_found": 1,
                "key_findings": ["Email trouvé dans 2 fuite(s)"],
            },
            "steps": [],
            "entities": [],
        }
        summary = self.ai.fallback_summary(result)
        self.assertIn("test@example.com", summary)
        self.assertIn("MEDIUM", summary)
        self.assertIn("2 fuite", summary)

    @patch("services.ai_investigator.requests.get")
    def test_check_status_offline(self, mock_get):
        mock_get.side_effect = ConnectionError("refused")
        status = self.ai.check_status()
        self.assertFalse(status["available"])

    @patch("services.ai_investigator.requests.get")
    def test_check_status_online(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"models": [{"name": "mistral:latest"}]}
        mock_get.return_value = mock_resp

        status = self.ai.check_status()
        self.assertTrue(status["available"])
        self.assertTrue(status["model_available"])
        self.assertEqual(status["active_model"], "mistral:latest")

    @patch("services.ai_investigator.requests.get")
    def test_resolve_fallback_model(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"models": [{"name": "llama3.2:latest"}]}
        mock_get.return_value = mock_resp

        status = self.ai.check_status()
        self.assertTrue(status["model_available"])
        self.assertEqual(status["active_model"], "llama3.2:latest")

    def test_build_investigation_context(self):
        result = {
            "target": "8.8.8.8",
            "target_type": "ip",
            "playbook_name": "IP OSINT",
            "duration_ms": 500,
            "synthesis": {"overall_risk": "low", "tools_success": 1, "tools_run": 2, "entities_found": 0, "key_findings": []},
            "steps": [{"status": "success", "plugin_name": "Shodan", "duration_ms": 200}],
            "entities": [],
        }
        ctx = self.ai.build_investigation_context(result)
        self.assertIn("8.8.8.8", ctx)
        self.assertIn("Shodan", ctx)


if __name__ == "__main__":
    unittest.main()
