import unittest
from unittest.mock import MagicMock, patch

from models.playbook import EntityType, PluginStatus, TargetTransform
from services.entity_resolver import (
    resolve_entity_type,
    suggest_playbook_id,
    transform_target,
)
from services.playbook_engine import PlaybookEngine
from playbooks.definitions import get_playbook, list_playbooks


class TestEntityResolver(unittest.TestCase):
    def test_resolve_email(self):
        self.assertEqual(resolve_entity_type("john@company.com"), EntityType.EMAIL)

    def test_resolve_ip(self):
        self.assertEqual(resolve_entity_type("8.8.8.8"), EntityType.IP)

    def test_resolve_domain(self):
        self.assertEqual(resolve_entity_type("example.com"), EntityType.DOMAIN)

    def test_resolve_username(self):
        self.assertEqual(resolve_entity_type("johndoe"), EntityType.USERNAME)

    def test_transform_username_from_email(self):
        result = transform_target("john@company.com", TargetTransform.USERNAME_FROM_EMAIL)
        self.assertEqual(result, "john")

    def test_transform_domain_from_email(self):
        result = transform_target("john@company.com", TargetTransform.DOMAIN_FROM_EMAIL)
        self.assertEqual(result, "company.com")

    def test_suggest_playbook_for_email(self):
        self.assertEqual(suggest_playbook_id(EntityType.EMAIL), "person_osint")


class TestPlaybookDefinitions(unittest.TestCase):
    def test_all_playbooks_have_steps(self):
        for playbook in list_playbooks():
            self.assertGreater(len(playbook.steps), 0, playbook.id)

    def test_person_playbook_exists(self):
        pb = get_playbook("person_osint")
        self.assertEqual(pb.id, "person_osint")
        self.assertIn(EntityType.EMAIL, pb.target_types)


class TestPlaybookEngine(unittest.TestCase):
    def setUp(self):
        self.engine = PlaybookEngine()

    def test_suggest_returns_playbook(self):
        result = self.engine.suggest("test@example.com")
        self.assertEqual(result["target_type"], "email")
        self.assertEqual(result["suggested_playbook_id"], "person_osint")

    def test_run_empty_target_raises(self):
        with self.assertRaises(ValueError):
            import asyncio
            asyncio.run(self.engine.run(""))

    @patch("services.playbook_engine.get_plugin")
    def test_run_executes_plugins_in_order(self, mock_get_plugin):
        from models.playbook import PluginResult

        mock_plugin = MagicMock()
        mock_plugin.id = "leakcheck"
        mock_plugin.name = "Leak Check"
        mock_plugin.env_key = None
        mock_plugin.is_available.return_value = True
        mock_plugin.supports.return_value = True
        mock_plugin.run.return_value = PluginResult(
            plugin_id="leakcheck",
            plugin_name="Leak Check",
            status=PluginStatus.SUCCESS,
            duration_ms=10,
            data={"found": False, "risk_level": "low"},
            entities=[],
        )
        mock_get_plugin.return_value = mock_plugin

        import asyncio
        result = asyncio.run(self.engine.run("test@example.com", "breach_check"))

        self.assertEqual(result.playbook_id, "breach_check")
        self.assertEqual(len(result.steps), 1)
        self.assertEqual(result.synthesis["tools_success"], 1)
        mock_plugin.run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
