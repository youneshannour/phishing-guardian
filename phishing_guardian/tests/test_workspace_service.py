import tempfile
import unittest
from pathlib import Path

from services.workspace_service import WorkspaceService

SAMPLE_INV = {
    "id": "inv-ws-001",
    "target": "target@example.com",
    "target_type": "email",
    "playbook_name": "Email Recon",
    "completed_at": "2026-06-29T12:00:00+00:00",
    "synthesis": {
        "overall_risk": "medium",
        "entities_found": 2,
        "key_findings": ["Fuite détectée"],
        "attack_surface": {"score": 35},
    },
    "entities": [{"type": "domain", "value": "example.com", "source": "email"}],
    "steps": [],
}


class TestWorkspaceService(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        self.tmp.close()
        self.svc = WorkspaceService(store_path=Path(self.tmp.name))

    def tearDown(self):
        Path(self.tmp.name).unlink(missing_ok=True)

    def test_create_and_list_workspace(self):
        ws = self.svc.create_workspace("Op Phish", owner="alice")
        self.assertTrue(ws["id"].startswith("ws_"))
        self.assertEqual(ws["owner"], "alice")
        items = self.svc.list_workspaces("alice")
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["name"], "Op Phish")

    def test_viewer_cannot_create_case(self):
        ws = self.svc.create_workspace("Test", owner="alice")
        self.svc.add_member(ws["id"], "alice", username="bob", role="viewer")
        with self.assertRaises(PermissionError):
            self.svc.create_case(ws["id"], "bob", title="Dossier 1")

    def test_analyst_creates_case_with_investigation(self):
        ws = self.svc.create_workspace("Test", owner="alice")
        self.svc.add_member(ws["id"], "alice", username="bob", role="analyst")
        case = self.svc.create_case(
            ws["id"],
            "bob",
            title="Cible email",
            investigation=SAMPLE_INV,
        )
        self.assertEqual(len(case["investigations"]), 1)
        self.assertEqual(case["investigations"][0]["target"], "target@example.com")

    def test_add_investigation_to_existing_case(self):
        ws = self.svc.create_workspace("Test", owner="alice")
        case = self.svc.create_case(ws["id"], "alice", title="Dossier")
        result = self.svc.add_investigation_to_case(
            ws["id"], case["id"], "alice", SAMPLE_INV
        )
        self.assertEqual(len(result["case"]["investigations"]), 1)

    def test_notes_and_activity(self):
        ws = self.svc.create_workspace("Test", owner="alice")
        note = self.svc.create_note(ws["id"], "alice", "Première note collaborative")
        self.assertEqual(note["author"], "alice")
        activity = self.svc.list_activity(ws["id"], "alice")
        actions = {a["action"] for a in activity}
        self.assertIn("workspace_created", actions)
        self.assertIn("note_created", actions)

    def test_permission_isolation(self):
        ws = self.svc.create_workspace("Private", owner="alice")
        with self.assertRaises(PermissionError):
            self.svc.get_workspace(ws["id"], "stranger")

    def test_remove_member(self):
        ws = self.svc.create_workspace("Team", owner="alice")
        self.svc.add_member(ws["id"], "alice", username="bob", role="analyst")
        self.assertTrue(self.svc.remove_member(ws["id"], "alice", "bob"))
        with self.assertRaises(PermissionError):
            self.svc.get_workspace(ws["id"], "bob")

    def test_normalize_username(self):
        self.assertEqual(self.svc.normalize_username("Alice.Test"), "alice.test")
        with self.assertRaises(ValueError):
            self.svc.normalize_username("a")


if __name__ == "__main__":
    unittest.main()
