import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from services.watch_service import WatchService


BASELINE = {
    "id": "inv-base-001",
    "target": "watch@test.com",
    "target_type": "email",
    "playbook_id": "email_recon",
    "playbook_name": "Email Recon",
    "steps": [
        {
            "plugin_id": "leakcheck",
            "status": "success",
            "data": {"found": True, "breach_count": 1},
        },
        {
            "plugin_id": "virustotal",
            "status": "success",
            "data": {"detections": 0, "total": 70},
        },
    ],
    "entities": [{"type": "domain", "value": "test.com", "source": "email"}],
    "synthesis": {
        "overall_risk": "low",
        "key_findings": ["1 fuite connue"],
        "attack_surface": {"score": 20.0},
    },
}

CURRENT_WORSE = {
    "id": "inv-cur-002",
    "target": "watch@test.com",
    "target_type": "email",
    "playbook_id": "email_recon",
    "playbook_name": "Email Recon",
    "steps": [
        {
            "plugin_id": "leakcheck",
            "status": "success",
            "data": {"found": True, "breach_count": 4},
        },
        {
            "plugin_id": "virustotal",
            "status": "success",
            "data": {"detections": 3, "total": 70},
        },
    ],
    "entities": [
        {"type": "domain", "value": "test.com", "source": "email"},
        {"type": "username", "value": "watchuser", "source": "sherlock"},
    ],
    "synthesis": {
        "overall_risk": "high",
        "key_findings": ["4 fuites connues", "Nouveau profil social"],
        "attack_surface": {"score": 45.0},
    },
}


class TestWatchService(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        self.tmp.close()
        self.svc = WatchService(store_path=Path(self.tmp.name))

    def tearDown(self):
        Path(self.tmp.name).unlink(missing_ok=True)

    def test_status_empty(self):
        st = self.svc.status()
        self.assertEqual(st["watch_count"], 0)
        self.assertEqual(st["unread_alerts"], 0)

    def test_compare_detects_changes(self):
        alerts = self.svc.compare_investigations(
            BASELINE, CURRENT_WORSE, watch_id="w1", target="watch@test.com"
        )
        types = {a.alert_type.value for a in alerts}
        self.assertIn("new_breach", types)
        self.assertIn("risk_increase", types)
        self.assertIn("vt_detections", types)
        self.assertIn("new_entity", types)
        self.assertIn("score_increase", types)

    @patch("services.watch_service.playbook_engine")
    def test_create_watch_with_baseline(self, mock_engine):
        mock_engine.run = AsyncMock()
        result = asyncio.run(
            self.svc.create_watch(
                "watch@test.com",
                baseline_investigation=BASELINE,
                label="Test watch",
                interval_hours=12,
            )
        )
        self.assertIn("watch", result)
        self.assertEqual(result["watch"]["target"], "watch@test.com")
        self.assertEqual(result["watch"]["interval_hours"], 12)
        mock_engine.run.assert_not_called()
        watches = self.svc.list_watches()
        self.assertEqual(len(watches), 1)

    @patch("services.watch_service.playbook_engine")
    def test_run_check_generates_alerts(self, mock_engine):
        mock_result = MagicMock()
        mock_result.to_dict.return_value = CURRENT_WORSE
        mock_engine.run = AsyncMock(return_value=mock_result)

        create = asyncio.run(
            self.svc.create_watch("watch@test.com", baseline_investigation=BASELINE)
        )
        watch_id = create["watch"]["id"]

        check = asyncio.run(self.svc.run_check(watch_id))
        self.assertGreater(check["changes_detected"], 0)
        self.assertGreater(len(check["alerts"]), 0)
        alerts = self.svc.list_alerts(unread_only=True)
        self.assertGreater(len(alerts), 0)

    def test_mark_alert_read(self):
        data = {
            "watches": [{"id": "w1", "unread_alerts": 1}],
            "alerts": [{"id": "a1", "watch_id": "w1", "read": False, "created_at": "2026-01-01"}],
            "investigations": {},
        }
        self.svc._save(data)
        alert = self.svc.mark_alert_read("a1")
        self.assertIsNotNone(alert)
        self.assertTrue(alert["read"])
        watch = self.svc.get_watch("w1")
        self.assertEqual(watch["unread_alerts"], 0)

    @patch("services.watch_service.playbook_engine")
    def test_duplicate_active_watch_rejected(self, mock_engine):
        mock_engine.run = AsyncMock()
        asyncio.run(
            self.svc.create_watch("dup@test.com", baseline_investigation=BASELINE)
        )
        with self.assertRaises(ValueError):
            asyncio.run(
                self.svc.create_watch("dup@test.com", baseline_investigation=BASELINE)
            )


if __name__ == "__main__":
    unittest.main()
