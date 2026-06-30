import unittest

from services.report_service import (
    REPORTLAB_AVAILABLE,
    generate_pdf_bytes,
    prepare_report_context,
    report_status,
    suggested_filename,
)


SAMPLE_INVESTIGATION = {
    "id": "inv-test-001",
    "playbook_id": "email_recon",
    "playbook_name": "Email Reconnaissance",
    "target": "user@example.com",
    "target_type": "email",
    "started_at": "2026-06-29T10:00:00+00:00",
    "completed_at": "2026-06-29T10:00:05+00:00",
    "duration_ms": 5200,
    "steps": [
        {
            "plugin_id": "leakcheck",
            "plugin_name": "Leak Check",
            "status": "success",
            "duration_ms": 800,
            "data": {
                "found": True,
                "breach_count": 2,
                "risk_level": "medium",
                "breach_details": [
                    {"Name": "Adobe", "BreachDate": "2013-10-04"},
                ],
            },
        },
        {
            "plugin_id": "sherlock",
            "plugin_name": "Sherlock",
            "status": "success",
            "duration_ms": 1200,
            "data": {
                "username": "user",
                "count": 1,
                "profiles": {"GitHub": {"url_main": "https://github.com/user"}},
            },
        },
    ],
    "entities": [
        {"type": "username", "value": "user", "source": "email", "confidence": 0.9},
        {"type": "domain", "value": "example.com", "source": "email", "confidence": 1.0},
    ],
    "synthesis": {
        "overall_risk": "medium",
        "key_findings": ["2 fuites de données détectées", "1 profil social trouvé"],
        "tools_success": 2,
        "tools_failed": 0,
        "entities_found": 2,
    },
}


class TestReportService(unittest.TestCase):
    def test_report_status(self):
        st = report_status()
        self.assertIn("pdf_available", st)
        self.assertEqual(st["pdf_available"], REPORTLAB_AVAILABLE)

    def test_prepare_report_context(self):
        ctx = prepare_report_context(SAMPLE_INVESTIGATION)
        self.assertEqual(ctx["target"], "user@example.com")
        self.assertIn("attack_surface", ctx)
        self.assertIn("timeline", ctx)
        self.assertIn("graph", ctx)
        self.assertGreater(ctx["attack_surface"]["score"], 0)
        self.assertGreater(len(ctx["timeline"]["events"]), 0)
        self.assertGreater(len(ctx["graph"]["nodes"]), 0)

    def test_suggested_filename(self):
        name = suggested_filename(SAMPLE_INVESTIGATION)
        self.assertTrue(name.endswith(".pdf"))
        self.assertIn("user_example.com", name)

    @unittest.skipUnless(REPORTLAB_AVAILABLE, "reportlab requis")
    def test_generate_pdf_bytes(self):
        pdf = generate_pdf_bytes(SAMPLE_INVESTIGATION)
        self.assertIsInstance(pdf, bytes)
        self.assertGreater(len(pdf), 500)
        self.assertTrue(pdf[:4] == b"%PDF")

    @unittest.skipUnless(REPORTLAB_AVAILABLE, "reportlab requis")
    def test_pdf_contains_sections(self):
        pdf = generate_pdf_bytes(SAMPLE_INVESTIGATION)
        # Texte embarqué (approximatif)
        text = pdf.decode("latin-1", errors="ignore")
        self.assertIn("Rapport", text)
        self.assertIn("user@example.com", text)


if __name__ == "__main__":
    unittest.main()
