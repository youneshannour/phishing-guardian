import unittest

from services.privacy_service import compute_privacy_score, _privacy_grade


class TestPrivacyService(unittest.TestCase):
    def test_excellent_privacy_no_signals(self):
        result = compute_privacy_score({
            "target": "private@example.com",
            "target_type": "email",
            "steps": [],
            "entities": [],
        })
        self.assertGreaterEqual(result["score"], 80)
        self.assertEqual(result["grade"], "excellent")
        self.assertLessEqual(result["exposure_total"], 20)

    def test_breaches_lower_privacy(self):
        result = compute_privacy_score({
            "target": "leaked@corp.com",
            "target_type": "email",
            "steps": [{
                "plugin_id": "leakcheck",
                "status": "success",
                "data": {"found": True, "breach_count": 10, "sources": ["Adobe", "LinkedIn"]},
            }],
            "entities": [],
        })
        breaches = next(f for f in result["factors"] if f["id"] == "data_breaches")
        self.assertGreater(breaches["exposure"], 20)
        self.assertLess(result["score"], 75)

    def test_social_footprint_impact(self):
        result = compute_privacy_score({
            "target": "johndoe",
            "target_type": "username",
            "steps": [{
                "plugin_id": "sherlock",
                "status": "success",
                "data": {"count": 15, "profiles": {f"P{i}": {} for i in range(15)}},
            }],
            "entities": [],
        })
        social = next(f for f in result["factors"] if f["id"] == "social_footprint")
        self.assertGreaterEqual(social["exposure"], 19)
        self.assertLess(result["score"], 80)

    def test_identity_correlation(self):
        result = compute_privacy_score({
            "target": "user@test.com",
            "target_type": "email",
            "steps": [],
            "entities": [
                {"type": "email", "value": "user@test.com", "source": "target"},
                {"type": "username", "value": "user", "source": "email"},
                {"type": "domain", "value": "test.com", "source": "email"},
                {"type": "url", "value": "https://test.com", "source": "whois"},
            ],
        })
        identity = next(f for f in result["factors"] if f["id"] == "identity_links")
        self.assertGreater(identity["exposure"], 0)

    def test_recommendations_for_poor_privacy(self):
        result = compute_privacy_score({
            "target": "x@y.com",
            "target_type": "email",
            "steps": [
                {
                    "plugin_id": "leakcheck",
                    "status": "success",
                    "data": {"found": True, "breach_count": 6, "sources": ["X"]},
                },
                {
                    "plugin_id": "sherlock",
                    "status": "success",
                    "data": {"count": 10, "profiles": {f"S{i}": {} for i in range(10)}},
                },
            ],
            "entities": [],
        })
        self.assertGreater(len(result["recommendations"]), 0)
        self.assertIn("grade_label", result)

    def test_privacy_grade_thresholds(self):
        self.assertEqual(_privacy_grade(85)[0], "excellent")
        self.assertEqual(_privacy_grade(65)[0], "good")
        self.assertEqual(_privacy_grade(40)[0], "moderate")
        self.assertEqual(_privacy_grade(10)[0], "critical")

    def test_score_inverse_of_exposure(self):
        result = compute_privacy_score({
            "target": "a@b.com",
            "target_type": "email",
            "steps": [{
                "plugin_id": "leakcheck",
                "status": "success",
                "data": {"found": True, "breach_count": 3},
            }],
            "entities": [],
        })
        self.assertAlmostEqual(result["score"], 100 - result["exposure_total"], places=0)


if __name__ == "__main__":
    unittest.main()
