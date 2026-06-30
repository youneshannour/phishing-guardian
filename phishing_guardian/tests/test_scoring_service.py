import unittest

from services.scoring_service import compute_attack_surface, _grade


class TestScoringService(unittest.TestCase):
    def test_minimal_score_no_signals(self):
        result = compute_attack_surface({
            "target": "test@example.com",
            "target_type": "email",
            "steps": [],
            "entities": [],
        })
        self.assertLessEqual(result["score"], 15)
        self.assertIn(result["grade"], ("minimal", "low"))

    def test_breach_increases_score(self):
        result = compute_attack_surface({
            "target": "leaked@corp.com",
            "target_type": "email",
            "steps": [{
                "plugin_id": "leakcheck",
                "status": "success",
                "data": {"found": True, "breach_count": 8, "sources": ["Adobe", "LinkedIn"]},
            }],
            "entities": [],
        })
        breach = next(f for f in result["factors"] if f["id"] == "breaches")
        self.assertGreater(breach["score"], 10)
        self.assertGreater(result["score"], 15)

    def test_social_profiles_score(self):
        result = compute_attack_surface({
            "target": "johndoe",
            "target_type": "username",
            "steps": [{
                "plugin_id": "sherlock",
                "status": "success",
                "data": {"count": 12, "profiles": {f"Site{i}": {} for i in range(12)}},
            }],
            "entities": [],
        })
        social = next(f for f in result["factors"] if f["id"] == "social")
        self.assertGreaterEqual(social["score"], 15)

    def test_network_shodan_vulns(self):
        result = compute_attack_surface({
            "target": "1.2.3.4",
            "target_type": "ip",
            "steps": [{
                "plugin_id": "shodan_ip",
                "status": "success",
                "data": {"ports": [22, 80, 443, 8080, 3306], "vuln_count": 3},
            }],
            "entities": [],
        })
        network = next(f for f in result["factors"] if f["id"] == "network")
        self.assertGreater(network["score"], 10)

    def test_recommendations_generated(self):
        result = compute_attack_surface({
            "target": "x@y.com",
            "target_type": "email",
            "steps": [{
                "plugin_id": "leakcheck",
                "status": "success",
                "data": {"found": True, "breach_count": 5, "sources": ["X"]},
            }],
            "entities": [],
        })
        self.assertGreater(len(result["recommendations"]), 0)

    def test_grade_thresholds(self):
        self.assertEqual(_grade(85)[0], "critical")
        self.assertEqual(_grade(65)[0], "high")
        self.assertEqual(_grade(40)[0], "medium")
        self.assertEqual(_grade(5)[0], "minimal")

    def test_score_capped_at_100(self):
        result = compute_attack_surface({
            "target": "bad@evil.com",
            "target_type": "email",
            "steps": [
                {"plugin_id": "leakcheck", "status": "success", "data": {"found": True, "breach_count": 20, "sources": ["A"] * 10}},
                {"plugin_id": "sherlock", "status": "success", "data": {"count": 20, "profiles": {str(i): {} for i in range(20)}}},
                {"plugin_id": "virustotal", "status": "success", "data": {"detections": 30, "total": 70}},
                {"plugin_id": "shodan_ip", "status": "success", "data": {"ports": list(range(15)), "vuln_count": 10}},
            ],
            "entities": [{"type": "url", "value": f"http://x{i}.com"} for i in range(10)],
        })
        self.assertLessEqual(result["score"], 100)


if __name__ == "__main__":
    unittest.main()
