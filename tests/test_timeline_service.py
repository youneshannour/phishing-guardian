import unittest

from services.timeline_service import build_timeline, _parse_date


class TestTimelineService(unittest.TestCase):
    def test_parse_date_iso(self):
        self.assertEqual(_parse_date("2019-05-14")[0], "2019-05-14")

    def test_parse_year_only(self):
        self.assertEqual(_parse_date("Breach in 2018")[0], "2018-01-01")

    def test_breach_events_from_hibp(self):
        tl = build_timeline({
            "target": "user@test.com",
            "target_type": "email",
            "completed_at": "2026-01-01T12:00:00+00:00",
            "steps": [{
                "plugin_id": "leakcheck",
                "status": "success",
                "data": {
                    "found": True,
                    "breach_details": [
                        {"Name": "Adobe", "BreachDate": "2013-10-04", "Description": "Test"},
                        {"Name": "LinkedIn", "BreachDate": "2012-05-05"},
                    ],
                },
            }],
            "entities": [],
        })
        breaches = [e for e in tl["events"] if e["event_type"] == "breach"]
        self.assertGreaterEqual(len(breaches), 2)
        self.assertEqual(tl["range"]["start"], "2012-05-05")

    def test_whois_domain_dates(self):
        tl = build_timeline({
            "target": "example.com",
            "target_type": "domain",
            "completed_at": "2026-01-01T12:00:00+00:00",
            "steps": [{
                "plugin_id": "whois",
                "status": "success",
                "data": {
                    "query": "example.com",
                    "type": "domain",
                    "data": {
                        "creation_date": "2000-08-10",
                        "expiration_date": "2027-08-10",
                    },
                },
            }],
            "entities": [],
        })
        types = {e["event_type"] for e in tl["events"]}
        self.assertIn("domain_registered", types)
        self.assertIn("domain_expires", types)

    def test_sherlock_profiles(self):
        tl = build_timeline({
            "target": "john",
            "target_type": "username",
            "completed_at": "2026-01-01T12:00:00+00:00",
            "steps": [{
                "plugin_id": "sherlock",
                "status": "success",
                "data": {
                    "username": "john",
                    "profiles": {"GitHub": {"url_main": "https://github.com/john"}},
                    "count": 1,
                },
            }],
            "entities": [],
        })
        profiles = [e for e in tl["events"] if e["event_type"] == "profile_found"]
        self.assertEqual(len(profiles), 1)

    def test_patterns_insights(self):
        tl = build_timeline({
            "target": "x@y.com",
            "target_type": "email",
            "completed_at": "2026-01-01T12:00:00+00:00",
            "steps": [{
                "plugin_id": "leakcheck",
                "status": "success",
                "data": {
                    "found": True,
                    "breach_details": [
                        {"Name": "A", "BreachDate": "2019-01-01"},
                        {"Name": "B", "BreachDate": "2019-06-01"},
                        {"Name": "C", "BreachDate": "2020-01-01"},
                    ],
                },
            }],
            "entities": [],
        })
        self.assertGreater(len(tl["patterns"]["insights"]), 0)
        self.assertIn("2019", tl["patterns"]["events_by_year"])

    def test_source_filters(self):
        tl = build_timeline({
            "target": "test.com",
            "target_type": "domain",
            "completed_at": "2026-01-01T12:00:00+00:00",
            "steps": [
                {"plugin_id": "whois", "status": "success", "data": {"type": "domain", "query": "test.com", "data": {"creation_date": "2010-01-01"}}},
                {"plugin_id": "virustotal", "status": "success", "data": {"detections": 2, "total": 70, "data": {"scan_date": "20260101"}}},
            ],
            "entities": [],
        })
        self.assertIn("whois", tl["sources"])


if __name__ == "__main__":
    unittest.main()
