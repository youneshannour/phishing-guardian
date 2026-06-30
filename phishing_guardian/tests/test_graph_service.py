import unittest

from services.graph_service import (
    build_graph_from_investigation,
    graph_to_cytoscape,
    merge_graphs,
    suggest_pivot_playbook,
)


class TestGraphService(unittest.TestCase):
    def _sample_investigation(self):
        return {
            "id": "inv-1",
            "target": "john@company.com",
            "target_type": "email",
            "playbook_name": "Person OSINT",
            "entities": [
                {"type": "email", "value": "john@company.com", "source": "leakcheck"},
                {"type": "domain", "value": "company.com", "source": "whois"},
                {"type": "username", "value": "john", "source": "sherlock"},
            ],
            "steps": [
                {
                    "plugin_id": "sherlock",
                    "status": "success",
                    "data": {
                        "username": "john",
                        "profiles": {
                            "GitHub": {"url_main": "https://github.com/john"},
                        },
                    },
                },
                {
                    "plugin_id": "leakcheck",
                    "status": "success",
                    "data": {
                        "found": True,
                        "sources": ["Adobe"],
                        "email": "john@company.com",
                    },
                },
            ],
        }

    def test_build_graph_has_root_and_edges(self):
        graph = build_graph_from_investigation(self._sample_investigation())
        self.assertGreaterEqual(len(graph["nodes"]), 3)
        self.assertGreater(len(graph["edges"]), 0)
        roots = [n for n in graph["nodes"] if n.get("is_root")]
        self.assertEqual(len(roots), 1)
        self.assertEqual(roots[0]["label"], "john@company.com")

    def test_email_domain_username_links(self):
        graph = build_graph_from_investigation(self._sample_investigation())
        relations = {e["relation"] for e in graph["edges"]}
        self.assertIn("uses_domain", relations)
        self.assertIn("has_username", relations)

    def test_sherlock_profile_edge(self):
        graph = build_graph_from_investigation(self._sample_investigation())
        relations = {e["relation"] for e in graph["edges"]}
        self.assertIn("profile_on", relations)

    def test_cytoscape_format(self):
        graph = build_graph_from_investigation(self._sample_investigation())
        cy = graph_to_cytoscape(graph)
        self.assertIn("elements", cy)
        self.assertEqual(len(cy["elements"]), len(graph["nodes"]) + len(graph["edges"]))

    def test_merge_graphs(self):
        g1 = build_graph_from_investigation(self._sample_investigation())
        g2 = build_graph_from_investigation({
            "target": "8.8.8.8",
            "target_type": "ip",
            "playbook_name": "IP OSINT",
            "entities": [{"type": "ip", "value": "8.8.8.8", "source": "shodan_ip"}],
            "steps": [],
        })
        merged = merge_graphs(g1, g2)
        self.assertGreater(merged["meta"]["node_count"], g1["meta"]["node_count"])

    def test_empty_target(self):
        graph = build_graph_from_investigation({"target": "", "entities": [], "steps": []})
        self.assertEqual(graph["nodes"], [])

    def test_suggest_pivot_playbook(self):
        self.assertEqual(suggest_pivot_playbook("email"), "person_osint")
        self.assertEqual(suggest_pivot_playbook("ip"), "ip_osint")


if __name__ == "__main__":
    unittest.main()
