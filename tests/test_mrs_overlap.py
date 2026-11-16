"""Offline parser tests for exact source-domain overlap metrics."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from mrs_overlap import parse_domain_keys, summarize, render


class OverlapTests(unittest.TestCase):
    def test_domain_keys_parse_text_and_yaml(self):
        text = b"# comments\n+.ads.example.com\nexample.net\n*.track.example.org\n0.0.0.0 bad.example.com\n"
        self.assertEqual(parse_domain_keys(text, "text"),
                         {"ads.example.com", "example.net", "track.example.org"})
        yaml = b"payload:\n - DOMAIN-SUFFIX,ads.example.com\n - DOMAIN,api.example.net\n - IP-CIDR,1.1.1.1/32\n"
        self.assertEqual(parse_domain_keys(yaml, "yaml"),
                         {"ads.example.com", "api.example.net"})

    def test_overlap_unique_counts_are_group_scoped(self):
        sources = {
            "ads-a": {"a.com", "b.com", "same.net"},
            "ads-b": {"b.com", "c.net", "same.net"},
            "ads-c": {"c.net", "different.com"},
            "security-x": {"b.com", "threat.com"},
        }
        result = summarize(sources)
        ads = {entry["name"]: entry for entry in result["ads"]}
        self.assertEqual(ads["ads-a"], {
            "name": "ads-a", "total": 3, "overlap": 2, "unique": 1
        })
        self.assertEqual(ads["ads-c"]["unique"], 1)
        self.assertEqual(result["security"][0]["unique"], 2)
        report = render(sources, ["antiad: plain list approximation"])
        self.assertIn("來源交集與差集", report)
        self.assertIn("antiad: plain list approximation", report)
        self.assertIn("完全相同的網域鍵", report)


if __name__ == "__main__":
    unittest.main()
