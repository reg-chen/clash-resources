import io
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from mrs_provenance import pin_source_url


class ProvenanceTests(unittest.TestCase):
    @mock.patch("mrs_provenance.urllib.request.urlopen")
    def test_fixed_url_and_cache(self, urlopen):
        revision = "abcdef0123456789abcdef0123456789abcdef01"
        urlopen.return_value = io.BytesIO(json.dumps({"sha": revision}).encode())
        cache = {}
        url, sha = pin_source_url(
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/a.txt", cache)
        url2, _ = pin_source_url(
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/b.txt", cache)
        self.assertEqual(sha, revision)
        self.assertTrue(url.endswith("/" + revision + "/wildcard/a.txt"))
        self.assertTrue(url2.endswith("/" + revision + "/wildcard/b.txt"))
        self.assertEqual(urlopen.call_count, 1)

    def test_rejects_unpinnable_source(self):
        for url in ("http://raw.githubusercontent.com/o/r/main/a.txt",
                    "https://example.com/o/r/main/a.txt",
                    "https://raw.githubusercontent.com/o/r/main/../a.txt",
                    "https://raw.githubusercontent.com/o/r/main"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                pin_source_url(url, {})
