import io
import ssl
import urllib.request
import urllib.error
import http.client
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from mrs_provenance import (pin_source_url, save_source_snapshot,
                            snapshot_path, verify_source_snapshots, commit_page, download_bytes)


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

    @mock.patch("mrs_provenance.time.sleep")
    @mock.patch("mrs_provenance.urllib.request.urlopen")
    def test_eof_then_success(self, urlopen, sleep):
        request = urllib.request.Request("https://raw.githubusercontent.com/o/r/main/a.txt")
        urlopen.side_effect = [
            urllib.error.URLError(ssl.SSLEOFError(8, "unexpected EOF")),
            http.client.IncompleteRead(b"partial"),
            io.BytesIO(b"complete response"),
        ]
        self.assertEqual(download_bytes(request), b"complete response")
        self.assertEqual(urlopen.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

    @mock.patch("mrs_provenance.time.sleep")
    @mock.patch("mrs_provenance.urllib.request.urlopen")
    def test_permanent_tls_or_http_error_not_retried(self, urlopen, sleep):
        request = urllib.request.Request("https://api.github.com/repos/o/r/commits/main")
        for error in (urllib.error.URLError(ssl.SSLCertVerificationError(1, "invalid certificate")),
                      urllib.error.HTTPError(request.full_url, 404, "Not Found", {}, None)):
            urlopen.reset_mock()
            urlopen.side_effect = error
            with self.assertRaisesRegex(RuntimeError, "GitHub revision lookup failed"):
                download_bytes(request, label="GitHub revision lookup")
            self.assertEqual(urlopen.call_count, 1)
        sleep.assert_not_called()

    @mock.patch("mrs_provenance.time.sleep")
    @mock.patch("mrs_provenance.urllib.request.urlopen")
    def test_exhausted_retries_identify_url(self, urlopen, sleep):
        request = urllib.request.Request("https://raw.githubusercontent.com/o/r/main/a.txt")
        urlopen.side_effect = urllib.error.URLError(ssl.SSLEOFError(8, "unexpected EOF"))
        with self.assertRaisesRegex(RuntimeError, "3/3") as result:
            download_bytes(request, label="security-threat")
        self.assertIn(request.full_url, str(result.exception))
        self.assertIn("security-threat", str(result.exception))
        self.assertEqual(urlopen.call_count, 3)

    def test_rejects_unpinnable_source(self):
        for url in ("http://raw.githubusercontent.com/o/r/main/a.txt",
                    "https://example.com/o/r/main/a.txt",
                    "https://raw.githubusercontent.com/o/r/main/../a.txt",
                    "https://raw.githubusercontent.com/o/r/main"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                pin_source_url(url, {})


class SnapshotTests(unittest.TestCase):
    def test_archive_preserves_source_bytes_and_validates_manifest(self):
        import hashlib
        import tempfile
        data = b"\xef\xbb\xbfpayload:\r\n  - '+.example.org'\r\n"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = save_source_snapshot(root, "ads-antiad", "yaml", data)
            self.assertEqual(path, root / "sources/mrs/ads-antiad.yaml")
            self.assertEqual(path.read_bytes(), data)
            stat = path.stat().st_mtime_ns
            self.assertEqual(save_source_snapshot(root, "ads-antiad", "yaml", data), path)
            self.assertEqual(path.stat().st_mtime_ns, stat)
            entry = {
                "name": "ads-antiad", "format": "yaml",
                "source_snapshot_path": "sources/mrs/ads-antiad.yaml",
                "source_sha256": hashlib.sha256(data).hexdigest(),
                "source_size_bytes": len(data),
            }
            verify_source_snapshots(root, [entry])
            path.write_bytes(b"tampered")
            with self.assertRaises(ValueError):
                verify_source_snapshots(root, [entry])

    def test_reject_unsafe_snapshot_paths_and_unknown_formats(self):
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            for name in ("../bad", "ads/evil", "", "Ads", "ads--bad"):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    snapshot_path(root, name, "text")
            with self.assertRaises(ValueError):
                snapshot_path(root, "ads-safe", "exe")

    def test_upstream_revision_page_is_commit_not_release(self):
        self.assertEqual(
            commit_page("https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/reject.txt",
                        "abcdef0123456789abcdef0123456789abcdef01"),
            "https://github.com/Loyalsoldier/clash-rules/commit/abcdef0123456789abcdef0123456789abcdef01")
