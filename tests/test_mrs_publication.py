"""Regression tests for published MRS paths and merge-only source inputs."""
import json
import os
import re
import runpy
import shutil
import sys
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import mrs_merge
import mrs_build
import mrs_provenance
from mrs_ip import IP_TARGET, FEODO_URL, parse_ip_rules

CATEGORIES = ("security", "privacy", "ads")
COMBINED = {f"rules/{c}/mrs/combined.mrs" for c in CATEGORIES}
STANDALONE = "rules/ads/mrs/antiad.mrs"
EXPECTED = COMBINED | {STANDALONE, IP_TARGET}
SOURCES = json.loads((ROOT / "tools/third-party-mrs-sources.json").read_text())


class PublicationTests(unittest.TestCase):
    def test_registry_manifest_and_profiles_match_published_artifacts(self):
        self.assertEqual(len(SOURCES), 22)
        self.assertEqual({s["name"] for s in SOURCES if s.get("behavior") == "ipcidr"},
                         {"security-ip-hagezi", "security-ip-feodo", "security-ip-phishing"})
        self.assertEqual({s["name"] for s in SOURCES if s.get("behavior") == "domain-ipcidr"},
                         {"security-metamask"})
        self.assertEqual({s["name"]: s["target"] for s in SOURCES if s.get("target")},
                         {"ads-antiad": STANDALONE})
        manifest = json.loads((ROOT / "tools/third-party-mrs-provenance.json").read_text())
        self.assertEqual(manifest["schema"], 2)
        published = {o["path"] for o in manifest["outputs"]}
        pending = IP_TARGET not in published
        if pending and os.environ.get("MRS_REQUIRE_CURRENT") == "1":
            self.fail("IP publication is still pending")
        expected_outputs = EXPECTED - {IP_TARGET} if pending else EXPECTED
        self.assertEqual(published, expected_outputs)
        if not pending:
            published_inputs = {i["name"] for i in manifest["inputs"]}
            registered_inputs = {s["name"] for s in SOURCES}
            if os.environ.get("MRS_REQUIRE_CURRENT") == "1":
                self.assertEqual(published_inputs, registered_inputs)
            else:
                # Before the first build of the new source, the published manifest is still valid.
                self.assertIn(published_inputs, (registered_inputs, registered_inputs - {"security-metamask"}))
        for item in manifest["inputs"]:
            category = item["name"].split("-", 1)[0]
            expected = {IP_TARGET} if item["name"].startswith("security-ip-") else {f"rules/{category}/mrs/combined.mrs"}
            if item["name"] == "security-metamask":
                expected.add(IP_TARGET)
            if item["name"] == "ads-antiad":
                expected.add(STANDALONE)
            self.assertEqual(set(item["output_paths"]), expected)
        actual = {p.relative_to(ROOT).as_posix() for c in CATEGORIES
                  for p in (ROOT / "rules" / c / "mrs").glob("*.mrs")}
        self.assertEqual(actual, expected_outputs)
        for name in ("desktop", "android-firewall-only", "windows-firewall-only",
                     "ios-firewall-only"):
            text = (ROOT / "configs" / f"{name}.yaml").read_text(encoding="utf-8")
            urls = {"rules/" + p for p in re.findall(
                r"https://rules\.reginald\.win/([^\s\"']+\.mrs)", text)}
            self.assertEqual(urls, {STANDALONE} if name.startswith("ios") else (COMBINED if pending else COMBINED | {IP_TARGET}))

    def test_metamask_mixed_domains_ipv4_and_allowlist(self):
        raw = json.dumps({
            "blacklist": ["PHISH.example.", "parent.example", "sub.safe.example",
                          "safe.example", "https://shared.example/path", "*.wild.example",
                          "8.8.8.8", "9.9.9.9", "127.0.0.1", "10.0.0.1",
                          "224.0.0.1", "2001:4860:4860::8888", "sub.localhost",
                          "trusted.example"],
            "whitelist": ["safe.example", "child.parent.example", "9.9.9.9",
                          "127.0.0.1", "localhost", "::1"],
            "fuzzylist": ["legitimate.example", "1.1.1.1"],
        }).encode()
        skipped = []
        domains, ips, excluded = mrs_merge.parse_metamask_rules(raw, skipped_invalid=skipped)
        self.assertEqual(domains, {"phish.example", "parent.example", "trusted.example"})
        self.assertEqual(ips, {"8.8.8.8/32"})
        self.assertEqual(set(excluded), {"9.9.9.9", "127.0.0.1", "10.0.0.1", "224.0.0.1"})
        self.assertEqual(len(skipped), 3)
        self.assertEqual(mrs_merge.parse_metamask_rules(
            b'{"blocklist":["bad.example"],"allowlist":[]}', skipped_invalid=[]),
            ({"bad.example"}, set(), []))
        self.assertEqual(mrs_merge.parse_metamask_rules(
            b'{"blocklist":["8.8.8.8"],"allowlist":[]}', skipped_invalid=[]),
            (set(), {"8.8.8.8/32"}, []))
        for invalid in (b'{}', b'{"blacklist":["bad.example"],"whitelist":"bad.example"}',
                        b'{"blacklist":["bad.example"],"whitelist":["https://bad.example"]}',
                        b'{"blacklist":["bad.example"],"whitelist":["bad.example"]}'):
            with self.assertRaises(ValueError):
                mrs_merge.parse_metamask_rules(invalid, skipped_invalid=[])

    def test_ip_parser_and_empty_feodo(self):
        values, excluded = parse_ip_rules(b"8.8.8.8\n100.83.3.144\n247.16.181.135\n224.0.0.1\n")
        self.assertEqual(values, {"8.8.8.8/32"})
        self.assertEqual(len(excluded), 3)
        header = b"# abuse.ch Feodo Tracker Botnet C2 IP Blocklist (recommended)\n"
        self.assertEqual(parse_ip_rules(header + b"# END 0 entries\n", feodo=True), (set(), []))
        for invalid in (b"<html>", b"8.8.8.8/24", header + b"# END 1 entries\n"):
            with self.assertRaises(ValueError):
                parse_ip_rules(invalid, feodo=True)

    def test_builder_compiles_only_published_outputs_and_tracks_all_inputs(self):
        import io
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tools").mkdir()
            shutil.copy(ROOT / "tools/build-third-party-mrs.py", root / "tools")
            shutil.copy(ROOT / "tools/third-party-mrs-sources.json", root / "tools")
            for entry in mrs_merge.CUSTOM_SOURCES:
                path = root / entry["path"]
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("custom.example.com\n", encoding="utf-8")
            source_bytes = {
                entry["source"]: (b"payload:\n  - 'example.org'\n" if entry["format"] == "yaml"
                                  else (b"8.8.8.8\n9.9.9.9\n" if entry.get("behavior") == "ipcidr" else b"example.org\n"))
                for entry in SOURCES
            }
            source_bytes[FEODO_URL] = (b"# abuse.ch Feodo Tracker Botnet C2 IP Blocklist (recommended)\n"
                                       b"# END 0 entries\n")
            metamask_url = next(s["source"] for s in SOURCES if s["name"] == "security-metamask")
            source_bytes[metamask_url] = json.dumps({
                "blacklist": ["example.org", "phish.example.net", "allowed.example.net",
                              "sub.allowed.example.net", "https://shared.example.net/path",
                              "8.8.8.8", "4.4.4.4", "9.9.9.9", "127.0.0.1"],
                "whitelist": ["allowed.example.net", "9.9.9.9", "127.0.0.1", "localhost"],
                "fuzzylist": ["legitimate.example.net"],
            }).encode()
            phishing_url = next(s["source"] for s in SOURCES if s["name"] == "security-ip-phishing")
            source_bytes[phishing_url] = b"9.9.9.9\n1.1.1.1\n"
            def download(req, **kwargs):
                return io.BytesIO(source_bytes[req.full_url])
            def convert(cmd, check, creationflags):
                self.assertTrue(check)
                self.assertEqual(creationflags, getattr(subprocess, "CREATE_NO_WINDOW", 0))
                rules = set(Path(cmd[-2]).read_text().splitlines())
                if cmd[2] == "ipcidr":
                    self.assertEqual(rules, {"8.8.8.8/32", "9.9.9.9/32", "1.1.1.1/32", "4.4.4.4/32"})
                elif "security" in str(cmd[-1]):
                    self.assertIn("phish.example.net", rules)
                    self.assertNotIn("allowed.example.net", rules)
                    self.assertNotIn("8.8.8.8", rules)
                    self.assertNotIn("4.4.4.4", rules)
                Path(cmd[-1]).write_bytes(b"MOCK-COMPILED-MRS")
            with mock.patch.object(mrs_build, "pin_source_url",
                                   side_effect=lambda url, cache: (url, "a" * 40)), \
                 mock.patch("urllib.request.urlopen", side_effect=download), \
                 mock.patch("subprocess.run", side_effect=convert) as compiler, \
                 mock.patch.dict(os.environ, {"MRS_OVERLAP_REPORT": str(root / "overlap.md")}):
                runpy.run_path(str(root / "tools/build-third-party-mrs.py"))
                self.assertEqual(compiler.call_count, 5)
                compiler.reset_mock()
                runpy.run_path(str(root / "tools/build-third-party-mrs.py"))
                self.assertEqual(compiler.call_count, 4)  # Unchanged anti-AD is reused.
            report = (root / "overlap.md").read_text(encoding="utf-8")
            self.assertIn("| security-metamask | 2 | 1 | 1 |", report)
            self.assertIn("## SECURITY-IP（聯集 4）", report)
            self.assertIn("| security-ip-hagezi | 2 | 2 | 0 | 0 |", report)
            self.assertIn("| security-metamask | 2 | 1 | 1 | 2 |", report)
            self.assertIn("| security-ip-phishing | 2 | 1 | 1 | 0 |", report)
            self.assertIn("| security-ip-feodo | 0 | 0 | 0 | 0 |", report)
            actual = {p.relative_to(root).as_posix() for p in (root / "rules").rglob("*.mrs")}
            self.assertEqual(actual, EXPECTED)
            state = json.loads((root / "tools/third-party-mrs-sha256.json").read_text())
            self.assertEqual(set(state), {s["name"] for s in SOURCES})
            manifest = json.loads((root / "tools/third-party-mrs-provenance.json").read_text())
            self.assertEqual(len(manifest["inputs"]), 22)
            self.assertEqual({o["path"] for o in manifest["outputs"]}, EXPECTED)
            entry = next(i for i in manifest["inputs"] if i["name"] == "security-metamask")
            self.assertEqual(set(entry["output_paths"]), {"rules/security/mrs/combined.mrs", IP_TARGET})
            self.assertEqual((root / entry["source_snapshot_path"]).read_bytes(), source_bytes[metamask_url])
            mrs_provenance.verify_source_snapshots(root, manifest["inputs"])
            # The local mode must not query GitHub REST, even with previous pinned state.
            with mock.patch.object(mrs_build, "pin_source_url", side_effect=AssertionError("unexpected API request")), \
                 mock.patch("urllib.request.urlopen", side_effect=download), \
                 mock.patch("subprocess.run", side_effect=convert):
                outputs = mrs_build.build(root, SOURCES, report_dir=root, pin_revisions=False)
            self.assertEqual({o["path"] for o in outputs}, EXPECTED)
            local = json.loads((root / "tools/third-party-mrs-provenance.json").read_text())
            for item in local["inputs"]:
                self.assertIsNone(item["source_commit_sha"])
                self.assertIsNone(item["pinned_source_url"])
                self.assertIsNone(item["source_commit_url"])
                self.assertEqual(item["source_type"], "live" if item["source_url"] == FEODO_URL else "branch")
            mrs_provenance.verify_source_snapshots(root, local["inputs"])


if __name__ == "__main__":
    unittest.main()
