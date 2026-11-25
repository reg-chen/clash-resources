"""Regression tests for published MRS paths and merge-only source inputs."""
import json
import os
import re
import runpy
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import mrs_merge
import mrs_provenance
from mrs_ip import IP_TARGET, FEODO_URL, parse_ip_rules

CATEGORIES = ("security", "privacy", "ads")
COMBINED = {f"rules/{c}/mrs/combined.mrs" for c in CATEGORIES}
STANDALONE = "rules/ads/mrs/antiad.mrs"
EXPECTED = COMBINED | {STANDALONE, IP_TARGET}
SOURCES = json.loads((ROOT / "tools/third-party-mrs-sources.json").read_text())


class PublicationTests(unittest.TestCase):
    def test_registry_manifest_and_profiles_match_published_artifacts(self):
        self.assertEqual(len(SOURCES), 20)
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
            self.assertEqual({i["name"] for i in manifest["inputs"]}, {s["name"] for s in SOURCES})
        for item in manifest["inputs"]:
            category = item["name"].split("-", 1)[0]
            expected = {IP_TARGET} if item["name"].startswith("security-ip-") else {f"rules/{category}/mrs/combined.mrs"}
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
            def download(req, **kwargs):
                return io.BytesIO(source_bytes[req.full_url])
            def convert(cmd, check):
                Path(cmd[-1]).write_bytes(b"MOCK-COMPILED-MRS")
            with mock.patch.object(mrs_provenance, "pin_source_url",
                                   side_effect=lambda url, cache: (url, "a" * 40)), \
                 mock.patch("urllib.request.urlopen", side_effect=download), \
                 mock.patch("subprocess.run", side_effect=convert) as compiler, \
                 mock.patch.dict(os.environ, {"MRS_OVERLAP_REPORT": str(root / "overlap.md")}):
                runpy.run_path(str(root / "tools/build-third-party-mrs.py"))
                self.assertEqual(compiler.call_count, 5)
                compiler.reset_mock()
                runpy.run_path(str(root / "tools/build-third-party-mrs.py"))
                self.assertEqual(compiler.call_count, 4)  # Unchanged anti-AD is reused.
            actual = {p.relative_to(root).as_posix() for p in (root / "rules").rglob("*.mrs")}
            self.assertEqual(actual, EXPECTED)
            state = json.loads((root / "tools/third-party-mrs-sha256.json").read_text())
            self.assertEqual(set(state), {s["name"] for s in SOURCES})
            manifest = json.loads((root / "tools/third-party-mrs-provenance.json").read_text())
            self.assertEqual(len(manifest["inputs"]), 20)
            self.assertEqual({o["path"] for o in manifest["outputs"]}, EXPECTED)
            mrs_provenance.verify_source_snapshots(root, manifest["inputs"])


if __name__ == "__main__":
    unittest.main()
