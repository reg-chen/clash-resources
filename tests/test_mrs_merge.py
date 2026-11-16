"""Same-category MRS union and safe YAML activation tests."""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import mrs_merge


def load_activate():
    path = ROOT / "tools" / "activate-merged-mrs.py"
    spec = importlib.util.spec_from_file_location("activate_merged_mrs_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MergeTests(unittest.TestCase):
    def test_domain_semantics_are_preserved(self):
        source_yaml = (
            b"payload:\n"
            b"  - 'exact.example.com'\n"
            b"  - '+.suffix.example.com'\n"
            b"  - DOMAIN-SUFFIX,other.example.com\n"
            b"  - DOMAIN,api.example.org\n"
        )
        self.assertEqual(mrs_merge.parse_domain_rules(source_yaml, "yaml"), {
            "exact.example.com", "+.suffix.example.com",
            "+.other.example.com", "api.example.org"
        })
        self.assertEqual(
            mrs_merge.parse_domain_rules(b"example.com\n*.only.example.net\n", "text"),
            {"example.com", "*.only.example.net"}
        )
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            mrs_merge.parse_domain_rules(b"payload:\n  - DOMAIN-KEYWORD,ad\n", "yaml")

    def test_category_boundaries_no_cross_merging(self):
        entries = [
            {"name": "ads-a"}, {"name": "ads-b"},
            {"name": "security-threat"}, {"name": "privacy-native-apple"}
        ]
        rules = {
            "ads-a": {"a.com", "same.net"},
            "ads-b": {"b.com", "same.net"},
            "security-threat": {"same.net", "malware.test"},
            "privacy-native-apple": {"same.net", "telemetry.example"}
        }
        groups = mrs_merge.grouped_sources(entries, rules)
        self.assertEqual(groups["ads"], {"a.com", "b.com", "same.net"})
        self.assertEqual(groups["security"], {"same.net", "malware.test"})
        self.assertEqual(groups["privacy"], {"same.net", "telemetry.example"})
        with self.assertRaisesRegex(ValueError, "Missing parsed"):
            mrs_merge.grouped_sources(entries, {"ads-a": {"a.com"}})

    def test_failed_conversion_never_installs_partial_output(self):
        entries = [{"name": f"{g}-a"} for g in mrs_merge.CATEGORIES]
        data = {f"{g}-a": {"example.com"} for g in mrs_merge.CATEGORIES}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for g in mrs_merge.CATEGORIES:
                target = root / "rules" / g / "mrs" / "combined.mrs"
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b"ORIGINAL")
            def fake_convert(cmd, check):
                if "privacy" in cmd[-1]:
                    raise RuntimeError("conversion failed")
                Path(cmd[-1]).write_bytes(b"UPDATED-MRS")
            with mock.patch.object(mrs_merge.subprocess, "run", side_effect=fake_convert):
                with self.assertRaisesRegex(RuntimeError, "conversion failed"):
                    mrs_merge.build_merged_mrs(root, entries, data)
            for g in mrs_merge.CATEGORIES:
                target = root / "rules" / g / "mrs" / "combined.mrs"
                self.assertEqual(target.read_bytes(), b"ORIGINAL")


class ActivationTests(unittest.TestCase):
    def test_only_combined_third_party_providers_active(self):
        module = load_activate()
        entries = [
            {"name": "security-threat"},
            {"name": "privacy-native-apple"},
            {"name": "ads-popup"},
        ]
        original = r"""
x-rule-provider-common: &RULE-PROVIDER
  interval: 3600
rule-providers:
  security-custom:
    behavior: domain
    path: ./rules/security/custom.txt

  security-threat:
    <<: *RULE-PROVIDER
    behavior: domain
    format: mrs
    path: ./rules/security/mrs/threat.mrs

  security-riskport:
    behavior: classical
    path: ./rules/security/riskport.yaml

  privacy-native-apple:
    <<: *RULE-PROVIDER
    behavior: domain
    format: mrs
    path: ./rules/privacy/native/mrs/native-apple.mrs

  ads-popup:
    <<: *RULE-PROVIDER
    behavior: domain
    format: mrs
    path: ./rules/ads/mrs/popup.mrs

sub-rules:
  SECURITY:
    - RULE-SET,security-custom,REJECT
    - RULE-SET,security-threat,REJECT
    - RULE-SET,security-riskport,REJECT
  PRIVACY-NATIVE:
    - RULE-SET,privacy-native-apple,REJECT
  ADS:
    - RULE-SET,ads-popup,REJECT

rules:
  - RULE-SET,direct-dns,DIRECT
  - SUB-RULE,(SRC-IP-CIDR,0.0.0.0/0),SECURITY
  - RULE-SET,direct-webview2,DIRECT
  - SUB-RULE,(SRC-IP-CIDR,0.0.0.0/0),PRIVACY-NATIVE
  - SUB-RULE,(SRC-IP-CIDR,0.0.0.0/0),ADS
  - MATCH,DIRECT
"""
        new = module.rewrite_config(original, entries)
        for category in ("security", "privacy", "ads"):
            self.assertIn(f"  {category}-combined:\n", new)
            self.assertIn(f"RULE-SET,{category}-combined,REJECT", new)
            self.assertIn(f"./rules/{category}/mrs/combined.mrs", new)
        for entry in entries:
            self.assertNotIn(f"  {entry['name']}:\n", new)
            self.assertNotIn(f"RULE-SET,{entry['name']},REJECT", new)
        self.assertIn("RULE-SET,security-custom,REJECT", new)
        self.assertIn("RULE-SET,security-riskport,REJECT", new)
        self.assertEqual(new.count("RULE-SET,ads-combined,REJECT"), 1)
        self.assertNotIn("sub-rules:", new)
        self.assertNotIn("SUB-RULE,", new)
        self.assertEqual(new.count("RULE-SET,security-combined,REJECT"), 1)
        self.assertEqual(new.count("RULE-SET,privacy-combined,REJECT"), 1)
        self.assertLess(new.index("RULE-SET,security-custom,REJECT"),
                        new.index("RULE-SET,security-combined,REJECT"))
        self.assertLess(new.index("RULE-SET,security-combined,REJECT"),
                        new.index("RULE-SET,security-riskport,REJECT"))
        self.assertLess(new.index("RULE-SET,security-riskport,REJECT"),
                        new.index("RULE-SET,direct-webview2,DIRECT"))
        self.assertLess(new.index("RULE-SET,direct-webview2,DIRECT"),
                        new.index("RULE-SET,privacy-combined,REJECT"))
        self.assertLess(new.index("RULE-SET,privacy-combined,REJECT"),
                        new.index("RULE-SET,ads-combined,REJECT"))

    def test_real_profiles_can_be_flattened_without_moving_critical_exceptions(self):
        module = load_activate()
        for relative in module.CONFIGS:
            with self.subTest(profile=relative):
                original = (ROOT / relative).read_text(encoding="utf-8")
                if "sub-rules:" not in original:
                    self.assertNotIn("SUB-RULE,", original)
                    continue
                updated = module.rewrite_config(original, module.SOURCES)
                self.assertNotIn("sub-rules:", updated)
                self.assertNotIn("SUB-RULE,", updated)
                for category in ("security", "privacy", "ads"):
                    self.assertEqual(
                        updated.count(f"RULE-SET,{category}-combined,REJECT"), 1
                    )
                self.assertLess(
                    updated.index("RULE-SET,security-combined,REJECT"),
                    updated.index("RULE-SET,direct-webview2,")
                ) if "direct-webview2" in updated else None
                self.assertLess(
                    updated.index("RULE-SET,security-riskport,REJECT"),
                    updated.index("RULE-SET,privacy-combined,REJECT")
                )
                self.assertIn("RULE-SET,privacy-custom,REJECT", updated)
                self.assertIn("RULE-SET,ads-custom,REJECT", updated)


if __name__ == "__main__":
    unittest.main()
