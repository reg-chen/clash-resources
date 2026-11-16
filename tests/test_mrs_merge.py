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

    def test_real_phishing_feed_domains_with_underscores(self):
        # Phishing.Database contains labels with underscores; legacy Mihomo
        # compilation accepted them, but our pre-merge regex rejected them.
        phishing = b"10000susan_gilbert.goodluckseeker.com\n_sip._tcp.example.com\n"
        self.assertEqual(mrs_merge.parse_domain_rules(phishing, "text"), {
            "10000susan_gilbert.goodluckseeker.com",
            "_sip._tcp.example.com",
        })
        with self.assertRaisesRegex(ValueError, "Invalid domain"):
            mrs_merge.parse_domain_rules(b"bad path.example.com\n", "text")

    def test_numeric_ip_like_domain_token_is_not_rejected(self):
        sample = (
            b"101.0.81.153\n"
            b"10000susan_gilbert.goodluckseeker.com\n"
            b"+.safe.example.org\n"
        )
        self.assertEqual(
            mrs_merge.parse_domain_rules(sample, "text"),
            {"101.0.81.153", "10000susan_gilbert.goodluckseeker.com", "+.safe.example.org"},
        )
        for bad in (b"bad domain.example\n", b"http://example.com\n"):
            with self.assertRaisesRegex(ValueError, "Invalid domain"):
                mrs_merge.parse_domain_rules(bad, "text")

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

    def test_local_custom_domains_are_merged_only_with_matching_category(self):
        custom = {}
        for item in mrs_merge.CUSTOM_SOURCES:
            raw = (ROOT / item["path"]).read_bytes()
            custom[item["name"]] = mrs_merge.parse_domain_rules(raw, "text")
        self.assertIn("+.crypto-loot.org", custom["security-custom"])
        self.assertIn("+.fingerprintjs.com", custom["privacy-custom"])
        self.assertIn("+.ironsource.mobi", custom["ads-custom"])

        entries = [
            {"name": f"{category}-third-party"}
            for category in mrs_merge.CATEGORIES
        ] + list(mrs_merge.CUSTOM_SOURCES)
        datasets = {
            f"{category}-third-party": {"shared.example.net"}
            for category in mrs_merge.CATEGORIES
        }
        datasets.update(custom)
        groups = mrs_merge.grouped_sources(entries, datasets)
        self.assertIn("+.crypto-loot.org", groups["security"])
        self.assertNotIn("+.crypto-loot.org", groups["privacy"])
        self.assertNotIn("+.crypto-loot.org", groups["ads"])
        self.assertIn("+.fingerprintjs.com", groups["privacy"])
        self.assertNotIn("+.fingerprintjs.com", groups["security"])
        self.assertIn("+.ironsource.mobi", groups["ads"])
        self.assertNotIn("+.ironsource.mobi", groups["security"])
        self.assertTrue(all("network-ports" not in rule for part in groups.values() for rule in part))

    def test_optional_empty_custom_does_not_break_union(self):
        self.assertEqual(mrs_merge.parse_domain_rules(b"# none\n", "text", allow_empty=True), set())
        with self.assertRaisesRegex(ValueError, "Empty parsed"):
            mrs_merge.parse_domain_rules(b"# none\n", "text")

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

  network-ports:
    behavior: classical
    path: ./rules/network/ports.yaml

  privacy-custom:
    behavior: domain
    path: ./rules/privacy/custom.txt

  privacy-native-apple:
    <<: *RULE-PROVIDER
    behavior: domain
    format: mrs
    path: ./rules/privacy/native/mrs/native-apple.mrs

  ads-custom:
    behavior: domain
    path: ./rules/ads/custom.txt

  ads-popup:
    <<: *RULE-PROVIDER
    behavior: domain
    format: mrs
    path: ./rules/ads/mrs/popup.mrs

sub-rules:
  SECURITY:
    - RULE-SET,security-custom,REJECT
    - RULE-SET,security-threat,REJECT
  PRIVACY-NATIVE:
    - RULE-SET,privacy-custom,REJECT
    - RULE-SET,privacy-native-apple,REJECT
  ADS:
    - RULE-SET,ads-custom,REJECT
    - RULE-SET,ads-popup,REJECT

rules:
  - RULE-SET,direct-dns,DIRECT
  - SUB-RULE,(SRC-IP-CIDR,0.0.0.0/0),SECURITY
  # Network port restrictions (classical)
  - RULE-SET,network-ports,REJECT
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
        for category in mrs_merge.CATEGORIES:
            self.assertNotIn(f"RULE-SET,{category}-custom,REJECT", new)
            self.assertNotIn(f"  {category}-custom:\n", new)
        self.assertIn("RULE-SET,network-ports,REJECT", new)
        self.assertIn("# Network port restrictions (classical)", new)
        self.assertEqual(new.count("RULE-SET,network-ports,REJECT"), 1)
        self.assertEqual(new.count("RULE-SET,ads-combined,REJECT"), 1)
        self.assertNotIn("sub-rules:", new)
        self.assertNotIn("SUB-RULE,", new)
        self.assertEqual(new.count("RULE-SET,security-combined,REJECT"), 1)
        self.assertEqual(new.count("RULE-SET,privacy-combined,REJECT"), 1)
        self.assertLess(new.index("RULE-SET,security-combined,REJECT"),
                        new.index("RULE-SET,network-ports,REJECT"))
        self.assertLess(new.index("RULE-SET,network-ports,REJECT"),
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
                if "RULE-SET,direct-webview2," in updated:
                    self.assertLess(
                        updated.index("RULE-SET,security-combined,REJECT"),
                        updated.index("RULE-SET,direct-webview2,")
                    )
                self.assertLess(
                    updated.index("RULE-SET,network-ports,REJECT"),
                    updated.index("RULE-SET,privacy-combined,REJECT")
                )
                for category in mrs_merge.CATEGORIES:
                    self.assertNotIn(f"RULE-SET,{category}-custom,REJECT", updated)
                    self.assertNotIn(f"  {category}-custom:\n", updated)
                self.assertIn("RULE-SET,network-ports,REJECT", updated)
                self.assertEqual(updated.count("RULE-SET,network-ports,REJECT"), 1)

    def test_migrated_config_cannot_keep_custom_as_second_provider(self):
        module = load_activate()
        source = (ROOT / "configs/desktop.yaml").read_text(encoding="utf-8")
        combined = module.rewrite_config(source, module.SOURCES)
        self.assertEqual(module.remove_custom_from_activated(combined), combined)

        # Prior flow combined third-party sources but retained local custom;
        # simulate that state, then ensure it is safely upgraded.
        prior = combined
        insert_at = prior.index("rule-providers:\n") + len("rule-providers:\n")
        for category in mrs_merge.CATEGORIES:
            prior = prior[:insert_at] + (
                f"  {category}-custom:\n"
                "    behavior: domain\n"
                f"    path: ./rules/{category}/custom.txt\n\n"
            ) + prior[insert_at:]
        for category in mrs_merge.CATEGORIES:
            needle = f"- RULE-SET,{category}-combined,REJECT"
            prior = prior.replace(
                needle,
                f"- RULE-SET,{category}-custom,REJECT\n  {needle}", 1
            )
        result = module.remove_custom_from_activated(prior)
        self.assertNotIn("sub-rules:", result)
        self.assertNotIn("SUB-RULE,", result)
        for category in mrs_merge.CATEGORIES:
            self.assertEqual(result.count(f"RULE-SET,{category}-combined,REJECT"), 1)
            self.assertNotIn(f"RULE-SET,{category}-custom,REJECT", result)


if __name__ == "__main__":
    unittest.main()
