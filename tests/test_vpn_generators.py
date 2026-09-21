"""Regression checks for generator-owned presentation and PIA entry points.

Run: python -m unittest discover -s tests
"""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import vpn_generator_core as core

pia = core.load_sibling("pia-openvpn-generator.py", "test_pia")
ss = core.load_sibling("surfshark-openvpn-generator.py", "test_ss")
wg = core.load_sibling("pia-wireguard-generator.py", "test_wg")


def profile(proto, host):
    return (f"client\ndev tun\nproto {proto}\nremote {host} 1194\n"
            "auth-user-pass\ncipher AES-256-CBC\nauth SHA256\n"
            "<ca>\nMOCK CERTIFICATE\n</ca>\n")


class GeneratorTests(unittest.TestCase):
    def test_surfshark_streaming_filter_is_explicit_and_optional(self):
        # Synthetic marked profiles exercise the switch; official ordinary
        # profiles and static-IP-looking names must remain untouched.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "ss.zip"
            with zipfile.ZipFile(bundle, "w") as archive:
                for endpoint in ("de-fra", "de-fra-st001", "de-fra-streaming-optimized"):
                    for proto in ("udp", "tcp"):
                        archive.writestr(
                            f"{endpoint}.prod.surfshark.com_{proto}.ovpn",
                            profile(proto, f"{endpoint}.example.com"))
            for exclude in (True, False):
                for single in (True, False):
                    output = root / f"{exclude}-{single}"
                    with contextlib.redirect_stdout(io.StringIO()):
                        ss.generate_openvpn(
                            bundle_zip=bundle, username="mock", password="mock",
                            out_dir=output, single_file=single, sync_override=False,
                            exclude_streaming=exclude)
                    payload = "\n".join(
                        path.read_text(encoding="utf-8")
                        for path in output.rglob("*.yaml"))
                    self.assertIn("de-fra.example.com", payload)
                    self.assertIn("de-fra-st001.example.com", payload)
                    self.assertEqual("de-fra-streaming-optimized.example.com" in payload, not exclude)


    def test_india_zip_to_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "ss.zip"
            with zipfile.ZipFile(bundle, "w") as archive:
                for city in ("del", "mum"):
                    for proto in ("udp", "tcp"):
                        archive.writestr(
                            f"in-{city}.prod.surfshark.com_{proto}.ovpn",
                            profile(proto, f"{city}.example.com"))
            nodes = ss.dedupe_nodes([
                ss.parse_ovpn(item) for item in ss.collect_ovpn_inputs(bundle)
            ])
            ss.apply_node_names(nodes)
            self.assertEqual(ss.topology_paths(nodes), ["IN\\delhi", "IN\\mumbai"])
            self.assertEqual({node.name for node in nodes}, {
                f"🇮🇳 OV-SS-IN(印度-{city})-{proto}"
                for city in ("德里", "孟買") for proto in ("UDP", "TCP")
            })
            with contextlib.redirect_stdout(io.StringIO()):
                ss.write_endpoint_tree(root, nodes, "mock", "mock")
            for city, label in (("delhi", "德里"), ("mumbai", "孟買")):
                payload = (root / "providers/IN" / city / "surfshark-ov.yaml").read_text(encoding="utf-8")
                for proto in ("UDP", "TCP"):
                    self.assertIn(f"OV-SS-IN(印度-{label})-{proto}", payload)

    def test_catalog_regeneration(self):
        catalog = core.location_catalog()
        self.assertEqual(catalog["DE\\berlin"], "德國-柏林")
        self.assertEqual(catalog["DE\\frankfurt"], "德國-法蘭克福")
        self.assertTrue(all("\\\\" not in key for key in catalog))
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "override.js"
            target.write_text(
                "// BEGIN GENERATED VPN LOCATION LABELS\n"
                "// END GENERATED VPN LOCATION LABELS\n", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                core.sync_override_location_catalog(generator="test", override_path=target)
                first = target.read_bytes()
                core.sync_override_location_catalog(generator="test", override_path=target)
            self.assertEqual(target.read_bytes(), first)
            text = target.read_text(encoding="utf-8")
            generated = text.split("const VPN_LOCATION_LABELS = ", 1)[1].split(";\n", 1)[0]
            self.assertEqual(json.loads(generated), catalog)
        committed = (ROOT / "overrides/vpn-providers.js").read_text(encoding="utf-8")
        generated = committed.split("const VPN_LOCATION_LABELS = ", 1)[1].split(";\n", 1)[0]
        self.assertEqual(json.loads(generated), catalog)

    def test_pia_gui_entry_points(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundles = []
            for proto in ("udp", "tcp"):
                bundle = root / f"{proto}.zip"
                bundles.append(bundle)
                with zipfile.ZipFile(bundle, "w") as archive:
                    for stem in ("de_berlin", "de_frankfurt", "taiwan"):
                        archive.writestr(f"{stem}.ovpn", profile(proto, f"{stem}.example.com"))
            for single in (False, True):
                output = root / ("single" if single else "tree")
                with contextlib.redirect_stdout(io.StringIO()):
                    pia.generate_openvpn(
                        udp_zip=bundles[0], tcp_zip=bundles[1],
                        username="mock", password="mock", out_dir=output,
                        single_file=single, exclude_streaming=True, sync_override=False)
            tree = root / "tree/providers"
            self.assertEqual(
                {p.relative_to(tree).as_posix() for p in tree.rglob("*.yaml")},
                {"DE/berlin/pia-ov.yaml", "DE/frankfurt/pia-ov.yaml", "TW/pia-ov.yaml"})
            aggregate = (root / "single/providers/pia-ov-all.yaml").read_text(encoding="utf-8")
            for path in tree.rglob("*.yaml"):
                payload = path.read_text(encoding="utf-8")
                for line in payload.splitlines():
                    if "- name:" in line:
                        self.assertIn(line, aggregate)


class CleanupRegressionTests(unittest.TestCase):
    def test_pia_canonical_names_paths_and_city_modes(self):
        stems = ("de_ber", "de_fra", "in_del", "in_mum", "uk_london", "taiwan")
        nodes = [pia.parse_ovpn(pia.OvpnFile(
            f"{stem}.ovpn", profile(proto, f"{stem}.example.com")))
            for stem in stems for proto in ("udp", "tcp")]
        expected_paths = {"DE/berlin", "DE/frankfurt", "IN/delhi", "IN/mumbai", "UK", "TW"}
        multi = pia.get_multi_endpoint_country_codes(nodes)
        self.assertEqual({path.replace("\\", "/") for path in pia.topology_paths(nodes)}, expected_paths)
        labels = {"de_ber": "德國-柏林", "de_fra": "德國-法蘭克福",
                  "in_del": "印度-德里", "in_mum": "印度-孟買"}
        for mode in ("multi", "always", "never"):
            with self.subTest(city_mode=mode):
                pia.apply_node_names(nodes, mode)
                self.assertEqual(len({node.name for node in nodes}), len(nodes))
                for node in nodes:
                    stem = pia.endpoint_stem(node)
                    if stem in labels:
                        self.assertIn(f"({labels[stem]})-{node.proto.upper()}", node.name)
                    elif stem == "uk_london":
                        label = "英國-倫敦" if mode == "always" else "英國"
                        self.assertEqual(node.name, f"🇬🇧 OV-PIA-UK({label})-{node.proto.upper()}")
                    else:
                        self.assertIn("OV-PIA-TW(台灣)", node.name)
                self.assertEqual(pia.provider_name(nodes[0], multi), "ov-pia-de-berlin")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with contextlib.redirect_stdout(io.StringIO()):
                pia.write_endpoint_tree(root, nodes, "mock", "mock", 20, 60)
            actual = {path.parent.relative_to(root / "providers").as_posix()
                      for path in root.rglob("pia-ov.yaml")}
            self.assertEqual(actual, expected_paths)

    def test_unlisted_locations_remain_distinct(self):
        nodes = [pia.parse_ovpn(pia.OvpnFile(f"de_{city}.ovpn", profile("udp", f"{city}.example.com")))
                 for city in ("new_city", "other_city")]
        pia.apply_node_names(nodes, "never")
        self.assertEqual({node.name for node in nodes}, {
            "🇩🇪 OV-PIA-DE(德國-new-city)-UDP", "🇩🇪 OV-PIA-DE(德國-other-city)-UDP"})

    def test_shared_parsing_keeps_vendor_payload_policy(self):
        text = profile("udp", "mock.example.com") + "compress\nverb 3\nreneg-sec 3600\n"
        self.assertEqual(core.get_directive(text, "compress"), [])
        self.assertEqual(core.get_directive("  PrOtO tcp ; comment\n", "proto"), ["tcp"])
        self.assertIsNone(core.get_directive(text, "missing"))
        pia_node = pia.parse_ovpn(pia.OvpnFile("taiwan.ovpn", text))
        ss_node = ss.parse_ovpn(ss.OvpnFile("in-del.prod.surfshark.com_udp.ovpn", text))
        self.assertEqual(pia_node.comp_lzo, "yes")
        self.assertIsNone(ss_node.comp_lzo)
        for field in ("compress", "reneg_sec", "location_label"):
            self.assertFalse(hasattr(pia_node, field))
        self.assertFalse(core.value_same_for_all([], "ca"))
        self.assertTrue(core.value_same_for_all([pia_node, ss_node], "ca"))
        self.assertFalse(core.value_same_for_all([pia_node, ss_node], "comp_lzo"))
        self.assertEqual(core.yaml_scalar("00123"), "00123")
        self.assertEqual(ss.yaml_scalar("00123"), '"00123"')
        self.assertEqual(core.yaml_scalar(123), "123")
        self.assertEqual(core.yaml_scalar(False), "false")
        self.assertEqual(core.yaml_block("ca", "ONE\nTWO", 2), ["  ca: |", "    ONE", "    TWO"])
        self.assertEqual(core.yaml_quote('a\\b"c'), '"a\\\\b\\"c"')

    def test_wireguard_generation_ignores_openvpn_display_text(self):
        locations = [("DE Berlin", "de", "DE/berlin", "德國-柏林"),
                     ("DE Frankfurt", "de", "DE/frankfurt", "德國-法蘭克福"),
                     ("IN Delhi", "in", "IN/delhi", "印度-德里"),
                     ("IN Mumbai", "in", "IN/mumbai", "印度-孟買"),
                     ("UK London", "uk", "UK", "英國"),
                     ("Taiwan", "tw", "TW", "台灣")]
        regions = [{"name": name, "id": core.normalized_stem(name), "country": cc,
                    "servers": {"wg": [{"ip": "192.0.2.1", "cn": "mock.example.com"}]}}
                   for name, cc, _, _ in locations]
        response = {"peer_ip": "10.0.0.2/32", "server_key": "mock-server-key", "server_port": 1337}
        # Exercise absent OV, edited names, and OV metadata without any proxies.
        for ov_mode in ("absent", "renamed", "no-proxies"):
            with self.subTest(ov_mode=ov_mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                providers = root / "providers"
                if ov_mode != "absent":
                    for name, _, path, _ in locations:
                        target = providers / path / "pia-ov.yaml"
                        target.parent.mkdir(parents=True, exist_ok=True)
                        body = f"# Source endpoint stem: {core.normalized_stem(name)}\n"
                        if ov_mode == "renamed":
                            body += 'proxies:\n  - name: "ARBITRARY OV DISPLAY-UDP"\n'
                        target.write_text(body, encoding="utf-8")
                    index = wg.read_openvpn_endpoint_index(providers)
                    self.assertEqual(index["de_berlin"], providers / "DE/berlin")
                for single in (False, True):
                    with mock.patch.multiple(wg,
                            fetch_json_first_line=mock.Mock(return_value={"regions": regions}),
                            get_token=mock.Mock(return_value="mock-token"),
                            fetch_pia_ca=mock.Mock(return_value="mock-ca"),
                            generate_wg_keypair=mock.Mock(return_value=("mock-private", "mock-public")),
                            add_key=mock.Mock(return_value=response)), \
                            mock.patch.object(core, "source_override_path", return_value=None), \
                            contextlib.redirect_stdout(io.StringIO()):
                        written = wg.generate_wireguard(
                            username="mock", password="mock", out_dir=root,
                            single_file=single, exclude_streaming=True, sync_override=False)
                    payloads = "\n".join(path.read_text(encoding="utf-8") for path in written)
                    self.assertNotIn("ARBITRARY", payloads)
                    for _, cc, _, label in locations:
                        self.assertIn(f"WG-PIA-{cc.upper()}({label})", payloads)
                    self.assertIn("🇬🇧 WG-PIA-UK", payloads)
                    if not single:
                        self.assertEqual(set(wg.relative_provider_paths(written, providers)),
                                         {path.replace("/", "\\") for _, _, path, _ in locations})
                        # Retain the aligned city directory even when OV lists only one city.
                if ov_mode != "absent":
                    with mock.patch.multiple(wg,
                            fetch_json_first_line=mock.Mock(return_value={"regions": regions[:1]}),
                            get_token=mock.Mock(return_value="mock-token"),
                            fetch_pia_ca=mock.Mock(return_value="mock-ca"),
                            generate_wg_keypair=mock.Mock(return_value=("mock-private", "mock-public")),
                            add_key=mock.Mock(return_value=response)), contextlib.redirect_stdout(io.StringIO()):
                        written = wg.generate_wireguard(
                            username="mock", password="mock", out_dir=root,
                            single_file=False, exclude_streaming=True, sync_override=False)
                    self.assertEqual(written, [providers / "DE/berlin/pia-wg.yaml"])
                    self.assertIn("WG-PIA-DE(德國-柏林)", written[0].read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
