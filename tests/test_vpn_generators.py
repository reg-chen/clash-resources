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
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import vpn_generator_core as core

pia = core.load_sibling("pia-openvpn-generator.py", "test_pia")
ss = core.load_sibling("surfshark-openvpn-generator.py", "test_ss")


def profile(proto, host):
    return (f"client\ndev tun\nproto {proto}\nremote {host} 1194\n"
            "auth-user-pass\ncipher AES-256-CBC\nauth SHA256\n"
            "<ca>\nMOCK CERTIFICATE\n</ca>\n")


class GeneratorTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
