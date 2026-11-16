"""Offline tests for the local Mihomo DoH CA and server certificate."""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from cryptography import x509
from cryptography.hazmat.primitives import serialization

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import mihomo_doh


class MihomoDohTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.patches = [
            patch.dict(os.environ, {"LOCALAPPDATA": str(Path(self.tmp.name) / "profile")}),
            patch.object(sys, "platform", "win32"),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)
        self.dest = Path(self.tmp.name) / "mihomo"

    def test_generation_chain_and_idempotency(self):
        files = mihomo_doh.generate_certificates(self.dest)
        self.assertTrue(files.renewed)
        ca = x509.load_pem_x509_certificate(files.ca_certificate.read_bytes())
        leaf = x509.load_pem_x509_certificate(files.server_certificate.read_bytes())
        key = serialization.load_pem_private_key(files.server_private_key.read_bytes(), password=None)
        self.assertTrue(ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        leaf.verify_directly_issued_by(ca)
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertIn("localhost", san.get_values_for_type(x509.DNSName))
        self.assertEqual(key.public_key().public_numbers(), leaf.public_key().public_numbers())
        self.assertNotIn("root-ca.key", [p.name for p in (self.dest / "certs").iterdir()])
        self.assertIn("external-controller-tls: 127.0.0.1:9443", mihomo_doh.mihomo_yaml(files))
        second = mihomo_doh.generate_certificates(self.dest)
        self.assertFalse(second.renewed)
        self.assertEqual(second.server_certificate.read_bytes(), files.server_certificate.read_bytes())

    def test_custom_host_in_san_and_ca_reused(self):
        initial = mihomo_doh.generate_certificates(self.dest)
        ca_before = initial.ca_certificate.read_bytes()
        original = initial.server_certificate.read_bytes()
        custom = mihomo_doh.generate_certificates(self.dest, "DNS.MIHOMO.TEST")
        self.assertTrue(custom.renewed)
        self.assertEqual(custom.ca_certificate.read_bytes(), ca_before)
        self.assertNotEqual(custom.server_certificate.read_bytes(), original)
        cert = x509.load_pem_x509_certificate(custom.server_certificate.read_bytes())
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertIn("dns.mihomo.test", san.get_values_for_type(x509.DNSName))
        self.assertIn("localhost", san.get_values_for_type(x509.DNSName))
        self.assertIn("127.0.0.1", [str(v) for v in san.get_values_for_type(x509.IPAddress)])
        second = mihomo_doh.generate_certificates(self.dest, "dns.mihomo.test")
        self.assertFalse(second.renewed)
        self.assertEqual(second.server_certificate.read_bytes(), custom.server_certificate.read_bytes())
        self.assertEqual(
            mihomo_doh.doh_url("dns.mihomo.test"),
            "https://dns.mihomo.test:9443/dns-query"
        )
        self.assertEqual(
            mihomo_doh.party_hosts_override("dns.mihomo.test"),
            "'dns.mihomo.test': 127.0.0.1"
        )
        self.assertNotIn("external-controller:", mihomo_doh.mihomo_yaml(custom))

    def test_hostname_validation(self):
        for value in ("https://dns.test", "dns.test:9443", "*.test", "abc/def", "8.8.8.8", ""):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    mihomo_doh.normalize_host(value)
        self.assertEqual(mihomo_doh.normalize_host("::1"), "::1")
        self.assertEqual(mihomo_doh.doh_url("::1"), "https://[::1]:9443/dns-query")
        self.assertEqual(mihomo_doh.normalize_host("  MiHoMo.LocalHost. "), "mihomo.localhost")

    def test_incomplete_ca_rejected(self):
        directory = Path(os.environ["LOCALAPPDATA"]) / "reg-chen" / "VPN-Mihomo-Generator" / "doh-ca"
        directory.mkdir(parents=True)
        (directory / "root-ca.crt").write_text("incomplete")
        with self.assertRaisesRegex(RuntimeError, "只有一項"):
            mihomo_doh.generate_certificates(self.dest)

    def test_user_trust_explicit(self):
        files = mihomo_doh.generate_certificates(self.dest)
        with patch.object(mihomo_doh.subprocess, "run", return_value=MagicMock(returncode=0, stdout="done")) as proc:
            self.assertEqual(mihomo_doh.trust_ca_for_current_user(files.ca_certificate), "done")
            args = proc.call_args[0][0]
            self.assertEqual(args[:4], ["certutil.exe", "-user", "-addstore", "Root"])


if __name__ == "__main__":
    unittest.main()
