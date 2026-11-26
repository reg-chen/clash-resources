"""Offline tests for the local Mihomo DoH CA and server certificate."""
import os
import ssl
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

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
        ski = leaf.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        aki = leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        self.assertFalse(ski.critical)
        self.assertFalse(aki.critical)
        self.assertEqual(ski.value, x509.SubjectKeyIdentifier.from_public_key(leaf.public_key()))
        self.assertEqual(aki.value.key_identifier, ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest)
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

    def test_legacy_leaf_is_renewed_and_strict_tls_works(self):
        host = "dns.mihomo.test"
        files = mihomo_doh.generate_certificates(self.dest, host)
        ca_pem = files.ca_certificate.read_bytes()
        ca_key_path = mihomo_doh._ca_directory() / "root-ca.key"
        ca_key_pem = ca_key_path.read_bytes()
        ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)
        leaf = x509.load_pem_x509_certificate(files.server_certificate.read_bytes())
        # Simulate the previous generator: same key, SAN, issuer and validity,
        # but no AKI/SKI extensions.
        old = (x509.CertificateBuilder().subject_name(leaf.subject)
               .issuer_name(leaf.issuer).public_key(leaf.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(leaf.not_valid_before_utc)
               .not_valid_after(leaf.not_valid_after_utc))
        for ext in leaf.extensions:
            if not isinstance(ext.value, (x509.AuthorityKeyIdentifier, x509.SubjectKeyIdentifier)):
                old = old.add_extension(ext.value, ext.critical)
        legacy = old.sign(ca_key, hashes.SHA256())
        files.server_certificate.write_bytes(legacy.public_bytes(serialization.Encoding.PEM))
        upgraded = mihomo_doh.generate_certificates(self.dest, host)
        self.assertTrue(upgraded.renewed)
        self.assertEqual(upgraded.ca_certificate.read_bytes(), ca_pem)
        self.assertEqual(ca_key_path.read_bytes(), ca_key_pem)
        self.assertFalse(mihomo_doh.generate_certificates(self.dest, host).renewed)

        # Real OpenSSL handshake with strict RFC 5280 and hostname checks,
        # no network, no OS trust-store modifications.
        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(str(upgraded.server_certificate), str(upgraded.server_private_key))
        client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_ctx.load_verify_locations(cafile=str(upgraded.ca_certificate))
        client_ctx.verify_flags |= ssl.VERIFY_X509_STRICT
        client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
        server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
        client = client_ctx.wrap_bio(client_in, client_out, server_hostname=host)
        server = server_ctx.wrap_bio(server_in, server_out, server_side=True)
        done = set()
        for _ in range(20):
            for name, peer, outgoing, incoming in (
                    ("client", client, client_out, server_in),
                    ("server", server, server_out, client_in)):
                if name not in done:
                    try:
                        peer.do_handshake()
                        done.add(name)
                    except ssl.SSLWantReadError:
                        pass
                if outgoing.pending:
                    incoming.write(outgoing.read())
            if len(done) == 2:
                break
        self.assertEqual(done, {"client", "server"})

    def test_hostname_validation(self):
        for value in ("https://dns.test", "dns.test:9443", "*.test", "abc/def", "8.8.8.8", ""):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    mihomo_doh.normalize_host(value)
        self.assertEqual(mihomo_doh.normalize_host("::1"), "::1")
        self.assertEqual(mihomo_doh.doh_url("::1"), "https://[::1]:9443/dns-query")
        self.assertEqual(mihomo_doh.normalize_host("  MiHoMo.LocalHost. "), "mihomo.localhost")

    def test_incomplete_ca_rejected(self):
        directory = Path(os.environ["LOCALAPPDATA"]) / "reg-chen" / "VPN-Network-Toolkit" / "doh-ca"
        directory.mkdir(parents=True)
        (directory / "root-ca.crt").write_text("incomplete")
        with self.assertRaisesRegex(RuntimeError, "只有一項"):
            mihomo_doh.generate_certificates(self.dest)

    def test_existing_ca_is_reused_after_app_rename(self):
        old_dir = (Path(os.environ["LOCALAPPDATA"]) / "reg-chen" /
                   "VPN-Mihomo-Generator" / "doh-ca")
        old_dir.mkdir(parents=True)
        self.assertEqual(mihomo_doh._ca_directory(), old_dir)
        files = mihomo_doh.generate_certificates(self.dest)
        self.assertTrue((old_dir / "root-ca.key").exists())
        self.assertEqual(files.ca_certificate.read_bytes(),
                         (old_dir / "root-ca.crt").read_bytes())
        self.assertFalse(mihomo_doh.generate_certificates(self.dest).renewed)

    def test_user_trust_explicit(self):
        files = mihomo_doh.generate_certificates(self.dest)
        with patch.object(mihomo_doh.subprocess, "run", return_value=MagicMock(returncode=0, stdout="done")) as proc:
            self.assertEqual(mihomo_doh.trust_ca_for_current_user(files.ca_certificate), "done")
            args = proc.call_args[0][0]
            self.assertEqual(args[:4], ["certutil.exe", "-user", "-addstore", "Root"])


if __name__ == "__main__":
    unittest.main()
