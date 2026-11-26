"""Local-only TLS certificate manager for Mihomo's loopback DoH endpoint.

The signing CA key lives in the Windows user's LOCALAPPDATA, not in the
Mihomo configuration directory. Only the CA's public certificate is exported.
"""
from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address, ip_address
import re
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_NAME = "VPN Network Toolkit - Local DoH CA"
CERT_NAME = "mihomo-localhost"


@dataclass(frozen=True)
class CertificateFiles:
    ca_certificate: Path
    server_certificate: Path
    server_private_key: Path
    renewed: bool


def normalize_host(value: str) -> str:
    """Normalize a local DoH endpoint identity; reject URLs and wildcards."""
    text = value.strip()
    if not text:
        raise ValueError("請輸入 DoH 主機名稱。")
    possible_ip = text[1:-1] if text.startswith("[") and text.endswith("]") else text
    try:
        addr = ip_address(possible_ip)
    except ValueError:
        addr = None
    if addr is not None:
        if not addr.is_loopback:
            raise ValueError("DoH IP 必須是 loopback；自訂名稱請使用網域。")
        return str(addr)
    if "://" in text or "/" in text or ":" in text or "*" in text or "@" in text:
        raise ValueError("請輸入主機名稱，不要包含通訊協定、埠號或路徑。")
    try:
        name = text.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("無效的網域名稱。") from exc
    labels = name.split(".")
    valid = all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)
    if not valid or len(name) > 253:
        raise ValueError("無效的網域名稱。")
    return name


def doh_url(host: str, port: int = 9443) -> str:
    host = normalize_host(host)
    address = f"[{host}]" if ":" in host else host
    return f"https://{address}:{port}/dns-query"


def party_hosts_override(host: str) -> str:
    """Return a hosts-entry hint for names needing local resolution."""
    host = normalize_host(host)
    if host == "localhost" or host.endswith(".localhost"):
        return ""
    try:
        ip_address(host)
        return ""
    except ValueError:
        return f"'{host}': 127.0.0.1"


def _ca_directory() -> Path:
    # A signing CA key must not be written next to shareable Mihomo configs.
    root = os.environ.get("LOCALAPPDATA")
    if not root:
        raise RuntimeError("找不到 LOCALAPPDATA；僅支援 Windows 本機憑證管理。")
    base = Path(root) / "reg-chen"
    current = base / "VPN-Network-Toolkit" / "doh-ca"
    legacy = base / "VPN-Mihomo-Generator" / "doh-ca"
    # Reuse the already trusted CA instead of silently minting a new one.
    if current.exists() or not legacy.exists():
        return current
    return legacy


def _pem_key(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".new")
    try:
        with tmp.open("xb") as fp:
            fp.write(data)
        tmp.replace(path)
    finally:
        tmp.unlink(missing_ok=True)


def _build_ca(now: datetime) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CA_NAME)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ), critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return certificate, key


def _load_or_create_ca(now: datetime) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    directory = _ca_directory()
    crt_path = directory / "root-ca.crt"
    key_path = directory / "root-ca.key"
    if crt_path.exists() != key_path.exists():
        raise RuntimeError(f"CA 憑證／私鑰只有一項存在，拒絕覆蓋：{directory}")
    if crt_path.exists():
        ca = x509.load_pem_x509_certificate(crt_path.read_bytes())
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise RuntimeError("既有 CA 私鑰類型不符。")
        if ca.public_key().public_numbers() != key.public_key().public_numbers():
            raise RuntimeError("既有 CA 憑證與私鑰不匹配。")
        ca.verify_directly_issued_by(ca)
        if ca.not_valid_after_utc <= now + timedelta(days=400):
            raise RuntimeError("本機 CA 即將到期；請先手動移除舊 CA 的信任後重建。")
        return ca, key
    ca, key = _build_ca(now)
    directory.mkdir(parents=True, exist_ok=True)
    # Write key before public certificate; incomplete pairs fail closed.
    _atomic_write(key_path, _pem_key(key))
    _atomic_write(crt_path, ca.public_bytes(serialization.Encoding.PEM))
    return ca, key


def _build_server(
    now: datetime,
    ca: x509.Certificate,
    ca_key: ec.EllipticCurvePrivateKey,
    host: str,
) -> tuple[bytes, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    try:
        identity = x509.IPAddress(ip_address(host))
    except ValueError:
        identity = x509.DNSName(host)
    names = [
        x509.DNSName("localhost"),
        x509.IPAddress(IPv4Address("127.0.0.1")),
        x509.IPAddress(IPv6Address("::1")),
    ]
    if identity not in names:
        names.append(identity)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ), critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM), _pem_key(key)


def _valid_server_identity(cert: x509.Certificate, host: str, ca: x509.Certificate) -> bool:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        issuer_ski = ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
        if (ski.critical or aki.critical
                or ski.value != x509.SubjectKeyIdentifier.from_public_key(cert.public_key())
                or aki.value.key_identifier != issuer_ski.digest):
            return False
        try:
            identity = x509.IPAddress(ip_address(host))
        except ValueError:
            identity = x509.DNSName(host)
        addresses = san.get_values_for_type(x509.IPAddress)
        dns_names = san.get_values_for_type(x509.DNSName)
        return (
            (identity.value in addresses if isinstance(identity, x509.IPAddress)
             else identity.value in dns_names)
            and ExtendedKeyUsageOID.SERVER_AUTH in eku
        )
    except x509.ExtensionNotFound:
        return False


def generate_certificates(mihomo_dir: Path, host: str = "127.0.0.1") -> CertificateFiles:
    """Reuse valid certificates; renew expired, mismatched or legacy leafs."""
    if sys.platform != "win32":
        raise RuntimeError("Mihomo DoH 信任匯入功能目前僅支援 Windows。")
    if not str(mihomo_dir).strip():
        raise ValueError("請指定 Mihomo 設定檔目錄。")
    host = normalize_host(host)
    now = datetime.now(timezone.utc)
    ca, ca_key = _load_or_create_ca(now)
    dest = mihomo_dir / "certs"
    cert = dest / f"{CERT_NAME}.crt"
    key = dest / f"{CERT_NAME}.key"
    root = dest / "root-ca.crt"
    if cert.exists() != key.exists():
        raise RuntimeError(f"伺服器憑證／私鑰只有一項存在，拒絕覆蓋：{dest}")
    renewed = True
    if cert.exists():
        current = x509.load_pem_x509_certificate(cert.read_bytes())
        current_key = serialization.load_pem_private_key(key.read_bytes(), password=None)
        if current.public_key().public_numbers() != current_key.public_key().public_numbers():
            raise RuntimeError("現有 DoH 憑證與私鑰不匹配，拒絕覆蓋。")
        if current.issuer == ca.subject and current.not_valid_after_utc > now + timedelta(days=30):
            try:
                current.verify_directly_issued_by(ca)
                renewed = not _valid_server_identity(current, host, ca)
            except (InvalidSignature, ValueError):
                renewed = True
    if renewed:
        crt_pem, key_pem = _build_server(now, ca, ca_key, host)
        _atomic_write(key, key_pem)
        _atomic_write(cert, crt_pem)
    _atomic_write(root, ca.public_bytes(serialization.Encoding.PEM))
    return CertificateFiles(root, cert, key, renewed)


def trust_ca_for_current_user(root_certificate: Path) -> str:
    """Explicit opt-in: trust our local CA for the current Windows user."""
    if sys.platform != "win32":
        raise RuntimeError("只支援 Windows 憑證存放區。")
    if not root_certificate.is_file():
        raise FileNotFoundError(root_certificate)
    result = subprocess.run(
        ["certutil.exe", "-user", "-addstore", "Root", str(root_certificate)],
        capture_output=True, text=True, timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode != 0:
        raise RuntimeError(f"匯入 Windows CurrentUser\\Root 失敗：{result.stderr or result.stdout}")
    return result.stdout.strip()


def mihomo_yaml(files: CertificateFiles) -> str:
    def quote(path: Path) -> str:
        return '"' + str(path).replace("\\", "\\\\").replace('"', '\\"') + '"'
    return (
        "external-controller-tls: 127.0.0.1:9443\n"
        "external-doh-server: /dns-query\n"
        "tls:\n"
        f"  certificate: {quote(files.server_certificate)}\n"
        f"  private-key: {quote(files.server_private_key)}\n"
    )
