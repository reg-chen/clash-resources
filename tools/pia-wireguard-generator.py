#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import getpass
import http.client
import json
import socket
import ssl
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

SERVERLIST_URL = "https://serverlist.piaservers.net/vpninfo/servers/v6"
TOKEN_URL = "https://www.privateinternetaccess.com/api/client/v2/token"
PIA_CA_URL = "https://raw.githubusercontent.com/pia-foss/manual-connections/master/ca.rsa.4096.crt"


@dataclass(frozen=True)
class Target:
    key: str
    alpha2: str
    flag: str
    label: str
    region_names: tuple[str, ...]


TARGETS: tuple[Target, ...] = (
    Target("tw", "TW", "🇹🇼", "台灣", ("Taiwan",)),
    Target("sg", "SG", "🇸🇬", "新加坡", ("Singapore",)),
    Target("ph", "PH", "🇵🇭", "菲律賓", ("Philippines",)),
    Target("hk", "HK", "🇭🇰", "香港", ("Hong Kong",)),
    Target("jp", "JP", "🇯🇵", "日本", ("Japan", "JP Tokyo")),
    Target("kr", "KR", "🇰🇷", "韓國", ("South Korea",)),
)


def fetch_json_first_line(url: str, timeout: float) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "pia-mihomo-wg-generator/1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="strict")
    first_line = raw.splitlines()[0].strip()
    if not first_line:
        raise RuntimeError(f"Empty response from {url}")
    return json.loads(first_line)


def multipart_form(fields: dict[str, str]) -> tuple[bytes, str]:
    boundary = f"----pia-mihomo-{uuid.uuid4().hex}"
    parts: list[bytes] = []
    for name, value in fields.items():
        parts.extend(
            [
                f"--{boundary}\r\n".encode(),
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(),
                value.encode("utf-8"),
                b"\r\n",
            ]
        )
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def get_token(username: str, password: str, timeout: float) -> str:
    body, content_type = multipart_form({"username": username, "password": password})
    req = urllib.request.Request(
        TOKEN_URL,
        data=body,
        method="POST",
        headers={
            "Content-Type": content_type,
            "User-Agent": "pia-mihomo-wg-generator/1",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = json.loads(resp.read().decode("utf-8", errors="strict"))
    token = payload.get("token")
    if not token:
        raise RuntimeError("PIA authentication failed: token not returned")
    return str(token)


def fetch_pia_ca(timeout: float, ca_file: Path | None) -> str:
    if ca_file is not None:
        return ca_file.read_text(encoding="utf-8")
    req = urllib.request.Request(PIA_CA_URL, headers={"User-Agent": "pia-mihomo-wg-generator/1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="strict")


class FixedIPHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        hostname: str,
        connect_ip: str,
        port: int,
        context: ssl.SSLContext,
        timeout: float,
    ) -> None:
        super().__init__(hostname, port=port, timeout=timeout, context=context)
        self._connect_ip = connect_ip

    def connect(self) -> None:
        raw_sock = socket.create_connection((self._connect_ip, self.port), self.timeout)
        if self._tunnel_host:
            self.sock = raw_sock
            self._tunnel()
            raw_sock = self.sock
        self.sock = self._context.wrap_socket(raw_sock, server_hostname=self.host)


def generate_wg_keypair() -> tuple[str, str]:
    private = X25519PrivateKey.generate()
    public = private.public_key()
    private_raw = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public_raw = public.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return (
        base64.b64encode(private_raw).decode("ascii"),
        base64.b64encode(public_raw).decode("ascii"),
    )


def add_key(
    *,
    server_ip: str,
    hostname: str,
    token: str,
    public_key: str,
    ca_pem: str,
    timeout: float,
) -> dict:
    context = ssl.create_default_context(cadata=ca_pem)
    # Python 3.13 enables VERIFY_X509_STRICT by default. PIA's official legacy
    # ca.rsa.4096.crt is accepted by their curl --cacert flow but fails strict
    # RFC 5280 validation because its Basic Constraints extension is not critical.
    # Keep certificate + hostname verification enabled; relax only X509 strictness.
    if hasattr(ssl, "VERIFY_X509_STRICT"):
        context.verify_flags &= ~ssl.VERIFY_X509_STRICT

    query = urllib.parse.urlencode({"pt": token, "pubkey": public_key})
    conn = FixedIPHTTPSConnection(
        hostname=hostname,
        connect_ip=server_ip,
        port=1337,
        context=context,
        timeout=timeout,
    )
    try:
        conn.request(
            "GET",
            f"/addKey?{query}",
            headers={
                "Host": f"{hostname}:1337",
                "User-Agent": "pia-mihomo-wg-generator/1",
                "Accept": "application/json",
            },
        )
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", errors="replace")
    finally:
        conn.close()

    if resp.status != 200:
        raise RuntimeError(f"PIA WireGuard API returned HTTP {resp.status}: {body[:300]}")
    payload = json.loads(body)
    if payload.get("status") != "OK":
        raise RuntimeError(f"PIA WireGuard API did not return OK: {payload}")
    return payload


def find_region(serverlist: dict, target: Target) -> dict:
    regions = serverlist.get("regions") or []
    exact = {name.casefold() for name in target.region_names}
    matches = [
        region for region in regions
        if str(region.get("name", "")).casefold() in exact
    ]
    if not matches:
        available = ", ".join(sorted(str(r.get("name", "")) for r in regions))
        raise RuntimeError(
            f"PIA region not found for {target.alpha2} ({'/'.join(target.region_names)}). "
            f"Available regions: {available}"
        )
    # Exact names deliberately avoid Streaming Optimized variants.
    region = matches[0]
    wg_servers = ((region.get("servers") or {}).get("wg") or [])
    if not wg_servers:
        raise RuntimeError(f"PIA region {region.get('name')} has no WireGuard server")
    return region


def yaml_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_provider_yaml(
    *,
    target: Target,
    server_ip: str,
    private_key: str,
    response: dict,
) -> str:
    peer_ip = str(response["peer_ip"]).split("/", 1)[0]
    server_key = str(response["server_key"])
    server_port = int(response["server_port"])
    name = f"{target.flag} WG-PIA-{target.alpha2}({target.label})"
    return "\n".join(
        [
            f"# GENERATED FILE — PIA WireGuard provider for {target.alpha2} / Mihomo.",
            "# Private key is endpoint-specific. Keep generated payloads local.",
            "proxies:",
            f"  - name: {yaml_quote(name)}",
            "    type: wireguard",
            f"    server: {yaml_quote(server_ip)}",
            f"    port: {server_port}",
            f"    ip: {yaml_quote(peer_ip)}",
            f"    private-key: {yaml_quote(private_key)}",
            f"    public-key: {yaml_quote(server_key)}",
            "    allowed-ips:",
            "      - 0.0.0.0/0",
            "    persistent-keepalive: 25",
            "    udp: true",
            "",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Provision PIA WireGuard peers for TW/SG/PH/HK/JP/KR and write Mihomo "
            "provider payloads beside the existing PIA OpenVPN tree."
        )
    )
    parser.add_argument("--username", help="PIA username. If omitted, prompt interactively.")
    parser.add_argument("--password", help="PIA password. If omitted, prompt securely.")
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("."),
        help=(
            "Root directory. Example: --out-dir P:\\Clash writes "
            "P:\\Clash\\providers\\TW\\pia-wg.yaml etc."
        ),
    )
    parser.add_argument("--ca-file", type=Path, help="Optional local PIA ca.rsa.4096.crt")
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args()

    username = args.username or input("PIA username: ").strip()
    password = args.password or getpass.getpass("PIA password: ")
    if not username or not password:
        parser.error("username/password cannot be empty")

    print("[INFO] Fetching PIA server list...")
    serverlist = fetch_json_first_line(SERVERLIST_URL, args.timeout)

    print("[INFO] Authenticating with PIA...")
    token = get_token(username, password, args.timeout)
    print("[OK] Authentication succeeded.")

    print("[INFO] Loading PIA certificate authority...")
    ca_pem = fetch_pia_ca(args.timeout, args.ca_file)

    providers_root = args.out_dir / "providers"
    written: list[Path] = []

    for target in TARGETS:
        region = find_region(serverlist, target)
        wg_server = region["servers"]["wg"][0]
        server_ip = str(wg_server["ip"])
        hostname = str(wg_server["cn"])
        private_key, public_key = generate_wg_keypair()

        print(
            f"[INFO] {target.flag} {region['name']}: provisioning {hostname} ({server_ip})..."
        )
        response = add_key(
            server_ip=server_ip,
            hostname=hostname,
            token=token,
            public_key=public_key,
            ca_pem=ca_pem,
            timeout=args.timeout,
        )

        path = providers_root / target.alpha2 / "pia-wg.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            build_provider_yaml(
                target=target,
                server_ip=server_ip,
                private_key=private_key,
                response=response,
            ),
            encoding="utf-8",
            newline="\n",
        )
        written.append(path)
        print(f"[WRITE] {path}")

    print(f"[OK] Generated {len(written)} PIA WireGuard provider files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
