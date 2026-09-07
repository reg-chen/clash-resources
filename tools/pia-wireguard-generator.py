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

import pia_generator_core as core

SERVERLIST_URL = "https://serverlist.piaservers.net/vpninfo/servers/v6"
TOKEN_URL = "https://www.privateinternetaccess.com/api/client/v2/token"
PIA_CA_URL = "https://raw.githubusercontent.com/pia-foss/manual-connections/master/ca.rsa.4096.crt"


@dataclass(frozen=True)
class RegionInfo:
    region: dict
    stem: str
    country_code: str


@dataclass(frozen=True)
class WgNode:
    stem: str
    country_code: str
    server_ip: str
    private_key: str
    peer_ip: str
    server_key: str
    server_port: int
    name: str


def fetch_json_first_line(url: str, timeout: float) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "pia-mihomo-wg-generator/3"})
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
        parts.extend([
            f"--{boundary}\r\n".encode(),
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode(),
            value.encode("utf-8"),
            b"\r\n",
        ])
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
            "User-Agent": "pia-mihomo-wg-generator/3",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        payload = json.loads(resp.read().decode("utf-8", errors="strict"))
    token = payload.get("token")
    if not token:
        raise RuntimeError("PIA authentication failed: token not returned")
    return str(token)


def fetch_pia_ca(timeout: float, ca_file: Path | None = None) -> str:
    if ca_file is not None:
        return ca_file.read_text(encoding="utf-8")
    req = urllib.request.Request(PIA_CA_URL, headers={"User-Agent": "pia-mihomo-wg-generator/3"})
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
                "User-Agent": "pia-mihomo-wg-generator/3",
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


def region_stem(region: dict) -> str:
    name = core.normalized_stem(str(region.get("name", "")))
    region_id = core.normalized_stem(str(region.get("id", "")))
    return name or region_id


def is_streaming_region(region: dict) -> bool:
    return any(
        core.normalized_stem(str(value)).endswith("_streaming_optimized")
        for value in (region.get("name", ""), region.get("id", ""))
        if value
    )


def collect_regions(serverlist: dict, exclude_streaming: bool) -> list[RegionInfo]:
    result: list[RegionInfo] = []
    seen: set[tuple[str, str]] = set()

    for region in serverlist.get("regions") or []:
        if exclude_streaming and is_streaming_region(region):
            continue
        if not ((region.get("servers") or {}).get("wg") or []):
            continue

        country_code = str(region.get("country", "")).lower()
        stem = region_stem(region)
        if not country_code or not stem:
            continue

        key = (country_code, stem)
        if key in seen:
            continue
        seen.add(key)
        result.append(RegionInfo(region=region, stem=stem, country_code=country_code))

    result.sort(key=lambda info: (info.country_code, info.stem))
    return result


def multi_country_codes(infos: list[RegionInfo]) -> set[str]:
    grouped: dict[str, set[str]] = {}
    for info in infos:
        grouped.setdefault(info.country_code, set()).add(info.stem)
    return {cc for cc, stems in grouped.items() if len(stems) >= 2}


def fallback_node_name(info: RegionInfo, multi_countries: set[str]) -> str:
    alpha2 = info.country_code.upper()
    display = str(info.region.get("name", "")).strip() or alpha2
    if info.country_code not in multi_countries:
        display = alpha2
    return f"{core.alpha2_flag(alpha2)} WG-PIA-{alpha2}({display})"


def provision_region(
    *,
    info: RegionInfo,
    token: str,
    ca_pem: str,
    timeout: float,
    multi_countries: set[str],
    ov_index: dict[str, tuple[Path, str | None]],
) -> WgNode:
    wg_server = info.region["servers"]["wg"][0]
    server_ip = str(wg_server["ip"])
    hostname = str(wg_server["cn"])
    private_key, public_key = generate_wg_keypair()

    response = add_key(
        server_ip=server_ip,
        hostname=hostname,
        token=token,
        public_key=public_key,
        ca_pem=ca_pem,
        timeout=timeout,
    )

    ov_name = ov_index.get(info.stem, (Path(), None))[1]
    name = core.wg_name_from_openvpn(ov_name) if ov_name else fallback_node_name(info, multi_countries)

    return WgNode(
        stem=info.stem,
        country_code=info.country_code,
        server_ip=server_ip,
        private_key=private_key,
        peer_ip=str(response["peer_ip"]).split("/", 1)[0],
        server_key=str(response["server_key"]),
        server_port=int(response["server_port"]),
        name=name,
    )


def yaml_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_proxy_lines(node: WgNode, indent: int = 2) -> list[str]:
    pad = " " * indent
    child = " " * (indent + 2)
    return [
        f"{pad}- name: {yaml_quote(node.name)}",
        f"{child}type: wireguard",
        f"{child}server: {yaml_quote(node.server_ip)}",
        f"{child}port: {node.server_port}",
        f"{child}ip: {yaml_quote(node.peer_ip)}",
        f"{child}private-key: {yaml_quote(node.private_key)}",
        f"{child}public-key: {yaml_quote(node.server_key)}",
        f"{child}allowed-ips:",
        f"{child}  - 0.0.0.0/0",
        f"{child}persistent-keepalive: 25",
        f"{child}udp: true",
    ]


def build_endpoint_yaml(node: WgNode) -> str:
    return "\n".join([
        "# GENERATED FILE — PIA WireGuard provider payload for Mihomo.",
        f"# Endpoint: {node.name}",
        f"# Source endpoint stem: {node.stem}",
        "# Private key is endpoint-specific. Keep generated payloads local.",
        "proxies:",
        *build_proxy_lines(node),
        "",
    ])


def build_single_yaml(nodes: list[WgNode]) -> str:
    lines = [
        "# GENERATED FILE — aggregate PIA WireGuard provider payload for Mihomo.",
        "# Private keys are endpoint-specific. Keep generated payloads local.",
        "proxies:",
    ]
    for node in nodes:
        lines.extend(build_proxy_lines(node))
    lines.append("")
    return "\n".join(lines)


def generate_wireguard(
    *,
    username: str,
    password: str,
    out_dir: Path,
    single_file: bool,
    exclude_streaming: bool,
    timeout: float = 15.0,
) -> list[Path]:
    providers_root = out_dir / "providers"
    ov_index = core.read_openvpn_endpoint_index(providers_root)

    print("[INFO] Fetching PIA server list...")
    serverlist = fetch_json_first_line(SERVERLIST_URL, timeout)
    infos = collect_regions(serverlist, exclude_streaming=exclude_streaming)
    if not infos:
        raise RuntimeError("PIA server list contains no usable WireGuard regions")

    if ov_index:
        by_stem = {info.stem: info for info in infos}
        aligned = [by_stem[stem] for stem in ov_index if stem in by_stem]
        if aligned:
            infos = aligned
            print(f"[INFO] Aligning WireGuard to {len(infos)} existing pia-ov.yaml endpoint(s).")

    print(f"[INFO] WireGuard regions selected: {len(infos)}")
    print("[INFO] Authenticating with PIA...")
    token = get_token(username, password, timeout)
    print("[OK] Authentication succeeded.")

    print("[INFO] Loading PIA certificate authority...")
    ca_pem = fetch_pia_ca(timeout)
    multi_countries = multi_country_codes(infos)

    nodes: list[WgNode] = []
    failures: list[tuple[RegionInfo, str]] = []
    for index, info in enumerate(infos, start=1):
        wg_server = info.region["servers"]["wg"][0]
        print(
            f"[INFO] [{index}/{len(infos)}] {info.region.get('name')} — "
            f"provisioning {wg_server.get('cn')} ({wg_server.get('ip')})..."
        )
        try:
            nodes.append(provision_region(
                info=info,
                token=token,
                ca_pem=ca_pem,
                timeout=timeout,
                multi_countries=multi_countries,
                ov_index=ov_index,
            ))
        except Exception as exc:
            failures.append((info, str(exc)))
            print(f"[ERROR] {info.region.get('name')}: {exc}")

    if not nodes:
        raise RuntimeError("所有 WireGuard endpoint provisioning 皆失敗。")

    providers_root.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    if single_file:
        path = providers_root / "pia-wg-all.yaml"
        path.write_text(build_single_yaml(nodes), encoding="utf-8", newline="\n")
        written.append(path)
        print(f"[WRITE] {path} ({len(nodes)} nodes, aggregate)")
    else:
        for node in nodes:
            indexed = ov_index.get(node.stem)
            endpoint_dir = indexed[0] if indexed else core.endpoint_tree_dir(
                providers_root,
                node.country_code,
                node.stem,
                multi_countries,
            )
            endpoint_dir.mkdir(parents=True, exist_ok=True)
            path = endpoint_dir / "pia-wg.yaml"
            path.write_text(build_endpoint_yaml(node), encoding="utf-8", newline="\n")
            written.append(path)
            print(f"[WRITE] {path}")

    print(f"[OK] WireGuard: {len(nodes)}/{len(infos)} regions, {len(written)} file(s).")
    if failures:
        print(f"[WARN] {len(failures)} region(s) failed.")
    return written


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Provision PIA WireGuard regions and write Mihomo provider payloads."
    )
    parser.add_argument("--username", help="PIA username; omitted = prompt")
    parser.add_argument("--password", help="PIA password; omitted = secure prompt")
    parser.add_argument("--out-dir", type=Path, default=Path("."))
    parser.add_argument("--single-only", action="store_true")
    parser.add_argument("--include-streaming", action="store_true")
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args()

    username = args.username or input("PIA username: ").strip()
    password = args.password or getpass.getpass("PIA password: ")
    if not username or not password:
        parser.error("username/password cannot be empty")

    generate_wireguard(
        username=username,
        password=password,
        out_dir=args.out_dir,
        single_file=args.single_only,
        exclude_streaming=not args.include_streaming,
        timeout=args.timeout,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
