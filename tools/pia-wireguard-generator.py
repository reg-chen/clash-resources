#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import getpass
import http.client
import importlib.util
import json
import re
import socket
import ssl
import sys
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
class RegionInfo:
    region: dict
    stem: str
    country_code: str
    location_label: str | None


@dataclass(frozen=True)
class WgNode:
    info: RegionInfo
    server_ip: str
    private_key: str
    peer_ip: str
    server_key: str
    server_port: int
    name: str


def load_openvpn_core():
    path = Path(__file__).resolve().with_name("pia-openvpn-generator.py")
    if not path.is_file():
        raise FileNotFoundError(
            f"找不到同目錄的 OpenVPN generator：{path}. "
            "WireGuard generator 會共用其 endpoint/country 命名規則。"
        )
    spec = importlib.util.spec_from_file_location("pia_openvpn_generator_core", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"無法載入 OpenVPN generator：{path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def fetch_json_first_line(url: str, timeout: float) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "pia-mihomo-wg-generator/2"})
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
            "User-Agent": "pia-mihomo-wg-generator/2",
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
    req = urllib.request.Request(PIA_CA_URL, headers={"User-Agent": "pia-mihomo-wg-generator/2"})
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
    # CA is accepted by their curl --cacert flow but fails that stricter check.
    # Keep certificate-chain and hostname verification enabled; relax only X509 strictness.
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
                "User-Agent": "pia-mihomo-wg-generator/2",
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


def normalized_region_stem(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def is_streaming_region(region: dict, core) -> bool:
    candidates = [
        str(region.get("id", "")),
        normalized_region_stem(str(region.get("name", ""))),
    ]
    return any(core.is_streaming_optimized_source(f"{value}.ovpn") for value in candidates if value)


def canonical_region_info(region: dict, core) -> RegionInfo:
    server_cc = str(region.get("country", "")).lower()
    if not server_cc:
        raise ValueError(f"Region has no country: {region}")

    # PIA's display names line up closely with Strong OpenVPN bundle stems
    # (CA Montreal -> ca_montreal, JP Tokyo -> jp_tokyo, Netherlands -> netherlands).
    # Prefer that form, then fall back to the server-list id.
    candidates = []
    display_stem = normalized_region_stem(str(region.get("name", "")))
    region_id = str(region.get("id", "")).lower().strip()
    for candidate in (display_stem, region_id):
        if candidate and candidate not in candidates:
            candidates.append(candidate)

    for stem in candidates:
        try:
            cc, label = core.location_from_stem(stem)
        except Exception:
            continue
        if cc == server_cc:
            return RegionInfo(region=region, stem=stem, country_code=cc, location_label=label)

    # Future PIA regions should still be usable even before the OpenVPN mapping table
    # learns their display name. The country code remains authoritative from serverlist.
    fallback_stem = region_id or display_stem
    if not fallback_stem:
        raise ValueError(f"Cannot derive endpoint stem from region: {region}")
    label = str(region.get("name", "")).strip() or None
    return RegionInfo(region=region, stem=fallback_stem, country_code=server_cc, location_label=label)


def collect_regions(serverlist: dict, core, include_streaming: bool) -> list[RegionInfo]:
    result: list[RegionInfo] = []
    seen: set[tuple[str, str]] = set()

    for region in serverlist.get("regions") or []:
        if not include_streaming and is_streaming_region(region, core):
            continue
        if not ((region.get("servers") or {}).get("wg") or []):
            continue

        info = canonical_region_info(region, core)
        key = (info.country_code, info.stem)
        if key in seen:
            continue
        seen.add(key)
        result.append(info)

    bucket_order = {name: index for index, name in enumerate(core.PROVIDER_BUCKET_ORDER)}
    result.sort(key=lambda info: (
        bucket_order.get(core.get_provider_bucket(info.country_code), 999),
        core.COUNTRY_ORDER.get(info.country_code, 999),
        info.country_code,
        info.stem,
    ))
    return result


def multi_endpoint_countries(infos: list[RegionInfo]) -> set[str]:
    counts: dict[str, set[str]] = {}
    for info in infos:
        counts.setdefault(info.country_code, set()).add(info.stem)
    return {cc for cc, stems in counts.items() if len(stems) >= 2}


def build_ov_directory_index(providers_root: Path) -> dict[str, Path]:
    index: dict[str, Path] = {}
    if not providers_root.is_dir():
        return index
    marker = re.compile(r"^# Source endpoint stem:\s*(.+?)\s*$")
    for path in providers_root.rglob("pia-ov.yaml"):
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                for _ in range(8):
                    line = fh.readline()
                    if not line:
                        break
                    match = marker.match(line.rstrip("\r\n"))
                    if match:
                        index[match.group(1).strip().lower()] = path.parent
                        break
        except OSError:
            continue
    return index


def endpoint_directory(
    *,
    providers_root: Path,
    info: RegionInfo,
    multi_countries: set[str],
    ov_index: dict[str, Path],
    core,
) -> Path:
    # If the OpenVPN tree already exists, use its own source-stem marker as the
    # authoritative placement. This keeps pia-wg.yaml literally beside pia-ov.yaml.
    if info.stem in ov_index:
        return ov_index[info.stem]

    alpha2 = core.country_alpha2(info.country_code)
    path = providers_root / alpha2
    if info.country_code in multi_countries:
        path = path / core.endpoint_slug(info.stem, info.country_code)
    return path


def wg_node_name(info: RegionInfo, multi_countries: set[str], core) -> str:
    ov_name = core.pia_base_name(
        country_code=info.country_code,
        location_label=info.location_label,
        multi_location_countries=multi_countries,
        city_mode="multi",
    )
    return ov_name.replace(" OV-PIA-", " WG-PIA-", 1)


def provision_region(
    *,
    info: RegionInfo,
    token: str,
    ca_pem: str,
    timeout: float,
    multi_countries: set[str],
    core,
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

    return WgNode(
        info=info,
        server_ip=server_ip,
        private_key=private_key,
        peer_ip=str(response["peer_ip"]).split("/", 1)[0],
        server_key=str(response["server_key"]),
        server_port=int(response["server_port"]),
        name=wg_node_name(info, multi_countries, core),
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
        f"# Source endpoint stem: {node.info.stem}",
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


def resolve_single_yaml_path(out_dir: Path, value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = out_dir / path
    return path


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Provision every current PIA WireGuard region and write one pia-wg.yaml "
            "per endpoint using the same tree semantics as pia-openvpn-generator.py."
        )
    )
    parser.add_argument("--username", help="PIA username. If omitted, prompt interactively.")
    parser.add_argument("--password", help="PIA password. If omitted, prompt securely.")
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("."),
        help="輸出根目錄，例如 P:\\Clash；預設建立 providers/<endpoint>/pia-wg.yaml。",
    )
    parser.add_argument(
        "--single-yaml",
        nargs="?",
        const="providers/pia-wg-all.yaml",
        default=None,
        metavar="PATH",
        help="額外產生 aggregate WG provider；不帶 PATH 時輸出 providers/pia-wg-all.yaml。",
    )
    parser.add_argument(
        "--single-only",
        action="store_true",
        help="只輸出 aggregate WG provider，不建立 endpoint tree。",
    )
    parser.add_argument(
        "--include-streaming",
        action="store_true",
        help="包含 PIA Streaming Optimized region；預設排除以對齊目前 OpenVPN/JS topology。",
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="任一 endpoint provisioning 失敗時立即停止；預設繼續其他 endpoint 並於最後回報失敗。",
    )
    parser.add_argument("--ca-file", type=Path, help="Optional local PIA ca.rsa.4096.crt")
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args()

    core = load_openvpn_core()

    username = args.username or input("PIA username: ").strip()
    password = args.password or getpass.getpass("PIA password: ")
    if not username or not password:
        parser.error("username/password cannot be empty")

    providers_root = args.out_dir / "providers"
    ov_index = build_ov_directory_index(providers_root)

    print("[INFO] Fetching PIA server list...")
    serverlist = fetch_json_first_line(SERVERLIST_URL, args.timeout)
    infos = collect_regions(serverlist, core, args.include_streaming)
    if not infos:
        parser.error("PIA server list contains no usable WireGuard regions")

    if ov_index:
        available_by_stem = {info.stem: info for info in infos}
        missing = sorted(set(ov_index) - set(available_by_stem))
        infos = [available_by_stem[stem] for stem in ov_index if stem in available_by_stem]
        print(f"[INFO] Aligning to {len(ov_index)} existing pia-ov.yaml endpoint markers.")
        if missing:
            print(f"[WARN] {len(missing)} OpenVPN endpoint(s) have no matching WireGuard region: {', '.join(missing)}")
    else:
        missing = []
        print("[INFO] No pia-ov.yaml tree found; using every current PIA WireGuard region.")

    print(f"[INFO] WireGuard regions selected: {len(infos)}")
    if not args.include_streaming:
        print("[INFO] PIA Streaming Optimized regions are excluded.")

    print("[INFO] Authenticating with PIA...")
    token = get_token(username, password, args.timeout)
    print("[OK] Authentication succeeded.")

    print("[INFO] Loading PIA certificate authority...")
    ca_pem = fetch_pia_ca(args.timeout, args.ca_file)

    multi_countries = multi_endpoint_countries(infos)
    nodes: list[WgNode] = []
    failures: list[tuple[RegionInfo, str]] = []

    for index, info in enumerate(infos, start=1):
        wg_server = info.region["servers"]["wg"][0]
        server_ip = str(wg_server["ip"])
        hostname = str(wg_server["cn"])
        print(
            f"[INFO] [{index}/{len(infos)}] {info.region.get('name')} — "
            f"provisioning {hostname} ({server_ip})..."
        )
        try:
            node = provision_region(
                info=info,
                token=token,
                ca_pem=ca_pem,
                timeout=args.timeout,
                multi_countries=multi_countries,
                core=core,
            )
        except Exception as exc:
            print(f"[ERROR] {info.region.get('name')}: {exc}")
            failures.append((info, str(exc)))
            if args.fail_fast:
                raise
            continue

        nodes.append(node)
        if not args.single_only:
            endpoint_dir = endpoint_directory(
                providers_root=providers_root,
                info=info,
                multi_countries=multi_countries,
                ov_index=ov_index,
                core=core,
            )
            endpoint_dir.mkdir(parents=True, exist_ok=True)
            path = endpoint_dir / "pia-wg.yaml"
            path.write_text(build_endpoint_yaml(node), encoding="utf-8", newline="\n")
            print(f"[WRITE] {path}")

    if args.single_only and args.single_yaml is None:
        args.single_yaml = "providers/pia-wg-all.yaml"

    if args.single_yaml is not None:
        path = resolve_single_yaml_path(args.out_dir, args.single_yaml)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(build_single_yaml(nodes), encoding="utf-8", newline="\n")
        print(f"[WRITE] {path} ({len(nodes)} nodes, aggregate)")

    print(f"[OK] Provisioned {len(nodes)}/{len(infos)} PIA WireGuard regions.")
    if failures:
        print(f"[WARN] {len(failures)} region(s) failed:")
        for info, error in failures:
            print(f"  - {info.region.get('name')}: {error}")
    if missing or failures:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
