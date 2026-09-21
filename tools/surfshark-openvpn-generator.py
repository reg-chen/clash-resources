#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path

import vpn_generator_core as core

OPENVPN_HANDSHAKE_TIMEOUT = 30
SURFSHARK_FILE_RE = re.compile(
    r"^(?P<endpoint>[a-z]{2}(?:-[a-z0-9]+)+)\.prod\.surfshark\.com_(?P<proto>udp|tcp)\.ovpn$",
    re.I,
)


@dataclass
class OvpnFile:
    name: str
    text: str


@dataclass
class OvpnNode:
    source: str
    endpoint: str
    country_code: str
    server: str
    port: int
    proto: str
    name: str = ""
    dev: str | None = None
    cipher: str | None = None
    auth: str | None = None
    comp_lzo: str | None = None
    ca: str | None = None
    tls_auth: str | None = None
    tls_crypt: str | None = None
    key_direction: str | None = None


def yaml_scalar(value) -> str:
    # Preserve Surfshark numeric-string quoting, unlike the PIA scalar format.
    if value is None:
        return '""'
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    value = str(value)
    if not value:
        return '""'
    if value.isdigit() or re.search(r"[\s:#{}\[\],&*?|\-<>=!%@`\"']", value):
        return core.yaml_quote(value)
    return value


def yaml_kv(key: str, value, indent: int) -> str:
    return f"{' ' * indent}{key}: {yaml_scalar(value)}"


def collect_ovpn_inputs(bundle: Path) -> list[OvpnFile]:
    if not bundle.is_file() or bundle.suffix.lower() != ".zip":
        raise ValueError(f"Surfshark 輸入必須是 ZIP：{bundle}")

    result: list[OvpnFile] = []
    with zipfile.ZipFile(bundle) as archive:
        for member in sorted(archive.namelist()):
            filename = Path(member).name
            if member.endswith("/") or not SURFSHARK_FILE_RE.match(filename):
                continue
            result.append(OvpnFile(name=filename, text=archive.read(member).decode("utf-8", errors="replace")))

    if not result:
        raise FileNotFoundError("ZIP 內找不到 Surfshark OpenVPN profiles。")
    return result


def is_streaming_optimized_source(source_name: str) -> bool:
    match = SURFSHARK_FILE_RE.match(Path(source_name).name)
    return bool(
        match and core.normalized_stem(match.group("endpoint")).endswith("_streaming_optimized")
    )


def parse_ovpn(item: OvpnFile) -> OvpnNode:
    match = SURFSHARK_FILE_RE.match(Path(item.name).name)
    if not match:
        raise ValueError(f"未知 Surfshark 檔名格式：{item.name}")

    endpoint = match.group("endpoint").lower()
    country_code = endpoint.split("-", 1)[0]
    filename_proto = match.group("proto").lower()

    remote = core.get_directive(item.text, "remote")
    if not remote:
        raise ValueError(f"{item.name}: 找不到 remote")
    server = remote[0]
    port = int(remote[1]) if len(remote) >= 2 and remote[1].isdigit() else (1194 if filename_proto == "udp" else 1443)

    proto_parts = core.get_directive(item.text, "proto")
    proto = proto_parts[0].lower() if proto_parts else filename_proto
    if proto.startswith("udp"):
        proto = "udp"
    elif proto.startswith("tcp"):
        proto = "tcp"
    else:
        raise ValueError(f"{item.name}: 不支援的 proto：{proto}")

    ca = core.get_inline_block(item.text, "ca")
    if not ca:
        raise ValueError(f"{item.name}: 找不到 <ca>...</ca>")

    dev = core.get_directive(item.text, "dev")
    cipher = core.get_directive(item.text, "cipher")
    auth = core.get_directive(item.text, "auth")
    comp_lzo = core.get_directive(item.text, "comp-lzo")
    key_direction = core.get_directive(item.text, "key-direction")

    return OvpnNode(
        source=item.name,
        endpoint=endpoint,
        country_code=country_code,
        server=server,
        port=port,
        proto=proto,
        dev=dev[0] if dev else "tun",
        cipher=cipher[0] if cipher else None,
        auth=auth[0] if auth else None,
        comp_lzo=comp_lzo[0] if comp_lzo else None,
        ca=ca,
        tls_auth=core.get_inline_block(item.text, "tls-auth"),
        tls_crypt=core.get_inline_block(item.text, "tls-crypt"),
        key_direction=key_direction[0] if key_direction else None,
    )


def get_multi_endpoint_country_codes(nodes: list[OvpnNode]) -> set[str]:
    grouped: dict[str, set[str]] = {}
    for node in nodes:
        grouped.setdefault(node.country_code, set()).add(node.endpoint)
    return {cc for cc, endpoints in grouped.items() if len(endpoints) >= 2}


def topology_paths(nodes: list[OvpnNode]) -> list[str]:
    multi = get_multi_endpoint_country_codes(nodes)
    by_endpoint: dict[str, OvpnNode] = {}
    for node in nodes:
        by_endpoint.setdefault(node.endpoint, node)

    result: list[str] = []
    for endpoint, node in sorted(by_endpoint.items(), key=lambda item: (item[1].country_code, item[0])):
        cc = node.country_code.upper()
        result.append(
            f"{cc}\\{core.endpoint_slug(endpoint, node.country_code)}"
            if node.country_code in multi else cc
        )
    return result


def sync_override_topology(nodes: list[OvpnNode]) -> bool:
    return core.sync_generated_topology(
        marker="SURFSHARK OPENVPN PATHS",
        const_name="SURFSHARK_OV_PATHS",
        values=topology_paths(nodes),
        source="the official Surfshark OpenVPN bundle",
        generator="tools/surfshark-openvpn-generator.py",
    )


def apply_node_names(nodes: list[OvpnNode]) -> None:
    multi = get_multi_endpoint_country_codes(nodes)
    for node in nodes:
        cc = node.country_code.upper()
        path = f"{cc}\\{core.endpoint_slug(node.endpoint, node.country_code)}" if node.country_code in multi else cc
        node.name = f"{core.vendor_location_name('OV-SS', path)}-{node.proto.upper()}"


def dedupe_nodes(nodes: list[OvpnNode]) -> list[OvpnNode]:
    seen: set[tuple[str, int, str]] = set()
    result: list[OvpnNode] = []
    for node in nodes:
        key = (node.server, node.port, node.proto)
        if key in seen:
            continue
        seen.add(key)
        result.append(node)
    result.sort(key=lambda node: (node.country_code, node.endpoint, 0 if node.proto == "udp" else 1, node.server, node.port))
    return result


def build_openvpn_base_anchor(nodes: list[OvpnNode], username: str, password: str) -> tuple[list[str], set[str]]:
    common_fields: set[str] = set()
    lines = [
        "# 共用 Surfshark OpenVPN 設定（YAML anchors 僅在本檔有效）",
        "x-surfshark-ov: &SURFSHARK-OV",
        yaml_kv("type", "openvpn", 2),
        yaml_kv("username", username, 2),
        yaml_kv("password", password, 2),
    ]

    scalar_attrs = [
        ("dev", "dev"), ("cipher", "cipher"), ("auth", "auth"),
        ("comp_lzo", "comp-lzo"), ("key_direction", "key-direction"),
    ]
    block_attrs = [("ca", "ca"), ("tls_crypt", "tls-crypt"), ("tls_auth", "tls-auth")]

    for attr, yaml_key in scalar_attrs:
        if core.value_same_for_all(nodes, attr):
            value = getattr(nodes[0], attr)
            if value is not None:
                lines.append(yaml_kv(yaml_key, value, 2))
                common_fields.add(attr)

    lines.append(yaml_kv("handshake-timeout", OPENVPN_HANDSHAKE_TIMEOUT, 2))

    for attr, yaml_key in block_attrs:
        if core.value_same_for_all(nodes, attr):
            value = getattr(nodes[0], attr)
            if value:
                lines.extend(core.yaml_block(yaml_key, value, 2))
                common_fields.add(attr)

    return lines, common_fields


def build_payload_node(node: OvpnNode, common_fields: set[str]) -> list[str]:
    lines = [
        f"  - name: {yaml_scalar(node.name)}",
        yaml_kv("server", node.server, 4),
        yaml_kv("port", node.port, 4),
        yaml_kv("proto", node.proto, 4),
        yaml_kv("udp", node.proto == "udp", 4),
    ]

    scalar_attrs = [
        ("dev", "dev"), ("cipher", "cipher"), ("auth", "auth"),
        ("comp_lzo", "comp-lzo"), ("key_direction", "key-direction"),
    ]
    block_attrs = [("ca", "ca"), ("tls_crypt", "tls-crypt"), ("tls_auth", "tls-auth")]

    for attr, yaml_key in scalar_attrs:
        if attr not in common_fields:
            value = getattr(node, attr)
            if value is not None:
                lines.append(yaml_kv(yaml_key, value, 4))
    for attr, yaml_key in block_attrs:
        if attr not in common_fields:
            value = getattr(node, attr)
            if value:
                lines.extend(core.yaml_block(yaml_key, value, 4))

    lines.append("    <<: *SURFSHARK-OV")
    return lines


def build_provider_yaml(nodes: list[OvpnNode], username: str, password: str, header: list[str]) -> str:
    base_lines, common_fields = build_openvpn_base_anchor(nodes, username, password)
    lines = [*header, *base_lines, "", "proxies:"]
    for node in nodes:
        lines.extend(build_payload_node(node, common_fields))
    return "\n".join(lines) + "\n"


def write_endpoint_tree(out_dir: Path, nodes: list[OvpnNode], username: str, password: str) -> None:
    providers_root = out_dir / "providers"
    multi = get_multi_endpoint_country_codes(nodes)
    endpoints = sorted({node.endpoint for node in nodes})

    for endpoint in endpoints:
        provider_nodes = [node for node in nodes if node.endpoint == endpoint]
        representative = provider_nodes[0]
        endpoint_dir = core.endpoint_tree_dir(providers_root, representative.country_code, endpoint, multi)
        endpoint_dir.mkdir(parents=True, exist_ok=True)

        path = endpoint_dir / "surfshark-ov.yaml"
        path.write_text(
            build_provider_yaml(
                provider_nodes,
                username,
                password,
                [
                    "# GENERATED FILE — edit the generator/source bundle, not this file.",
                    f"# Endpoint: {endpoint} | vendor: Surfshark | transports: UDP + TCP",
                ],
            ),
            encoding="utf-8",
            newline="\n",
        )
        print(f"[WRITE] {path} ({len(provider_nodes)} nodes: UDP + TCP)")


def write_single_yaml(out_dir: Path, nodes: list[OvpnNode], username: str, password: str) -> None:
    path = out_dir / "providers" / "surfshark-ov-all.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        build_provider_yaml(
            nodes,
            username,
            password,
            [
                "# GENERATED FILE — aggregate Surfshark OpenVPN provider payload for Mihomo.",
                "# Contains all endpoints/transports from the official Surfshark configuration ZIP.",
            ],
        ),
        encoding="utf-8",
        newline="\n",
    )
    print(f"[WRITE] {path} ({len(nodes)} nodes)")


def print_summary(nodes: list[OvpnNode]) -> None:
    multi = get_multi_endpoint_country_codes(nodes)
    print(f"節點總數：{len(nodes)}")
    print(f"國家數：{len({node.country_code for node in nodes})}")
    print(f"endpoint 數：{len({node.endpoint for node in nodes})}")
    if multi:
        print(f"多 endpoint 國家數：{len(multi)}")
        for cc in sorted(multi):
            endpoints = {node.endpoint for node in nodes if node.country_code == cc}
            print(f"  {cc.upper()}: {len(endpoints)} endpoints")


def generate_openvpn(
    *,
    bundle_zip: Path,
    username: str,
    password: str,
    out_dir: Path,
    single_file: bool,
    sync_override: bool = True,
    exclude_streaming: bool = True,
) -> None:
    inputs = collect_ovpn_inputs(bundle_zip)
    if exclude_streaming:
        inputs = [item for item in inputs if not is_streaming_optimized_source(item.name)]
    nodes = dedupe_nodes([parse_ovpn(item) for item in inputs])
    apply_node_names(nodes)
    if not nodes:
        raise RuntimeError("沒有任何 Surfshark OpenVPN 節點可輸出。")

    out_dir.mkdir(parents=True, exist_ok=True)
    if single_file:
        write_single_yaml(out_dir, nodes, username, password)
    else:
        core.clear_generated_payloads(out_dir / "providers", "surfshark-ov.yaml")
        write_endpoint_tree(out_dir, nodes, username, password)
        if sync_override and not sync_override_topology(nodes):
            print("[INFO] repo override 不在目前 source tree；略過 Surfshark topology sync。")

    print_summary(nodes)


def main() -> None:
    parser = argparse.ArgumentParser(description="Surfshark OpenVPN ZIP -> Mihomo endpoint provider generator")
    parser.add_argument("bundle_zip", type=Path)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--out-dir", type=Path, default=Path("."))
    parser.add_argument("--single-file", action="store_true")
    parser.add_argument("--no-sync-override", action="store_true")
    parser.add_argument("--include-streaming", action="store_true")
    args = parser.parse_args()
    generate_openvpn(
        bundle_zip=args.bundle_zip,
        username=args.username,
        password=args.password,
        out_dir=args.out_dir,
        single_file=args.single_file,
        sync_override=not args.no_sync_override,
        exclude_streaming=not args.include_streaming,
    )


if __name__ == "__main__":
    main()
