#!/usr/bin/env python3
# PIA Strong OpenVPN -> Mihomo provider payload generator.
# v11: one provider payload per endpoint/vendor (pia-ov.yaml), containing UDP + TCP.
#      Permanently excludes every PIA *_streaming_optimized profile.
#
# Generator responsibility is deliberately narrow: it emits only payload files
# that Mihomo file providers can read. proxy-providers declarations and all
# proxy-groups (endpoint / OV-* / AUTO-* / LB-* / PROXY) belong in config.yaml.
#
# Default output layout:
#   Single-endpoint country:
#     <out-dir>/providers/TW/pia-ov.yaml
#   Multi-endpoint country:
#     <out-dir>/providers/US/denver/pia-ov.yaml
#     <out-dir>/providers/US/new-york/pia-ov.yaml
#
# Each pia-ov.yaml contains that endpoint's UDP and TCP nodes together.  The file
# name identifies the VPN vendor; transport is a node property, not a provider
# namespace. This leaves room for future sibling providers such as surfshark.yaml.
#
# Optional Android-friendly aggregate:
#   --single-yaml
#     additionally emits <out-dir>/providers/pia-ov-all.yaml
#   --single-yaml PATH
#     additionally emits PATH (relative paths are resolved under <out-dir>)
#   --single-only
#     skip the endpoint tree and emit only --single-yaml (Android-friendly)
#
# HLS / CHINA / ASIA-EXTRA endpoints are HOT regardless of transport at the
# provider/group layer.  Inside pia-ov.yaml only HOT UDP keeps ping/ping-restart;
# TCP stays free of forced OpenVPN keepalive. Health-check policy is owned by
# config.yaml / the Clash Party JS override, not emitted into payload files.
#
# PIA Strong bundles use naked OpenVPN "compress"; this setup has been empirically
# validated with Mihomo using comp-lzo: yes, which remains the default.

from __future__ import annotations

import argparse
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path

import vpn_generator_core as core

# PIA Strong 的裸 compress 指令在此 Mihomo/PIA 組合需映射成 comp-lzo: yes。
COMPRESS_MAP_VALUE = "yes"

# Mihomo OpenVPN handshake deadline. This does not initiate connections; it only
# bounds handshakes that have already been started by actual traffic/health checks.
OPENVPN_HANDSHAKE_TIMEOUT = 30



# PIA .ovpn file stem -> country code.
# Most files are one-country endpoints. Multi-location countries are handled separately below.
COUNTRY_BY_STEM: dict[str, str] = {
    "albania": "al",
    "algeria": "dz",
    "andorra": "ad",
    "argentina": "ar",
    "armenia": "am",
    "austria": "at",
    "bahamas": "bs",
    "bangladesh": "bd",
    "belgium": "be",
    "bolivia": "bo",
    "bosnia_and_herzegovina": "ba",
    "brazil": "br",
    "bulgaria": "bg",
    "cambodia": "kh",
    "chile": "cl",
    "china": "cn",
    "colombia": "co",
    "costa_rica": "cr",
    "croatia": "hr",
    "cyprus": "cy",
    "czech_republic": "cz",
    "ecuador": "ec",
    "egypt": "eg",
    "estonia": "ee",
    "france": "fr",
    "georgia": "ge",
    "greece": "gr",
    "greenland": "gl",
    "guatemala": "gt",
    "hong_kong": "hk",
    "hungary": "hu",
    "iceland": "is",
    "india": "in",
    "indonesia": "id",
    "ireland": "ie",
    "isle_of_man": "im",
    "israel": "il",
    "kazakhstan": "kz",
    "latvia": "lv",
    "liechtenstein": "li",
    "lithuania": "lt",
    "luxembourg": "lu",
    "macao": "mo",
    "malaysia": "my",
    "malta": "mt",
    "mexico": "mx",
    "moldova": "md",
    "monaco": "mc",
    "mongolia": "mn",
    "montenegro": "me",
    "morocco": "ma",
    "nepal": "np",
    "netherlands": "nl",
    "new_zealand": "nz",
    "nigeria": "ng",
    "north_macedonia": "mk",
    "norway": "no",
    "panama": "pa",
    "peru": "pe",
    "philippines": "ph",
    "poland": "pl",
    "portugal": "pt",
    "qatar": "qa",
    "romania": "ro",
    "saudi_arabia": "sa",
    "serbia": "rs",
    "singapore": "sg",
    "slovakia": "sk",
    "slovenia": "si",
    "south_africa": "za",
    "south_korea": "kr",
    "sri_lanka": "lk",
    "switzerland": "ch",
    "taiwan": "tw",
    "turkey": "tr",
    "ukraine": "ua",
    "united_arab_emirates": "ae",
    "uruguay": "uy",
    "venezuela": "ve",
    "vietnam": "vn",
}


HLS_COUNTRIES = {"tw", "ph", "sg"}

# Policy bucket: Macau / Hong Kong / China stay together.
CHINA_COUNTRIES = {"mo", "hk", "cn"}

ASIA_EXTRA_PRIMARY_COUNTRIES = {"jp", "kr", "my", "id", "th"}

# Asia, excluding HLS and Middle East. The Middle East nodes are intentionally
# separated because latency / routing / content-region behavior differs enough
# from East/Southeast/South Asia to deserve its own provider bucket.
OTHER_ASIA_COUNTRIES = {
    "az", "bd", "bn", "bt", "in",
    "kh", "la", "lk", "mm", "mn", "np", "pk",
    "uz", "vn",
}

MIDDLE_EAST_COUNTRIES = {
    "ae",  # United Arab Emirates
    "eg",  # Egypt: PIA often behaves closer to MENA routing than Sub-Saharan Africa
    "il",
    "qa",
    "sa",
    "tr",
}

EUROPE_COUNTRIES = {
    "ad", "al", "at", "ba", "be", "bg", "ch", "cy", "cz", "de",
    "dk", "ee", "es", "fi", "fr", "gb", "gr", "hr", "hu", "ie",
    "im", "is", "it", "li", "lt", "lu", "lv", "mc", "md", "me",
    "mk", "mt", "nl", "no", "pl", "pt", "ro", "rs", "se", "si",
    "sk", "ua", "uk",
    # Policy placement: Armenia / Georgia / Kazakhstan are in Europe.
    "am", "ge", "kz",
}

NORTH_AMERICA_COUNTRIES = {"ca", "gl", "us"}

LATIN_AMERICA_COUNTRIES = {
    "ar", "bo", "br", "bs", "cl", "co", "cr", "ec", "gt", "mx",
    "pa", "pe", "pr", "py", "uy", "ve",
}

OCEANIA_COUNTRIES = {"au", "nz"}

AFRICA_COUNTRIES = {"dz", "gh", "ma", "ng", "za"}

PROVIDER_BUCKET_ORDER = [
    "hls",
    "china",
    "asia-extra",
    "middle-east",
    "europe",
    "north-america",
    "latin-america",
    "oceania",
    "africa",
    "global-extra",
]

# Smaller / frequently used PIA OpenVPN buckets can use the normal health-check cadence.
# Large regional pools should use a slower cadence to avoid excessive OpenVPN handshakes.
PIA_NORMAL_TEST_BUCKETS = {"hls", "china", "asia-extra"}

COUNTRY_ORDER = {
    # HLS
    "tw": 0,
    "ph": 1,
    "sg": 2,

    # China policy bucket
    "mo": 5,
    "hk": 6,
    "cn": 7,

    # Asia Extra primary
    "jp": 10,
    "kr": 11,
    "my": 12,
    "id": 13,
    "th": 14,

    # Other Asia
    "vn": 20,
    "in": 21,
    "kh": 22,
    "la": 23,
    "mm": 24,
    "mn": 25,
    "np": 26,
    "pk": 27,
    "bd": 28,
    "lk": 29,
    "az": 30,
    "uz": 31,

    # Middle East
    "ae": 50,
    "qa": 51,
    "sa": 52,
    "il": 53,
    "tr": 54,
    "eg": 55,

    # Europe common preference
    "nl": 100,
    "de": 101,
    "uk": 102,
    "gb": 102,
    "fr": 103,
    "es": 104,
    "it": 105,
    "am": 106,
    "ge": 107,
    "kz": 108,

    # North America
    "us": 200,
    "ca": 201,

    # Latin America / Caribbean
    "mx": 250,
    "br": 251,
    "ar": 252,
    "cl": 253,
    "co": 254,

    # Oceania
    "au": 300,
    "nz": 301,

    # Africa
    "za": 350,
    "ng": 351,
    "gh": 352,
    "ma": 353,
    "dz": 354,
}


@dataclass
class OvpnFile:
    name: str
    text: str


@dataclass
class OvpnNode:
    source: str
    server: str
    port: int
    proto: str
    name: str

    country_code: str

    dev: str | None
    cipher: str | None
    auth: str | None
    comp_lzo: str | None

    ca: str | None
    cert: str | None
    key: str | None
    tls_auth: str | None
    tls_crypt: str | None
    key_direction: str | None


def read_text_file(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def collect_ovpn_inputs(input_paths: list[Path]) -> list[OvpnFile]:
    result: list[OvpnFile] = []

    for input_path in input_paths:
        if not input_path.exists():
            raise FileNotFoundError(f"找不到輸入路徑：{input_path}")

        if input_path.is_dir():
            files = sorted(input_path.glob("*.ovpn"))

            if not files:
                raise FileNotFoundError(f"資料夾內找不到 .ovpn：{input_path}")

            result.extend(
                OvpnFile(name=str(path), text=read_text_file(path))
                for path in files
            )
            continue

        if input_path.is_file() and input_path.suffix.lower() == ".zip":
            with zipfile.ZipFile(input_path) as zf:
                ovpn_names = sorted(
                    name
                    for name in zf.namelist()
                    if name.lower().endswith(".ovpn") and not name.endswith("/")
                )

                if not ovpn_names:
                    raise FileNotFoundError(f"zip 內找不到 .ovpn：{input_path}")

                for name in ovpn_names:
                    text = zf.read(name).decode("utf-8", errors="replace")
                    result.append(OvpnFile(name=f"{input_path.name}:{name}", text=text))
            continue

        if input_path.is_file() and input_path.suffix.lower() == ".ovpn":
            result.append(OvpnFile(name=str(input_path), text=read_text_file(input_path)))
            continue

        raise ValueError(f"輸入必須是 .ovpn、含 .ovpn 的資料夾，或 .zip：{input_path}")

    if not result:
        raise FileNotFoundError("找不到任何 .ovpn。")

    return result


def has_directive(text: str, name: str) -> bool:
    pattern = rf"^\s*{re.escape(name)}(?:\s+.*)?$"
    return bool(re.search(pattern, text, flags=re.M | re.I))


def normalize_proto(proto: str | None) -> str:
    if not proto:
        return "udp"

    p = proto.lower()

    if p.startswith("udp"):
        return "udp"

    if p.startswith("tcp"):
        return "tcp"

    return p


def parse_remote(text: str) -> tuple[str, int]:
    remote = core.get_directive(text, "remote")

    if not remote:
        raise ValueError("找不到 remote，例如：remote tw.privacy.network 1197")

    server = remote[0]

    if len(remote) >= 2 and remote[1].isdigit():
        port = int(remote[1])
    else:
        port = 1197

    return server, port


def stem_from_source(source_name: str) -> str:
    # Supports "zipname.zip:filename.ovpn"
    filename = source_name.rsplit(":", 1)[-1]
    return Path(filename).stem.lower()


def is_streaming_optimized_source(source_name: str) -> bool:
    """PIA Streaming Optimized profiles are intentionally unsupported in this setup."""
    return stem_from_source(source_name).endswith("_streaming_optimized")


def country_from_stem(stem: str) -> str:
    """Decode PIA source identity without resolving presentation text."""
    if stem in COUNTRY_BY_STEM:
        return COUNTRY_BY_STEM[stem]
    match = re.match(r"^(?P<cc>[a-z]{2})_.+$", stem)
    if match:
        return match.group("cc")
    raise ValueError(f"未知 PIA 檔名位置格式：{stem}")


def get_provider_bucket(country_code: str) -> str:
    if country_code in HLS_COUNTRIES:
        return "hls"

    if country_code in CHINA_COUNTRIES:
        return "china"

    if country_code in ASIA_EXTRA_PRIMARY_COUNTRIES or country_code in OTHER_ASIA_COUNTRIES:
        return "asia-extra"

    if country_code in MIDDLE_EAST_COUNTRIES:
        return "middle-east"

    if country_code in EUROPE_COUNTRIES:
        return "europe"

    if country_code in NORTH_AMERICA_COUNTRIES:
        return "north-america"

    if country_code in LATIN_AMERICA_COUNTRIES:
        return "latin-america"

    if country_code in OCEANIA_COUNTRIES:
        return "oceania"

    if country_code in AFRICA_COUNTRIES:
        return "africa"

    return "global-extra"


def parse_ovpn(ovpn_file: OvpnFile) -> OvpnNode:
    text = ovpn_file.text

    server, port = parse_remote(text)
    stem = stem_from_source(ovpn_file.name)
    country_code = country_from_stem(stem)

    proto_parts = core.get_directive(text, "proto")
    proto = normalize_proto(proto_parts[0] if proto_parts else None)

    dev_parts = core.get_directive(text, "dev")
    cipher_parts = core.get_directive(text, "cipher")
    auth_parts = core.get_directive(text, "auth")
    comp_lzo_parts = core.get_directive(text, "comp-lzo")
    compress_parts = core.get_directive(text, "compress")
    key_direction_parts = core.get_directive(text, "key-direction")

    # PIA Strong profiles contain a naked OpenVPN "compress" directive.
    # Empirical test on Clash Verge nightly / recent Mihomo shows that PIA works
    # when this is mapped to "comp-lzo: yes".
    if comp_lzo_parts:
        comp_lzo = comp_lzo_parts[0]
    elif compress_parts is not None:
        comp_lzo = COMPRESS_MAP_VALUE
    else:
        comp_lzo = None

    ca = core.get_inline_block(text, "ca")
    cert = core.get_inline_block(text, "cert")
    key = core.get_inline_block(text, "key")
    tls_auth = core.get_inline_block(text, "tls-auth")
    tls_crypt = core.get_inline_block(text, "tls-crypt")

    if not ca:
        raise ValueError(f"{ovpn_file.name}: 找不到 <ca>...</ca>")

    if proto not in {"udp", "tcp"}:
        raise ValueError(f"{ovpn_file.name}: 不支援的 proto：{proto}")

    if not has_directive(text, "auth-user-pass") and not (cert and key):
        print(f"[WARN] {ovpn_file.name}: 找不到 auth-user-pass，也沒有 cert/key，請確認 ovpn 是否完整。")

    return OvpnNode(
        source=ovpn_file.name,
        server=server,
        port=port,
        proto=proto,
        name="",

        country_code=country_code,

        dev=dev_parts[0] if dev_parts else "tun",
        cipher=cipher_parts[0] if cipher_parts else None,
        auth=auth_parts[0] if auth_parts else None,
        comp_lzo=comp_lzo,

        ca=ca,
        cert=cert,
        key=key,
        tls_auth=tls_auth,
        tls_crypt=tls_crypt,
        key_direction=key_direction_parts[0] if key_direction_parts else None,
    )


def endpoint_stem(node: OvpnNode) -> str:
    """Stable endpoint identity shared by the UDP and TCP Strong bundles."""
    return stem_from_source(node.source)


def endpoint_stems_in_nodes(nodes: list[OvpnNode]) -> list[str]:
    stems = {endpoint_stem(node) for node in nodes}

    representative: dict[str, OvpnNode] = {}
    for node in nodes:
        representative.setdefault(endpoint_stem(node), node)

    return sorted(
        stems,
        key=lambda stem: (
            sort_key(representative[stem]),
            stem,
        ),
    )


def get_multi_endpoint_country_codes(nodes: list[OvpnNode]) -> set[str]:
    country_to_endpoints: dict[str, set[str]] = {}

    for node in nodes:
        country_to_endpoints.setdefault(node.country_code, set()).add(endpoint_stem(node))

    return {
        country_code
        for country_code, endpoints in country_to_endpoints.items()
        if len(endpoints) >= 2
    }


def endpoint_representative(nodes: list[OvpnNode], stem: str) -> OvpnNode:
    for node in nodes:
        if endpoint_stem(node) == stem:
            return node
    raise KeyError(f"找不到 endpoint：{stem}")


def endpoint_group_name(
    node: OvpnNode,
    multi_endpoint_countries: set[str],
) -> str:
    path = core.endpoint_tree_dir(
        Path(), node.country_code, endpoint_stem(node), multi_endpoint_countries,
    ).as_posix()
    return core.vendor_location_name("OV-PIA", path)


def apply_node_names(nodes: list[OvpnNode], city_mode: str) -> None:
    # Multi-endpoint countries always include their location for uniqueness.
    multi = get_multi_endpoint_country_codes(nodes)
    for node in nodes:
        show_location = multi
        if city_mode == "always" and endpoint_stem(node) not in COUNTRY_BY_STEM:
            show_location = multi | {node.country_code}
        path = core.endpoint_tree_dir(
            Path(), node.country_code, endpoint_stem(node), show_location,
        ).as_posix()
        node.name = f"{core.vendor_location_name('OV-PIA', path)}-{node.proto.upper()}"


def sort_key(node: OvpnNode) -> tuple[int, int, str, str, int, str, int]:
    bucket_order = {bucket: index for index, bucket in enumerate(PROVIDER_BUCKET_ORDER)}

    proto_order = {
        "udp": 0,
        "tcp": 1,
    }

    bucket = get_provider_bucket(node.country_code)

    return (
        bucket_order.get(bucket, 9),
        COUNTRY_ORDER.get(node.country_code, 999),
        node.country_code,
        endpoint_stem(node),
        proto_order.get(node.proto, 9),
        node.name,
        node.port,
    )


def dedupe_nodes(nodes: list[OvpnNode]) -> list[OvpnNode]:
    seen: set[tuple[str, int, str]] = set()
    result: list[OvpnNode] = []

    for node in nodes:
        key = (node.server, node.port, node.proto)

        if key in seen:
            continue

        seen.add(key)
        result.append(node)

    result.sort(key=sort_key)

    return result


def country_codes_in_nodes(nodes: list[OvpnNode]) -> list[str]:
    codes = {node.country_code for node in nodes}
    bucket_order = {bucket: index for index, bucket in enumerate(PROVIDER_BUCKET_ORDER)}
    return sorted(
        codes,
        key=lambda cc: (
            bucket_order.get(get_provider_bucket(cc), 999),
            COUNTRY_ORDER.get(cc, 999),
            cc,
        ),
    )


def country_alpha2(country_code: str) -> str:
    return country_code.upper()


def provider_name(
    node: OvpnNode,
    multi_endpoint_countries: set[str],
) -> str:
    """Stable provider name: one PIA provider per endpoint, transport-agnostic."""
    alpha2 = country_alpha2(node.country_code).lower()
    if node.country_code in multi_endpoint_countries:
        slug = core.endpoint_slug(endpoint_stem(node), node.country_code)
        return f"ov-pia-{alpha2}-{slug}"
    return f"ov-pia-{alpha2}"


def is_hot_country(country_code: str) -> bool:
    return get_provider_bucket(country_code) in PIA_NORMAL_TEST_BUCKETS


def is_hot_openvpn_file(country_code: str, proto: str) -> bool:
    # Preserve the existing transport keepalive policy: only HOT UDP gets 20/60.
    # HOT TCP is health-checked at the provider layer but does not get forced ping.
    return is_hot_country(country_code) and proto == "udp"


def nodes_for_endpoint(nodes: list[OvpnNode], stem: str) -> list[OvpnNode]:
    """Return all transports for one endpoint; sort_key keeps UDP before TCP."""
    result = [
        node for node in nodes
        if endpoint_stem(node) == stem
    ]
    result.sort(key=sort_key)
    return result


def maybe_add_ping(lines: list[str], ping: int, ping_restart: int, indent: int) -> None:
    if ping > 0:
        lines.append(core.yaml_kv("ping", ping, indent=indent))
    if ping_restart > 0:
        lines.append(core.yaml_kv("ping-restart", ping_restart, indent=indent))


def build_openvpn_base_anchor(
    all_nodes: list[OvpnNode],
    username: str,
    password: str,
) -> tuple[list[str], set[str]]:
    """Build the common PIA OpenVPN anchor repeated in every provider document."""
    common_fields: set[str] = set()
    lines: list[str] = [
        "# 共用 PIA OpenVPN 設定（YAML anchors 僅在本檔有效）",
        "x-pia-ov: &PIA-OV",
        core.yaml_kv("type", "openvpn", indent=2),
        core.yaml_kv("username", username, indent=2),
        core.yaml_kv("password", password, indent=2),
    ]

    scalar_attrs = [
        ("dev", "dev"),
        ("cipher", "cipher"),
        ("auth", "auth"),
        ("comp_lzo", "comp-lzo"),
        ("key_direction", "key-direction"),
    ]
    block_attrs = [
        ("ca", "ca"),
        ("cert", "cert"),
        ("key", "key"),
        ("tls_crypt", "tls-crypt"),
        ("tls_auth", "tls-auth"),
    ]

    for attr, yaml_key in scalar_attrs:
        if core.value_same_for_all(all_nodes, attr):
            value = getattr(all_nodes[0], attr)
            if value is not None:
                lines.append(core.yaml_kv(yaml_key, value, indent=2))
                common_fields.add(attr)

    # Hard requirement retained from the validated v2 generator.
    # This caps only handshakes that have already started; it does not initiate them.
    lines.append(core.yaml_kv("handshake-timeout", OPENVPN_HANDSHAKE_TIMEOUT, indent=2))

    for attr, yaml_key in block_attrs:
        if core.value_same_for_all(all_nodes, attr):
            value = getattr(all_nodes[0], attr)
            if value:
                lines.extend(core.yaml_block(yaml_key, value, indent=2))
                common_fields.add(attr)

    return lines, common_fields


def build_payload_node(
    node: OvpnNode,
    common_fields: set[str],
    ov_anchor: str,
    indent: int = 2,
) -> list[str]:
    lines = [
        f"{' ' * indent}- name: {core.yaml_scalar(node.name)}",
        core.yaml_kv("server", node.server, indent=indent + 2),
        core.yaml_kv("port", node.port, indent=indent + 2),
        core.yaml_kv("proto", node.proto, indent=indent + 2),
        core.yaml_kv("udp", node.proto == "udp", indent=indent + 2),
    ]

    scalar_attrs = [
        ("dev", "dev"),
        ("cipher", "cipher"),
        ("auth", "auth"),
        ("comp_lzo", "comp-lzo"),
        ("key_direction", "key-direction"),
    ]
    block_attrs = [
        ("ca", "ca"),
        ("cert", "cert"),
        ("key", "key"),
        ("tls_crypt", "tls-crypt"),
        ("tls_auth", "tls-auth"),
    ]

    for attr, yaml_key in scalar_attrs:
        if attr not in common_fields:
            value = getattr(node, attr)
            if value is not None:
                lines.append(core.yaml_kv(yaml_key, value, indent=indent + 2))

    for attr, yaml_key in block_attrs:
        if attr not in common_fields:
            value = getattr(node, attr)
            if value:
                lines.extend(core.yaml_block(yaml_key, value, indent=indent + 2))

    lines.append(f"{' ' * (indent + 2)}<<: *{ov_anchor}")
    return lines


def build_endpoint_provider_yaml(
    endpoint_node: OvpnNode,
    provider_nodes: list[OvpnNode],
    all_nodes: list[OvpnNode],
    username: str,
    password: str,
    hot_ping: int,
    hot_ping_restart: int,
    multi_endpoint_countries: set[str],
) -> str:
    """Build one vendor payload (pia-ov.yaml) containing UDP + TCP for an endpoint."""
    base_lines, common_fields = build_openvpn_base_anchor(
        all_nodes=all_nodes,
        username=username,
        password=password,
    )

    endpoint_name = endpoint_group_name(endpoint_node, multi_endpoint_countries)
    lines: list[str] = [
        "# GENERATED FILE — edit the generator/source bundles, not this file.",
        f"# Endpoint: {endpoint_name} | vendor: PIA | transports: UDP + TCP",
        f"# Source endpoint stem: {endpoint_stem(endpoint_node)}",
        "# Common blocks repeat because YAML anchors are document-local.",
        *base_lines,
    ]

    has_hot_udp = any(
        is_hot_openvpn_file(node.country_code, node.proto)
        for node in provider_nodes
    )
    if has_hot_udp:
        lines.extend([
            "",
            "# HOT UDP：HLS / CHINA / ASIA-EXTRA 保留積極 keepalive；同 endpoint 的 TCP 不套用。",
            "x-pia-ov-hot: &PIA-OV-HOT",
            "  <<: *PIA-OV",
        ])
        maybe_add_ping(lines, hot_ping, hot_ping_restart, indent=2)

    lines.append("")
    if not provider_nodes:
        lines.append("proxies: []")
        return "\n".join(lines) + "\n"

    lines.append("proxies:")
    for node in provider_nodes:
        ov_anchor = (
            "PIA-OV-HOT"
            if is_hot_openvpn_file(node.country_code, node.proto)
            else "PIA-OV"
        )
        lines.extend(build_payload_node(node, common_fields, ov_anchor, indent=2))

    return "\n".join(lines) + "\n"


def write_endpoint_tree(
    out_dir: Path,
    nodes,
    username: str,
    password: str,
    hot_ping: int,
    hot_ping_restart: int,
) -> None:
    """Write one PIA OpenVPN payload per endpoint as pia-ov.yaml."""
    providers_dir = out_dir / "providers"
    providers_dir.mkdir(parents=True, exist_ok=True)
    multi_endpoint_countries = get_multi_endpoint_country_codes(nodes)

    for stem in endpoint_stems_in_nodes(nodes):
        endpoint_node = endpoint_representative(nodes, stem)
        endpoint_dir = core.endpoint_tree_dir(
            providers_dir,
            endpoint_node.country_code,
            stem,
            multi_endpoint_countries,
        )
        endpoint_dir.mkdir(parents=True, exist_ok=True)

        provider_nodes = nodes_for_endpoint(nodes, stem)
        path = endpoint_dir / "pia-ov.yaml"
        path.write_text(
            build_endpoint_provider_yaml(
                endpoint_node=endpoint_node,
                provider_nodes=provider_nodes,
                all_nodes=nodes,
                username=username,
                password=password,
                hot_ping=hot_ping,
                hot_ping_restart=hot_ping_restart,
                multi_endpoint_countries=multi_endpoint_countries,
            ),
            encoding="utf-8",
            newline="\n",
        )
        print(f"[WRITE] {path} ({len(provider_nodes)} nodes: UDP + TCP)")




def build_single_provider_yaml(
    nodes: list[OvpnNode],
    username: str,
    password: str,
    hot_ping: int,
    hot_ping_restart: int,
) -> str:
    """Build one Android payload containing every PIA node. Android config may expose multiple filtered provider views over this one file."""
    base_lines, common_fields = build_openvpn_base_anchor(
        all_nodes=nodes,
        username=username,
        password=password,
    )

    lines: list[str] = [
        "# GENERATED FILE — aggregate PIA Strong provider payload for Mihomo.",
        "# Contains all endpoints/transports; Android config can create multiple filtered proxy-provider views over this single file.",
        "# HOT UDP nodes use PIA-OV-HOT; all other nodes use PIA-OV.",
        *base_lines,
    ]

    has_hot_udp = any(
        is_hot_openvpn_file(node.country_code, node.proto)
        for node in nodes
    )
    if has_hot_udp:
        lines.extend([
            "",
            "# HOT UDP：HLS / CHINA / ASIA-EXTRA 保留積極 keepalive。",
            "x-pia-ov-hot: &PIA-OV-HOT",
            "  <<: *PIA-OV",
        ])
        maybe_add_ping(lines, hot_ping, hot_ping_restart, indent=2)

    lines.extend(["", "proxies:"])
    for node in nodes:
        ov_anchor = (
            "PIA-OV-HOT"
            if is_hot_openvpn_file(node.country_code, node.proto)
            else "PIA-OV"
        )
        lines.extend(build_payload_node(node, common_fields, ov_anchor, indent=2))

    return "\n".join(lines) + "\n"


def resolve_single_yaml_path(out_dir: Path, value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = out_dir / path
    return path


def write_single_yaml(
    path: Path,
    nodes: list[OvpnNode],
    username: str,
    password: str,
    hot_ping: int,
    hot_ping_restart: int,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        build_single_provider_yaml(
            nodes=nodes,
            username=username,
            password=password,
            hot_ping=hot_ping,
            hot_ping_restart=hot_ping_restart,
        ),
        encoding="utf-8",
        newline="\n",
    )
    print(f"[WRITE] {path} ({len(nodes)} nodes, aggregate)")

def print_summary(nodes) -> None:
    countries = country_codes_in_nodes(nodes)
    endpoint_stems = endpoint_stems_in_nodes(nodes)
    multi_endpoint_countries = get_multi_endpoint_country_codes(nodes)

    hot_endpoints = [
        stem for stem in endpoint_stems
        if is_hot_country(endpoint_representative(nodes, stem).country_code)
    ]
    cold_endpoints = [
        stem for stem in endpoint_stems
        if not is_hot_country(endpoint_representative(nodes, stem).country_code)
    ]

    print(f"節點總數：{len(nodes)}")
    print(f"國家數：{len(countries)}")
    print(f"endpoint 數：{len(endpoint_stems)}（HOT {len(hot_endpoints)} / COLD {len(cold_endpoints)}）")
    print(f"endpoint provider YAML：{len(endpoint_stems)}（每 endpoint 一份 pia-ov.yaml，內含 UDP + TCP）")
    print("HOT endpoint 國家：" + ", ".join(
        country_alpha2(cc)
        for cc in countries
        if is_hot_country(cc)
    ))

    if multi_endpoint_countries:
        print(f"多 endpoint 國家數：{len(multi_endpoint_countries)}")
        for cc in sorted(multi_endpoint_countries, key=lambda x: (COUNTRY_ORDER.get(x, 999), x)):
            stems = sorted({
                endpoint_stem(node)
                for node in nodes
                if node.country_code == cc
            })
            print(f"  {country_alpha2(cc)}: {len(stems)} endpoints")


def topology_paths(nodes) -> list[str]:
    """Exact canonical folder paths generated for the current PIA OpenVPN bundle."""
    multi = get_multi_endpoint_country_codes(nodes)
    result: list[str] = []
    for stem in endpoint_stems_in_nodes(nodes):
        node = endpoint_representative(nodes, stem)
        alpha2 = country_alpha2(node.country_code)
        if node.country_code in multi:
            result.append(f"{alpha2}\\{core.endpoint_slug(stem, node.country_code)}")
        else:
            result.append(alpha2)
    return result


def sync_override_topology(nodes) -> bool:
    synced = core.sync_generated_js_array(
        marker="PIA OPENVPN PATHS",
        const_name="PIA_OV_PATHS",
        values=topology_paths(nodes),
        source="the current PIA OpenVPN bundles",
        generator="tools/pia-openvpn-generator.py",
    )
    if synced:
        core.sync_override_location_catalog(generator="tools/pia-openvpn-generator.py")
    return synced


def generate_openvpn(
    *,
    udp_zip: Path,
    tcp_zip: Path,
    username: str,
    password: str,
    out_dir: Path,
    single_file: bool,
    exclude_streaming: bool,
    sync_override: bool = True,
) -> None:
    """GUI-friendly OpenVPN entry point without routing through CLI argv."""
    global COMPRESS_MAP_VALUE
    COMPRESS_MAP_VALUE = "yes"
    ovpn_inputs = collect_ovpn_inputs([udp_zip, tcp_zip])

    if exclude_streaming:
        streaming = [item for item in ovpn_inputs if is_streaming_optimized_source(item.name)]
        if streaming:
            print(f"[INFO] 已排除 {len(streaming)} 個 PIA Streaming Optimized profile。")
        ovpn_inputs = [item for item in ovpn_inputs if not is_streaming_optimized_source(item.name)]

    nodes = []
    for ovpn_file in ovpn_inputs:
        try:
            nodes.append(parse_ovpn(ovpn_file))
        except Exception as exc:
            raise RuntimeError(f"解析失敗：{ovpn_file.name}") from exc

    nodes = dedupe_nodes(nodes)
    apply_node_names(nodes, city_mode="multi")
    if not nodes:
        raise RuntimeError("沒有任何 OpenVPN 節點可輸出。")

    out_dir.mkdir(parents=True, exist_ok=True)
    if single_file:
        target = out_dir / "providers" / "pia-ov-all.yaml"
        write_single_yaml(
            path=target,
            nodes=nodes,
            username=username,
            password=password,
            hot_ping=20,
            hot_ping_restart=60,
        )
    else:
        providers_root = out_dir / "providers"
        core.clear_generated_payloads(providers_root, "pia-ov.yaml")
        write_endpoint_tree(
            out_dir=out_dir,
            nodes=nodes,
            username=username,
            password=password,
            hot_ping=20,
            hot_ping_restart=60,
        )
        if sync_override and not sync_override_topology(nodes):
            print("[INFO] repo override 不在目前 source tree；略過 PIA OpenVPN topology sync。")

    print_summary(nodes)



def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert PIA Strong UDP/TCP OpenVPN bundles into one Mihomo pia-ov.yaml provider payload per endpoint. proxy-providers and proxy-groups remain in config.yaml."
    )
    parser.add_argument(
        "inputs",
        nargs="+",
        type=Path,
        help="PIA .ovpn、包含 .ovpn 的資料夾，或 Strong UDP/TCP zip；可同時輸入多個。",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("."),
        help="輸出根目錄；每個 endpoint 目錄只產生 pia-ov.yaml（UDP + TCP），不產生任何 proxy-providers/group fragment。",
    )
    parser.add_argument(
        "--single-yaml",
        nargs="?",
        const="providers/pia-ov-all.yaml",
        default=None,
        metavar="PATH",
        help="額外產生單一 aggregate provider YAML；不帶 PATH 時輸出 <out-dir>/providers/pia-ov-all.yaml。相對 PATH 以 --out-dir 為基準。",
    )
    parser.add_argument(
        "--single-only",
        action="store_true",
        help="只輸出 --single-yaml，不建立 providers/<endpoint>/pia-ov.yaml；給 Android 單檔 payload 使用。",
    )
    parser.add_argument("--username", default="", help="PIA OpenVPN username，可留空手填。")
    parser.add_argument("--password", default="", help="PIA OpenVPN password，可留空手填。")
    parser.add_argument(
        "--city-mode",
        choices=["multi", "always", "never"],
        default="multi",
        help="raw node 命名：multi=多 endpoint 國家顯示位置；always=全部；never=單 endpoint 可省略位置。多 endpoint 國家為避免撞名仍強制顯示 endpoint。",
    )
    parser.add_argument(
        "--pia-hot-ping",
        type=int,
        default=20,
        help="HOT UDP OpenVPN ping interval 秒；0=不輸出。預設 20。",
    )
    parser.add_argument(
        "--pia-hot-ping-restart",
        type=int,
        default=60,
        help="HOT UDP OpenVPN ping-restart 秒；0=不輸出。預設 60。",
    )
    parser.add_argument(
        "--compress-map",
        choices=["adaptive", "yes", "no"],
        default="yes",
        help="將 PIA 裸 compress 映射成 comp-lzo；預設 yes（此 PIA/Mihomo 組合已實測需要）。",
    )
    parser.add_argument(
        "--exclude-stem",
        action="append",
        default=[],
        help="額外排除指定 PIA ovpn stem；可重複指定。所有 *_streaming_optimized 已固定排除。",
    )

    args = parser.parse_args()

    global COMPRESS_MAP_VALUE
    COMPRESS_MAP_VALUE = args.compress_map

    ovpn_inputs = collect_ovpn_inputs(args.inputs)

    # PIA Streaming Optimized profiles consistently time out in this deployment.
    # Filter them before parsing so they never affect country/location topology,
    # endpoint counts, provider payloads, or the Android aggregate.
    streaming_optimized = [
        ovpn_file for ovpn_file in ovpn_inputs
        if is_streaming_optimized_source(ovpn_file.name)
    ]
    if streaming_optimized:
        print(f"[INFO] 已固定排除 {len(streaming_optimized)} 個 PIA Streaming Optimized 節點。")
    ovpn_inputs = [
        ovpn_file for ovpn_file in ovpn_inputs
        if not is_streaming_optimized_source(ovpn_file.name)
    ]

    nodes: list[OvpnNode] = []
    for ovpn_file in ovpn_inputs:
        try:
            nodes.append(parse_ovpn(ovpn_file))
        except Exception as exc:
            raise RuntimeError(f"解析失敗：{ovpn_file.name}") from exc

    excluded_stems = {stem.lower() for stem in (args.exclude_stem or [])}
    if excluded_stems:
        before_count = len(nodes)
        nodes = [node for node in nodes if stem_from_source(node.source) not in excluded_stems]
        excluded_count = before_count - len(nodes)
        if excluded_count:
            print(f"[INFO] 已排除 {excluded_count} 個節點：{', '.join(sorted(excluded_stems))}")

    nodes = dedupe_nodes(nodes)
    apply_node_names(nodes, city_mode=args.city_mode)

    if not nodes:
        parser.error("排除後沒有任何節點可輸出。")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    if args.single_only and args.single_yaml is None:
        args.single_yaml = "pia-ov-all.yaml"

    if not args.single_only:
        write_endpoint_tree(
            out_dir=args.out_dir,
            nodes=nodes,
            username=args.username,
            password=args.password,
            hot_ping=args.pia_hot_ping,
            hot_ping_restart=args.pia_hot_ping_restart,
        )

    if args.single_yaml is not None:
        write_single_yaml(
            path=resolve_single_yaml_path(args.out_dir, args.single_yaml),
            nodes=nodes,
            username=args.username,
            password=args.password,
            hot_ping=args.pia_hot_ping,
            hot_ping_restart=args.pia_hot_ping_restart,
        )

    print(f"OVPN 檔案數：{len(ovpn_inputs)}")
    print_summary(nodes)

    has_tls_auth = any(node.tls_auth for node in nodes)
    has_tls_crypt = any(node.tls_crypt for node in nodes)
    has_comp_lzo = any(node.comp_lzo is not None for node in nodes)

    if has_tls_auth:
        print("[WARN] 偵測到 tls-auth；請確認目前 Mihomo OpenVPN outbound 支援狀況。")
    else:
        print("[OK] 未偵測到 tls-auth/key-direction。")

    if has_tls_crypt:
        print("[INFO] 偵測到 tls-crypt。")
    else:
        print("[INFO] 未偵測到 tls-crypt。")

    if has_comp_lzo:
        print(f"[OK] OpenVPN compress/comp-lzo 已映射為 comp-lzo: {COMPRESS_MAP_VALUE}。")


if __name__ == "__main__":
    main()
