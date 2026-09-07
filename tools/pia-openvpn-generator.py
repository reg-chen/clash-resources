#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _impl_path() -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS) / "pia-openvpn-generator-impl.py"
    return Path(__file__).resolve().with_name("pia-openvpn-generator-impl.py")


def _load_impl():
    path = _impl_path()
    if not path.is_file():
        raise FileNotFoundError(f"找不到 PIA OpenVPN generator implementation：{path}")

    spec = importlib.util.spec_from_file_location("pia_openvpn_generator_impl_v11", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"無法載入 PIA OpenVPN generator implementation：{path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_impl = _load_impl()

# Public OpenVPN module: protocol-specific implementation stays in the OpenVPN
# implementation file; the generic shared core is not used as an OpenVPN dumping ground.
for _name in dir(_impl):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_impl, _name)


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
    multi_endpoint_countries = _impl.get_multi_endpoint_country_codes(nodes)

    for stem in _impl.endpoint_stems_in_nodes(nodes):
        endpoint_node = _impl.endpoint_representative(nodes, stem)
        alpha2 = _impl.country_alpha2(endpoint_node.country_code)
        endpoint_dir = providers_dir / alpha2

        if endpoint_node.country_code in multi_endpoint_countries:
            endpoint_dir = endpoint_dir / _impl.endpoint_slug(stem, endpoint_node.country_code)

        endpoint_dir.mkdir(parents=True, exist_ok=True)
        provider_nodes = _impl.nodes_for_endpoint(nodes, stem)
        path = endpoint_dir / "pia-ov.yaml"
        path.write_text(
            _impl.build_endpoint_provider_yaml(
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


def print_summary(nodes) -> None:
    countries = _impl.country_codes_in_nodes(nodes)
    endpoint_stems = _impl.endpoint_stems_in_nodes(nodes)
    multi_endpoint_countries = _impl.get_multi_endpoint_country_codes(nodes)

    hot_endpoints = [
        stem for stem in endpoint_stems
        if _impl.is_hot_country(_impl.endpoint_representative(nodes, stem).country_code)
    ]
    cold_endpoints = [
        stem for stem in endpoint_stems
        if not _impl.is_hot_country(_impl.endpoint_representative(nodes, stem).country_code)
    ]

    print(f"節點總數：{len(nodes)}")
    print(f"國家數：{len(countries)}")
    print(f"endpoint 數：{len(endpoint_stems)}（HOT {len(hot_endpoints)} / COLD {len(cold_endpoints)}）")
    print(f"endpoint provider YAML：{len(endpoint_stems)}（每 endpoint 一份 pia-ov.yaml，內含 UDP + TCP）")
    print("HOT endpoint 國家：" + ", ".join(
        _impl.country_alpha2(cc)
        for cc in countries
        if _impl.is_hot_country(cc)
    ))

    if multi_endpoint_countries:
        print(f"多 endpoint 國家數：{len(multi_endpoint_countries)}")
        for cc in sorted(multi_endpoint_countries, key=lambda x: (_impl.COUNTRY_ORDER.get(x, 999), x)):
            stems = sorted({
                _impl.endpoint_stem(node)
                for node in nodes
                if node.country_code == cc
            })
            print(f"  {_impl.country_alpha2(cc)}: {len(stems)} endpoints")


_impl.write_endpoint_tree = write_endpoint_tree
_impl.print_summary = print_summary


def generate_openvpn(
    *,
    udp_zip: Path,
    tcp_zip: Path,
    username: str,
    password: str,
    out_dir: Path,
    single_file: bool,
    exclude_streaming: bool,
) -> None:
    """GUI-friendly OpenVPN entry point without routing through CLI argv."""
    _impl.COMPRESS_MAP_VALUE = "yes"
    ovpn_inputs = _impl.collect_ovpn_inputs([udp_zip, tcp_zip])

    if exclude_streaming:
        streaming = [item for item in ovpn_inputs if _impl.is_streaming_optimized_source(item.name)]
        if streaming:
            print(f"[INFO] 已排除 {len(streaming)} 個 PIA Streaming Optimized profile。")
        ovpn_inputs = [item for item in ovpn_inputs if not _impl.is_streaming_optimized_source(item.name)]

    nodes = []
    for ovpn_file in ovpn_inputs:
        try:
            nodes.append(_impl.parse_ovpn(ovpn_file))
        except Exception as exc:
            raise RuntimeError(f"解析失敗：{ovpn_file.name}") from exc

    nodes = _impl.dedupe_nodes(nodes)
    _impl.apply_node_names(nodes, city_mode="multi")
    if not nodes:
        raise RuntimeError("沒有任何 OpenVPN 節點可輸出。")

    out_dir.mkdir(parents=True, exist_ok=True)
    if single_file:
        target = out_dir / "providers" / "pia-ov-all.yaml"
        _impl.write_single_yaml(
            path=target,
            nodes=nodes,
            username=username,
            password=password,
            hot_ping=20,
            hot_ping_restart=60,
        )
    else:
        write_endpoint_tree(
            out_dir=out_dir,
            nodes=nodes,
            username=username,
            password=password,
            hot_ping=20,
            hot_ping_restart=60,
        )

    print_summary(nodes)


def main() -> None:
    _impl.main()


if __name__ == "__main__":
    main()
