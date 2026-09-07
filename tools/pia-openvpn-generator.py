#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _core_path() -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS) / "_pia-openvpn-generator-core.py"
    return Path(__file__).resolve().with_name("_pia-openvpn-generator-core.py")


def _load_core():
    path = _core_path()
    if not path.is_file():
        raise FileNotFoundError(f"找不到 PIA OpenVPN generator core：{path}")
    spec = importlib.util.spec_from_file_location("pia_openvpn_generator_core_v11", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"無法載入 PIA OpenVPN generator core：{path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_core = _load_core()

# Re-export the validated v11 implementation so GUI/WG tooling can continue to
# import this file as the public generator module without duplicating parser logic.
for _name in dir(_core):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_core, _name)


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
    multi_endpoint_countries = _core.get_multi_endpoint_country_codes(nodes)

    for stem in _core.endpoint_stems_in_nodes(nodes):
        endpoint_node = _core.endpoint_representative(nodes, stem)
        alpha2 = _core.country_alpha2(endpoint_node.country_code)
        endpoint_dir = providers_dir / alpha2

        if endpoint_node.country_code in multi_endpoint_countries:
            endpoint_dir = endpoint_dir / _core.endpoint_slug(stem, endpoint_node.country_code)

        endpoint_dir.mkdir(parents=True, exist_ok=True)
        provider_nodes = _core.nodes_for_endpoint(nodes, stem)
        path = endpoint_dir / "pia-ov.yaml"
        path.write_text(
            _core.build_endpoint_provider_yaml(
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
    countries = _core.country_codes_in_nodes(nodes)
    endpoint_stems = _core.endpoint_stems_in_nodes(nodes)
    multi_endpoint_countries = _core.get_multi_endpoint_country_codes(nodes)

    hot_endpoints = [
        stem for stem in endpoint_stems
        if _core.is_hot_country(_core.endpoint_representative(nodes, stem).country_code)
    ]
    cold_endpoints = [
        stem for stem in endpoint_stems
        if not _core.is_hot_country(_core.endpoint_representative(nodes, stem).country_code)
    ]

    print(f"節點總數：{len(nodes)}")
    print(f"國家數：{len(countries)}")
    print(f"endpoint 數：{len(endpoint_stems)}（HOT {len(hot_endpoints)} / COLD {len(cold_endpoints)}）")
    print(f"endpoint provider YAML：{len(endpoint_stems)}（每 endpoint 一份 pia-ov.yaml，內含 UDP + TCP）")
    print("HOT endpoint 國家：" + ", ".join(
        _core.country_alpha2(cc)
        for cc in countries
        if _core.is_hot_country(cc)
    ))

    if multi_endpoint_countries:
        print(f"多 endpoint 國家數：{len(multi_endpoint_countries)}")
        for cc in sorted(multi_endpoint_countries, key=lambda x: (_core.COUNTRY_ORDER.get(x, 999), x)):
            stems = sorted({
                _core.endpoint_stem(node)
                for node in nodes
                if node.country_code == cc
            })
            print(f"  {_core.country_alpha2(cc)}: {len(stems)} endpoints")


# core.main() resolves these names from its own module globals.
_core.write_endpoint_tree = write_endpoint_tree
_core.print_summary = print_summary


def main() -> None:
    _core.main()


if __name__ == "__main__":
    main()
