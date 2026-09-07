#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path


def bundled_path(filename: str) -> Path:
    """Resolve a sibling source file both from the repo and from PyInstaller _MEIPASS."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS) / filename
    return Path(__file__).resolve().with_name(filename)


def load_sibling(filename: str, module_name: str):
    """Load one protocol-specific generator without coupling protocols to each other."""
    path = bundled_path(filename)
    if not path.is_file():
        raise FileNotFoundError(f"找不到模組：{path}")

    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"無法載入模組：{path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def normalized_stem(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def alpha2_flag(alpha2: str) -> str:
    alpha2 = alpha2.upper()
    if len(alpha2) != 2 or not alpha2.isalpha():
        return "🏳️"
    return "".join(chr(0x1F1E6 + ord(ch) - ord("A")) for ch in alpha2)


def endpoint_slug(stem: str, country_code: str) -> str:
    raw = normalized_stem(stem)
    prefix = f"{country_code.lower()}_"
    if raw.startswith(prefix):
        raw = raw[len(prefix):]
    return re.sub(r"[^a-z0-9]+", "-", raw).strip("-") or "default"


def endpoint_tree_dir(
    providers_root: Path,
    country_code: str,
    stem: str,
    multi_countries: set[str],
) -> Path:
    path = providers_root / country_code.upper()
    if country_code in multi_countries:
        path = path / endpoint_slug(stem, country_code)
    return path


def read_openvpn_endpoint_index(providers_root: Path) -> dict[str, tuple[Path, str | None]]:
    """
    Index existing pia-ov.yaml files by their Source endpoint stem.

    The optional display name is read from the first proxy node and lets WireGuard
    mirror the established OpenVPN naming without importing OpenVPN implementation code.
    """
    result: dict[str, tuple[Path, str | None]] = {}
    if not providers_root.is_dir():
        return result

    for path in providers_root.rglob("pia-ov.yaml"):
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue

        stem: str | None = None
        node_name: str | None = None
        for line in lines[:80]:
            if line.startswith("# Source endpoint stem:"):
                stem = normalized_stem(line.split(":", 1)[1])
            stripped = line.strip()
            if node_name is None and stripped.startswith("- name:"):
                value = stripped.split(":", 1)[1].strip()
                if len(value) >= 2 and value[0] == value[-1] == '"':
                    value = value[1:-1].replace('\\"', '"').replace('\\\\', '\\')
                node_name = value
            if stem and node_name:
                break

        if stem:
            result[stem] = (path.parent, node_name)

    return result


def wg_name_from_openvpn(openvpn_name: str) -> str:
    name = re.sub(r"-(?:UDP|TCP)$", "", openvpn_name)
    return name.replace(" OV-PIA-", " WG-PIA-", 1)
