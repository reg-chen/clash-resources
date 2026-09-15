#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path


# Provider source names are not a filesystem schema. Normalize known aliases to
# stable, readable location slugs so different vendors share the same directory
# for the same actual location.
LOCATION_SLUG_ALIASES: dict[str, dict[str, str]] = {
    "IN": {
        "del": "delhi",
        "mum": "mumbai",
    },
    "DE": {
        "ber": "berlin",
        "fra": "frankfurt",
    },
    "UK": {
        "edi": "edinburgh",
        "gla": "glasgow",
        "lon": "london",
        "man": "manchester",
    },
    "FR": {
        "bod": "bordeaux",
        "mrs": "marseille",
        "par": "paris",
    },
    "ES": {
        "bcn": "barcelona",
        "mad": "madrid",
        "vlc": "valencia",
    },
    "IT": {
        "mil": "milan",
        "milano": "milan",
        "rom": "rome",
    },
    "BE": {
        "anr": "antwerp",
        "bru": "brussels",
    },
    "PL": {
        "gdn": "gdansk",
        "waw": "warsaw",
    },
    "PT": {
        "lis": "lisbon",
        "opo": "porto",
    },
    "US": {
        "ash": "ashburn",
        "atl": "atlanta",
        "bna": "nashville",
        "bos": "boston",
        "buf": "buffalo",
        "chi": "chicago",
        "clt": "charlotte",
        "dal": "dallas",
        "den": "denver",
        "dtw": "detroit",
        "hou": "houston",
        "kan": "kansas-city",
        "las": "las-vegas",
        "lax": "los-angeles",
        "mia": "miami",
        "nyc": "new-york",
        "oma": "omaha",
        "phx": "phoenix",
        "sea": "seattle",
        "sfo": "san-francisco",
        "sjc": "san-jose",
        "slc": "salt-lake-city",
        "bdn": "bend",
        "ltm": "latham",
    },
    "CA": {
        "mon": "montreal",
        "tor": "toronto",
        "van": "vancouver",
    },
    "AU": {
        "adl": "adelaide",
        "bne": "brisbane",
        "mel": "melbourne",
        "per": "perth",
        "syd": "sydney",
    },
}


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
    slug = re.sub(r"[^a-z0-9]+", "-", raw).strip("-") or "default"
    return LOCATION_SLUG_ALIASES.get(country_code.upper(), {}).get(slug, slug)


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


def clear_generated_payloads(providers_root: Path, filename: str) -> list[Path]:
    """Remove only generator-owned payloads with the exact managed filename."""
    if not providers_root.is_dir():
        return []

    removed: list[Path] = []
    for path in providers_root.rglob(filename):
        path.unlink()
        removed.append(path)
        print(f"[REMOVE] {path}")
    return removed


def source_override_path(filename: str = "vpn-providers.js") -> Path | None:
    """Return the checked-out override path; frozen builds intentionally have none."""
    if getattr(sys, "frozen", False):
        return None
    candidate = Path(__file__).resolve().parents[1] / "overrides" / filename
    return candidate if candidate.is_file() else None


def sync_generated_js_array(
    *,
    marker: str,
    const_name: str,
    values: list[str],
    source: str,
    generator: str,
    override_path: Path | None = None,
) -> bool:
    """
    Replace one explicitly marked generated JS array in the checked-out override.

    The generator-discovered list remains the sole topology source. The JS array is a
    runtime artifact required only because Clash Party's override sandbox cannot inspect
    the local provider filesystem.
    """
    path = override_path or source_override_path()
    if path is None:
        return False

    start_marker = f"// BEGIN GENERATED {marker}"
    end_marker = f"// END GENERATED {marker}"
    text = path.read_text(encoding="utf-8")
    start = text.find(start_marker)
    end = text.find(end_marker)
    if start < 0 or end < 0 or end < start:
        raise RuntimeError(f"{path}: 找不到 generated block：{marker}")

    lines = [
        start_marker,
        f"// AUTO-GENERATED from {source}.",
        f"// Do not edit this block by hand; regenerate it with {generator}.",
        f"const {const_name} = [",
    ]
    lines.extend(f"  {json.dumps(value, ensure_ascii=False)}," for value in values)
    lines.extend([
        "];",
        end_marker,
    ])
    block = "\n".join(lines)

    end += len(end_marker)
    updated = text[:start] + block + text[end:]
    if updated != text:
        path.write_text(updated, encoding="utf-8", newline="\n")
        print(f"[WRITE] {path} ({const_name} synced)")
    else:
        print(f"[OK] {path} ({const_name} unchanged)")
    return True


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
