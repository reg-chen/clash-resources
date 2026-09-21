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
    "IN": {"del": "delhi", "mum": "mumbai"},
    "DE": {"ber": "berlin", "fra": "frankfurt"},
    "UK": {"edi": "edinburgh", "gla": "glasgow", "lon": "london", "man": "manchester"},
    "FR": {"bod": "bordeaux", "mrs": "marseille", "par": "paris"},
    "ES": {"bcn": "barcelona", "mad": "madrid", "vlc": "valencia"},
    "IT": {"mil": "milan", "milano": "milan", "rom": "rome"},
    "BE": {"anr": "antwerp", "bru": "brussels"},
    "PL": {"gdn": "gdansk", "waw": "warsaw"},
    "PT": {"lis": "lisbon", "opo": "porto"},
    "US": {
        "ash": "ashburn", "atl": "atlanta", "bna": "nashville", "bos": "boston",
        "buf": "buffalo", "chi": "chicago", "clt": "charlotte", "dal": "dallas",
        "den": "denver", "dtw": "detroit", "hou": "houston", "kan": "kansas-city",
        "las": "las-vegas", "lax": "los-angeles", "mia": "miami", "nyc": "new-york",
        "oma": "omaha", "phx": "phoenix", "sea": "seattle", "sfo": "san-francisco",
        "sjc": "san-jose", "slc": "salt-lake-city", "bdn": "bend", "ltm": "latham",
    },
    "CA": {"mon": "montreal", "tor": "toronto", "van": "vancouver"},
    "AU": {"adl": "adelaide", "bne": "brisbane", "mel": "melbourne", "per": "perth", "syd": "sydney"},
}


# Shared user-facing location vocabulary. Provider parsers own source decoding;
# this catalog owns presentation for every generator and generated runtime metadata.
COUNTRY_ZH: dict[str, str] = {
    "TW": "台灣",
    "PH": "菲律賓",
    "SG": "新加坡",
    "MO": "澳門",
    "HK": "香港",
    "CN": "中國",
    "JP": "日本",
    "KR": "韓國",
    "MY": "馬來西亞",
    "ID": "印尼",
    "VN": "越南",
    "IN": "印度",
    "KH": "柬埔寨",
    "MN": "蒙古",
    "NP": "尼泊爾",
    "BD": "孟加拉",
    "LK": "斯里蘭卡",
    "AE": "阿聯酋",
    "QA": "卡達",
    "SA": "沙烏地阿拉伯",
    "IL": "以色列",
    "TR": "土耳其",
    "EG": "埃及",
    "NL": "荷蘭",
    "DE": "德國",
    "UK": "英國",
    "FR": "法國",
    "ES": "西班牙",
    "IT": "義大利",
    "AM": "亞美尼亞",
    "GE": "喬治亞",
    "KZ": "哈薩克",
    "AD": "安道爾",
    "AL": "阿爾巴尼亞",
    "AT": "奧地利",
    "BA": "波士尼亞",
    "BE": "比利時",
    "BG": "保加利亞",
    "CH": "瑞士",
    "CY": "賽普勒斯",
    "CZ": "捷克",
    "DK": "丹麥",
    "EE": "愛沙尼亞",
    "FI": "芬蘭",
    "GR": "希臘",
    "HR": "克羅埃西亞",
    "HU": "匈牙利",
    "IE": "愛爾蘭",
    "IM": "曼島",
    "IS": "冰島",
    "LI": "列支敦斯登",
    "LT": "立陶宛",
    "LU": "盧森堡",
    "LV": "拉脫維亞",
    "MC": "摩納哥",
    "MD": "摩爾多瓦",
    "ME": "蒙特內哥羅",
    "MK": "北馬其頓",
    "MT": "馬爾他",
    "NO": "挪威",
    "PL": "波蘭",
    "PT": "葡萄牙",
    "RO": "羅馬尼亞",
    "RS": "塞爾維亞",
    "SE": "瑞典",
    "SI": "斯洛維尼亞",
    "SK": "斯洛伐克",
    "UA": "烏克蘭",
    "US": "美國",
    "CA": "加拿大",
    "GL": "格陵蘭",
    "MX": "墨西哥",
    "BR": "巴西",
    "AR": "阿根廷",
    "CL": "智利",
    "CO": "哥倫比亞",
    "BO": "玻利維亞",
    "BS": "巴哈馬",
    "BZ": "貝里斯",
    "CR": "哥斯大黎加",
    "EC": "厄瓜多",
    "GT": "瓜地馬拉",
    "PA": "巴拿馬",
    "PE": "秘魯",
    "PR": "波多黎各",
    "PY": "巴拉圭",
    "UY": "烏拉圭",
    "VE": "委內瑞拉",
    "AU": "澳洲",
    "NZ": "紐西蘭",
    "ZA": "南非",
    "NG": "奈及利亞",
    "GH": "迦納",
    "MA": "摩洛哥",
    "DZ": "阿爾及利亞",
    "AZ": "亞塞拜然",
    "BT": "不丹",
    "BN": "汶萊",
    "LA": "寮國",
    "MM": "緬甸",
    "PK": "巴基斯坦",
    "TH": "泰國",
    "UZ": "烏茲別克",
}

LOCATION_ZH: dict[str, str] = {
    "IN\\\\delhi": "德里",
    "IN\\\\mumbai": "孟買",
    "NL\\\\netherlands": "荷蘭",
    "DE\\\\berlin": "柏林",
    "DE\\\\frankfurt": "法蘭克福",
    "UK\\\\edinburgh": "愛丁堡",
    "UK\\\\glasgow": "格拉斯哥",
    "UK\\\\london": "倫敦",
    "UK\\\\manchester": "曼徹斯特",
    "UK\\\\southampton": "南安普敦",
    "FR\\\\bordeaux": "波爾多",
    "FR\\\\marseille": "馬賽",
    "FR\\\\paris": "巴黎",
    "ES\\\\barcelona": "巴塞隆納",
    "ES\\\\madrid": "馬德里",
    "ES\\\\valencia": "瓦倫西亞",
    "IT\\\\milan": "米蘭",
    "IT\\\\rome": "羅馬",
    "BE\\\\antwerp": "安特衛普",
    "BE\\\\brussels": "布魯塞爾",
    "PL\\\\gdansk": "格但斯克",
    "PL\\\\warsaw": "華沙",
    "PT\\\\lisbon": "里斯本",
    "PT\\\\porto": "波多",
    "DK\\\\copenhagen": "哥本哈根",
    "FI\\\\helsinki": "赫爾辛基",
    "SE\\\\stockholm": "斯德哥爾摩",
    "US\\\\alabama": "阿拉巴馬",
    "US\\\\alaska": "阿拉斯加",
    "US\\\\arkansas": "阿肯色",
    "US\\\\ashburn": "阿什本",
    "US\\\\atlanta": "亞特蘭大",
    "US\\\\baltimore": "巴爾的摩",
    "US\\\\california": "加州",
    "US\\\\nashville": "納什維爾",
    "US\\\\boston": "波士頓",
    "US\\\\buffalo": "水牛城",
    "US\\\\chicago": "芝加哥",
    "US\\\\charlotte": "夏洛特",
    "US\\\\connecticut": "康乃狄克",
    "US\\\\dallas": "達拉斯",
    "US\\\\denver": "丹佛",
    "US\\\\detroit": "底特律",
    "US\\\\east": "美東",
    "US\\\\florida": "佛羅里達",
    "US\\\\honolulu": "檀香山",
    "US\\\\houston": "休士頓",
    "US\\\\idaho": "愛達荷",
    "US\\\\indiana": "印第安納",
    "US\\\\iowa": "愛荷華",
    "US\\\\kansas": "堪薩斯",
    "US\\\\kansas-city": "堪薩斯城",
    "US\\\\kentucky": "肯塔基",
    "US\\\\las-vegas": "拉斯維加斯",
    "US\\\\los-angeles": "洛杉磯",
    "US\\\\louisiana": "路易斯安那",
    "US\\\\maine": "緬因",
    "US\\\\massachusetts": "麻薩諸塞",
    "US\\\\miami": "邁阿密",
    "US\\\\michigan": "密西根",
    "US\\\\minnesota": "明尼蘇達",
    "US\\\\mississippi": "密西西比",
    "US\\\\missouri": "密蘇里",
    "US\\\\montana": "蒙大拿",
    "US\\\\nebraska": "內布拉斯加",
    "US\\\\new-hampshire": "新罕布夏",
    "US\\\\new-mexico": "新墨西哥",
    "US\\\\new-york": "紐約",
    "US\\\\north-carolina": "北卡羅來納",
    "US\\\\north-dakota": "北達科他",
    "US\\\\ohio": "俄亥俄",
    "US\\\\oklahoma": "奧克拉荷馬",
    "US\\\\omaha": "奧馬哈",
    "US\\\\oregon": "奧勒岡",
    "US\\\\pennsylvania": "賓夕法尼亞",
    "US\\\\phoenix": "鳳凰城",
    "US\\\\rhode-island": "羅德島",
    "US\\\\salt-lake-city": "鹽湖城",
    "US\\\\san-francisco": "舊金山",
    "US\\\\san-jose": "聖荷西",
    "US\\\\seattle": "西雅圖",
    "US\\\\silicon-valley": "矽谷",
    "US\\\\south-carolina": "南卡羅來納",
    "US\\\\south-dakota": "南達科他",
    "US\\\\tennessee": "田納西",
    "US\\\\texas": "德州",
    "US\\\\vermont": "佛蒙特",
    "US\\\\virginia": "維吉尼亞",
    "US\\\\washington-dc": "華盛頓DC",
    "US\\\\west": "美西",
    "US\\\\west-virginia": "西維吉尼亞",
    "US\\\\wilmington": "威明頓",
    "US\\\\wisconsin": "威斯康辛",
    "US\\\\wyoming": "懷俄明",
    "US\\\\bend": "本德",
    "US\\\\latham": "拉瑟姆",
    "CA\\\\montreal": "蒙特婁",
    "CA\\\\ontario": "安大略",
    "CA\\\\toronto": "多倫多",
    "CA\\\\vancouver": "溫哥華",
    "AU\\\\adelaide": "阿德雷德",
    "AU\\\\brisbane": "布里斯本",
    "AU\\\\melbourne": "墨爾本",
    "AU\\\\perth": "伯斯",
    "AU\\\\sydney": "雪梨",
    "JP\\tokyo": "東京",
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


def country_label(country_code: str) -> str:
    cc = country_code.upper()
    return COUNTRY_ZH.get(cc, cc)


def location_label(path: str) -> str:
    normalized = path.replace("/", "\\")
    cc = normalized.split("\\", 1)[0].upper()
    country = country_label(cc)
    city = LOCATION_ZH.get(normalized)
    return f"{country}-{city}" if city else country


def vendor_location_name(vendor: str, path: str) -> str:
    normalized = path.replace("/", "\\")
    cc = normalized.split("\\", 1)[0].upper()
    flag_cc = "GB" if cc == "UK" else cc
    return f"{alpha2_flag(flag_cc)} {vendor}-{cc}({location_label(normalized)})"


def location_catalog() -> dict[str, str]:
    result = dict(COUNTRY_ZH)
    result.update({path: location_label(path) for path in LOCATION_ZH})
    return result


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


def _prune_empty_parent(path: Path, stop: Path) -> None:
    current = path
    while current != stop:
        try:
            current.rmdir()
        except OSError:
            break
        current = current.parent


def clear_generated_payloads(providers_root: Path, filename: str) -> list[Path]:
    """Remove exact managed payloads and directories made empty by those removals."""
    if not providers_root.is_dir():
        return []

    removed: list[Path] = []
    parents: list[Path] = []
    for path in providers_root.rglob(filename):
        parents.append(path.parent)
        path.unlink()
        removed.append(path)
        print(f"[REMOVE] {path}")

    for parent in sorted(set(parents), key=lambda p: len(p.parts), reverse=True):
        _prune_empty_parent(parent, providers_root)
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
    """Replace one explicitly marked generated JS array in the checked-out override."""
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
    lines.extend(["];", end_marker])
    block = "\n".join(lines)

    end += len(end_marker)
    updated = text[:start] + block + text[end:]
    if updated != text:
        path.write_text(updated, encoding="utf-8", newline="\n")
        print(f"[WRITE] {path} ({const_name} synced)")
    else:
        print(f"[OK] {path} ({const_name} unchanged)")
    return True


def sync_override_location_catalog(
    *,
    generator: str,
    override_path: Path | None = None,
) -> bool:
    path = override_path or source_override_path()
    if path is None:
        return False
    start_marker = "// BEGIN GENERATED VPN LOCATION LABELS"
    end_marker = "// END GENERATED VPN LOCATION LABELS"
    text = path.read_text(encoding="utf-8")
    start = text.find(start_marker)
    end = text.find(end_marker)
    if start < 0 or end < 0 or end < start:
        raise RuntimeError(f"{path}: 找不到 generated block：VPN LOCATION LABELS")
    rendered = json.dumps(location_catalog(), ensure_ascii=False, indent=2, sort_keys=True)
    block = "\\n".join([
        start_marker,
        "// AUTO-GENERATED from the shared VPN generator location catalog.",
        f"// Do not edit this block by hand; regenerate it with {generator}.",
        f"const VPN_LOCATION_LABELS = {rendered};",
        end_marker,
    ])
    end += len(end_marker)
    updated = text[:start] + block + text[end:]
    if updated != text:
        path.write_text(updated, encoding="utf-8", newline="\\n")
        print(f"[WRITE] {path} (VPN_LOCATION_LABELS synced)")
    else:
        print(f"[OK] {path} (VPN_LOCATION_LABELS unchanged)")
    return True
