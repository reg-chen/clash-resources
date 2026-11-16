"""Strict, category-scoped domain union builder for Mihomo MRS.

Never merge ads/privacy/security with one another. Fail rather than silently drop
source rules whose semantics cannot be represented as Mihomo domain text.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

CATEGORIES = ("security", "privacy", "ads")
CUSTOM_SOURCES = tuple(
    {"name": f"{category}-custom", "path": f"rules/{category}/custom.txt"}
    for category in CATEGORIES
)
def normalized_domain(raw: str) -> str:
    value = raw.strip().rstrip(".").lower()
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"Invalid domain: {raw!r}") from exc
    # Domain-behavior rulesets are not restricted to RFC hostname labels.
    # Preserve upstream IP-looking values and underscores as literal domain
    # tokens; the Mihomo converter will validate the native domain syntax.
    # These are NOT converted into IP-CIDR matches.
    if (
        not value
        or any(ch.isspace() or ord(ch) < 32 for ch in value)
        or any(ch in ",;/\\#<>" for ch in value)
    ):
        raise ValueError(f"Invalid domain token: {raw!r}")
    return value


def parse_domain_rules(raw: bytes, source_format: str, *, allow_empty: bool = False) -> set[str]:
    """Keep exact domains and suffix/wildcard domains distinct."""
    if source_format not in ("text", "yaml"):
        raise ValueError(f"Cannot merge {source_format!r} directly")
    result: set[str] = set()
    for row, original in enumerate(raw.decode("utf-8-sig").splitlines(), 1):
        line = original.strip()
        if not line or line.startswith(("#", "//", ";", "!")):
            continue
        if source_format == "yaml":
            if line == "payload:":
                continue
            if not line.startswith("- "):
                raise ValueError(f"Unrecognized YAML rule at line {row}: {line[:100]!r}")
            line = line[2:].strip()
        line = line.strip("'\"").strip()
        # Clash DOMAIN and DOMAIN-SUFFIX are mapped to the canonical Mihomo
        # text representation, preserving the distinction.
        if "," in line:
            kind, domain, *_ = line.split(",")
            kind = kind.strip().upper()
            if kind == "DOMAIN":
                line = normalized_domain(domain)
            elif kind == "DOMAIN-SUFFIX":
                line = "+." + normalized_domain(domain)
            else:
                raise ValueError(f"Unsupported domain rule at line {row}: {kind}")
        elif line.startswith(("+.", "*.")):
            line = line[:2] + normalized_domain(line[2:])
        else:
            line = normalized_domain(line)
        result.add(line)
    if not result and not allow_empty:
        raise ValueError("Empty parsed domain rules")
    return result


def grouped_sources(entries: list[dict], source_rules: dict[str, set[str]]) -> dict[str, set[str]]:
    by_category: dict[str, set[str]] = {category: set() for category in CATEGORIES}
    for item in entries:
        category = item["name"].split("-", 1)[0]
        if category not in by_category:
            raise ValueError(f"Unknown MRS category: {category}")
        if item["name"] not in source_rules:
            raise ValueError(f"Missing parsed rules for: {item['name']}")
        by_category[category].update(source_rules[item["name"]])
    for category, rules in by_category.items():
        if not rules:
            raise ValueError(f"Empty category: {category}")
    return by_category


def build_merged_mrs(
    root: Path,
    entries: list[dict],
    source_rules: dict[str, set[str]],
    mihomo_executable: str = "./mihomo",
) -> list[Path]:
    """Build all category artifacts first, and replace targets only on success."""
    groups = grouped_sources(entries, source_rules)
    candidates: list[tuple[Path, Path]] = []
    try:
        for category in CATEGORIES:
            target = root / "rules" / category / "mrs" / "combined.mrs"
            target.parent.mkdir(parents=True, exist_ok=True)
            source = target.with_suffix(".source.tmp")
            temporary = target.with_suffix(".mrs.tmp")
            source.write_text("\n".join(sorted(groups[category])) + "\n", encoding="utf-8")
            candidates.append((source, temporary))
            subprocess.run(
                [mihomo_executable, "convert-ruleset", "domain", "text",
                 str(source), str(temporary)], check=True
            )
            if not temporary.is_file() or temporary.stat().st_size < 8:
                raise RuntimeError(f"Missing combined {category} MRS")
        targets = []
        for category, (source, temporary) in zip(CATEGORIES, candidates):
            target = root / "rules" / category / "mrs" / "combined.mrs"
            temporary.replace(target)
            targets.append(target)
        return targets
    finally:
        for source, temporary in candidates:
            source.unlink(missing_ok=True)
            temporary.unlink(missing_ok=True)
