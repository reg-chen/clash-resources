"""Strict, category-scoped domain union builder for Mihomo MRS.

Never merge ads/privacy/security with one another. Fail rather than silently drop
source rules whose semantics cannot be represented as Mihomo domain text.
"""
from __future__ import annotations

import ipaddress
import json
import re
import subprocess
from pathlib import Path

CATEGORIES = ("security", "privacy", "ads")
CUSTOM_SOURCES = tuple(
    {"name": f"{category}-custom", "path": f"rules/{category}/custom.txt"}
    for category in CATEGORIES
)
def normalized_domain(raw: str) -> str:
    value = raw.strip().rstrip(".").lower()
    # Keep upstream tokens as-is apart from case and a terminal DNS root dot.
    # The native Mihomo converter, not Python IDNA hostname checks, owns
    # source validity (including numeric labels, underscores and IDNs).
    # Domain-behavior rulesets are not restricted to RFC hostname labels.
    # Preserve upstream IP-looking values and underscores as literal domain
    # tokens; the Mihomo converter will validate the native domain syntax.
    # These are NOT converted into IP-CIDR matches.
    if (
        not value
        or any(ch.isspace() or ord(ch) < 32 for ch in value)
        or any(ch in ",;/\\#<>?=&@:%|()[]" for ch in value)
    ):
        raise ValueError(f"Invalid domain token: {raw!r}")
    return value


def parse_domain_rules(
    raw: bytes,
    source_format: str,
    *,
    allow_empty: bool = False,
    skipped_invalid: list[tuple[int, str]] | None = None,
) -> set[str]:
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
        # Full URLs in third-party phishing feeds cannot be represented as
        # path-specific rules in a domain MRS. Audit/skip unsupported entries,
        # never silently turn a path-specific URL into a whole-host block.
        try:
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
        except ValueError:
            if skipped_invalid is None or source_format != "text":
                raise
            # Avoid writing complete phishing URLs (which can carry tokens,
            # email addresses or other PII in query strings) to public CI logs.
            reason = "URL/path entry" if "://" in original or "/" in original else "non-domain token"
            skipped_invalid.append((row, reason))
            continue
        result.add(line)
    if not result and not allow_empty:
        raise ValueError("Empty parsed domain rules")
    return result


def parse_metamask_domains(raw: bytes, *, skipped_invalid: list[tuple[int, str]]) -> set[str]:
    """Extract explicit host blocks only; never promote a URL or fuzzy match."""
    config = json.loads(raw.decode("utf-8-sig"))
    if not isinstance(config, dict):
        raise ValueError("Invalid MetaMask config object")

    def entries(*keys):
        found = [key for key in keys if key in config]
        if len(found) != 1:
            raise ValueError(f"Expected exactly one MetaMask field from {keys}")
        values = config[found[0]]
        if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
            raise ValueError(f"Invalid MetaMask {found[0]} array")
        return values

    host_pattern = re.compile(
        r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    )

    def host(value, *, allow=False):
        value = normalized_domain(value)
        # Never map a Unicode block to a different ASCII hostname via IDNA2003.
        # For exceptions, IDNA mapping only reduces the number of blocks.
        if allow and not value.isascii():
            value = value.encode("idna").decode("ascii")
        if len(value) > 253 or not host_pattern.fullmatch(value):
            raise ValueError("Not a plain DNS hostname")
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return value
        raise ValueError("IP address is not a domain rule")

    block = entries("blacklist", "blocklist")
    allowed = set()
    for value in entries("whitelist", "allowlist"):
        # Refuse to publish if an exception cannot be interpreted safely.
        allowed.add(host(value, allow=True))
    result = set()
    for index, value in enumerate(block, 1):
        try:
            domain = host(value)
        except ValueError:
            skipped_invalid.append((index, "non-domain token"))
            continue
        labels = domain.split(".")
        if any(".".join(labels[i:]) in allowed for i in range(len(labels))):
            continue
        # Exact domains only: a domain suffix would expand the blocking scope
        # and may override a legitimate subdomain present in the allowlist.
        result.add(domain)
    if not result:
        raise ValueError("Empty MetaMask explicit domain blocklist")
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
