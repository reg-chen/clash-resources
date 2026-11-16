#!/usr/bin/env python3
"""Activate category MRS containing local custom domains; leave port rules separate."""
from __future__ import annotations

import json
import pathlib
import re

from mrs_merge import CUSTOM_SOURCES

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCES = json.loads((ROOT / "tools/third-party-mrs-sources.json").read_text())
CATEGORIES = ("security", "privacy", "ads")
CONFIGS = (
    "configs/desktop.yaml",
    "configs/android-firewall-only.yaml",
    # iOS already has no sub-rules and deliberately uses a reduced rule set.
    "configs/windows-firewall-only.yaml",
)


def category_name(name: str) -> str:
    return name.split("-", 1)[0]


def merged_path(category: str) -> pathlib.Path:
    return ROOT / "rules" / category / "mrs" / "combined.mrs"


def replacement_path(name: str, category: str, section: str) -> str:
    match = re.search(
        rf"(?m)^  {re.escape(name)}:\n((?:    [^\n]*\n)*)", section
    )
    if not match:
        raise ValueError(f"Missing source rule provider {name}")
    path_match = re.search(r"(?m)^    path:\s*(.+)$", match.group(1))
    if not path_match:
        raise ValueError(f"Missing source path: {name}")
    value = path_match.group(1).strip()
    quote = value[:1] if value.startswith(("'", '"')) else ""
    raw = value.strip("'\"")
    # Use the same base prefix and separator as existing per-platform rules.
    if "\\\\" in raw:
        sep = "\\\\"
    elif "\\" in raw:
        sep = "\\"
    else:
        sep = "/"
    normalized = raw.replace("\\\\", "/").replace("\\", "/")
    marker = "rules/"
    idx = normalized.find(marker)
    if idx < 0:
        raise ValueError(f"Source path is not under rules/: {raw}")
    prefix = normalized[:idx]
    new_path = (prefix + f"rules/{category}/mrs/combined.mrs").replace("/", sep)
    return quote + new_path + quote


def _source_groups(sources: list[dict]) -> dict[str, list[str]]:
    merged_sources = [*sources, *CUSTOM_SOURCES]
    groups = {
        category: [item["name"] for item in merged_sources if category_name(item["name"]) == category]
        for category in CATEGORIES
    }
    if any(not names for names in groups.values()):
        raise ValueError("Incomplete MRS source categories")
    return groups


def _flatten_sub_rules(sub_section: str, rule_section: str, groups: dict[str, list[str]]) -> str:
    """Replace each SUB-RULE invocation with ordered, direct RULE-SET entries."""
    section_headers = list(re.finditer(r"(?m)^  (SECURITY|PRIVACY-NATIVE|ADS):\s*$", sub_section))
    if len(section_headers) != 3:
        raise ValueError("Expected three legacy sub-rule groups")
    names_to_category = {
        "SECURITY": "security", "PRIVACY-NATIVE": "privacy", "ADS": "ads"
    }
    replacements: dict[str, list[str]] = {}
    for i, header in enumerate(section_headers):
        name = header.group(1)
        end = section_headers[i + 1].start() if i + 1 < len(section_headers) else len(sub_section)
        contents = sub_section[header.end():end]
        entries = []
        for line in contents.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            matched = re.fullmatch(r"- RULE-SET,([\w-]+),REJECT(?:,.*)?", stripped)
            if not matched:
                raise ValueError(f"Unsupported legacy sub-rule: {stripped}")
            entries.append(stripped)
        if not entries:
            raise ValueError(f"Empty legacy sub-rule: {name}")
        category = names_to_category[name]
        sources = set(groups[category])
        found = {line.split(",")[1] for line in entries if line.split(",")[1] in sources}
        if found != sources:
            raise ValueError(f"Missing {category} source sub-rules: {sorted(sources - found)}")
        flattened = []
        inserted = False
        for line in entries:
            rule_name = line.split(",")[1]
            if rule_name in sources:
                if not inserted:
                    flattened.append(f"- RULE-SET,{category}-combined,REJECT")
                    inserted = True
            else:
                if rule_name == "network-ports":
                    flattened.append("# Network port restrictions (classical)")
                flattened.append(line)
        replacements[name] = flattened

    # Match both normal YAML list indentation and Android's indentless lists.
    pattern = re.compile(
        r"(?m)^(?P<indent>[ \t]*)-[ \t]+SUB-RULE,"
        r"\(SRC-IP-CIDR,0\.0\.0\.0/0\),(?P<name>SECURITY|PRIVACY-NATIVE|ADS)\s*$"
    )
    occurrences: dict[str, int] = {}
    def expand(match: re.Match[str]) -> str:
        name = match.group("name")
        occurrences[name] = occurrences.get(name, 0) + 1
        indent = match.group("indent")
        return "\n".join(indent + rule for rule in replacements[name])

    rewritten = pattern.sub(expand, rule_section)
    if occurrences != {"SECURITY": 1, "PRIVACY-NATIVE": 1, "ADS": 1}:
        raise ValueError(f"Unexpected SUB-RULE occurrence counts: {occurrences}")
    if "SUB-RULE," in rewritten:
        raise ValueError("Unknown SUB-RULE remains; refusing to remove its definition")
    return rewritten


def rewrite_config(text: str, sources: list[dict]) -> str:
    groups = _source_groups(sources)
    provider_start = text.index("rule-providers:\n")
    sub_start = text.index("\nsub-rules:", provider_start)
    rules_start = text.index("\nrules:", sub_start)
    providers = text[provider_start:sub_start]
    legacy_sub = text[sub_start + 1:rules_start]
    tail = text[rules_start + 1:]

    original_paths = {
        category: replacement_path(names[0], category, providers)
        for category, names in groups.items()
    }

    # Validate and flatten every sub-rule before touching any provider.
    flattened_tail = _flatten_sub_rules(legacy_sub, tail, groups)

    for category, names in groups.items():
        for name in names:
            # Remove only sources merged into this category. Keep non-domain
            # network-ports and other classical providers independent.
            pattern = re.compile(
                rf"(?m)(?:^  # [^\n]*\n){{0,5}}^  {re.escape(name)}:\n"
                r"(?:^    [^\n]*\n)+"
            )
            providers, count = pattern.subn("", providers)
            if count != 1:
                raise ValueError(f"Expected one provider declaration for {name}, found {count}")

    merged_providers = ""
    for category in CATEGORIES:
        merged_providers += (
            f"  {category}-combined:\n"
            "    <<: *RULE-PROVIDER\n"
            "    type: http\n"
            "    behavior: domain\n"
            "    format: mrs\n"
            f"    url: https://rules.reginald.win/{category}/mrs/combined.mrs\n"
            f"    path: {original_paths[category]}\n\n"
        )
    providers = providers.replace(
        "rule-providers:\n", "rule-providers:\n" + merged_providers, 1
    )
    return text[:provider_start] + providers + "\n" + flattened_tail


def remove_custom_from_activated(text: str) -> str:
    """Upgrade an already combined YAML that still loads custom TXT separately."""
    if "sub-rules:" in text or "SUB-RULE," in text:
        raise ValueError("Legacy sub-rules remain in a combined profile")
    if any(f"  {category}-combined:\n" not in text for category in CATEGORIES):
        raise ValueError("Missing category-combined rule provider")
    if all(f"RULE-SET,{category}-custom,REJECT" not in text for category in CATEGORIES):
        return text

    providers_start = text.index("rule-providers:\n")
    rules_start = text.index("\nrules:", providers_start)
    providers = text[providers_start:rules_start]
    tail = text[rules_start:]
    for category in CATEGORIES:
        name = f"{category}-custom"
        provider_match = re.compile(
            rf"(?m)(?:^  # [^\n]*\n){{0,5}}^  {name}:\n(?:^    [^\n]*\n)+"
        )
        providers, count = provider_match.subn("", providers)
        if count != 1:
            raise ValueError(f"Missing active custom provider {name}")
        pattern = re.compile(rf"(?m)^[ \t]*- RULE-SET,{name},REJECT[^\n]*\n")
        tail, count = pattern.subn("", tail)
        if count != 1:
            raise ValueError(f"Missing active custom rule {name}")
        if tail.count(f"RULE-SET,{category}-combined,REJECT") != 1:
            raise ValueError(f"Missing active {category} merged rule")
    return text[:providers_start] + providers + tail


def main() -> None:
    for category in CATEGORIES:
        target = merged_path(category)
        if not target.is_file() or target.stat().st_size < 8:
            raise RuntimeError(f"Combined {category} MRS missing; leaving YAML unchanged: {target}")
    modified = []
    for rel in CONFIGS:
        file = ROOT / rel
        original = file.read_text(encoding="utf-8")
        # Skip once migrated; the source set may still update independently.
        if all(f"  {category}-combined:\n" in original for category in CATEGORIES):
            if "sub-rules:" in original or "SUB-RULE," in original:
                raise ValueError(f"Partially migrated configuration: {rel}")
            updated = remove_custom_from_activated(original)
        else:
            updated = rewrite_config(original, SOURCES)
        if updated != original:
            modified.append((file, updated))
    # Validate all configs before touching any of them.
    for file, updated in modified:
        file.write_text(updated, encoding="utf-8")
        print(f"COMBINED_CONFIG {file.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
