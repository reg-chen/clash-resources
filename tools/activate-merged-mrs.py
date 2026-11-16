#!/usr/bin/env python3
"""Switch configs to category-combined MRS only after all merged files exist.

Keeps custom rules and classical security-riskport untouched.
"""
from __future__ import annotations

import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCES = json.loads((ROOT / "tools/third-party-mrs-sources.json").read_text())
CATEGORIES = ("security", "privacy", "ads")
CONFIGS = (
    "configs/desktop.yaml",
    "configs/android-firewall-only.yaml",
    "configs/ios-firewall-only.yaml",
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


def rewrite_config(text: str, sources: list[dict]) -> str:
    start = text.index("rule-providers:\n")
    end = text.index("\nsub-rules:", start)
    section = text[start:end]
    by_category = {
        category: [item["name"] for item in sources if category_name(item["name"]) == category]
        for category in CATEGORIES
    }
    if any(not names for names in by_category.values()):
        raise ValueError("Incomplete MRS source categories")
    original_paths = {
        category: replacement_path(names[0], category, section)
        for category, names in by_category.items()
    }
    # Sub-rules can contain additional bespoke entries. Replace only named
    # third-party references, leaving security-custom / riskport untouched.
    tail = text[end:]
    for category, names in by_category.items():
        anchor_found = False
        for name in names:
            pattern = re.compile(rf"(?m)^(\s+- RULE-SET,){re.escape(name)}(,REJECT[^\n]*)\n")
            matches = list(pattern.finditer(tail))
            if len(matches) != 1:
                raise ValueError(f"Expected one sub-rule for {name}, found {len(matches)}")
            if not anchor_found:
                tail = pattern.sub(rf"\g<1>{category}-combined\g<2>\n", tail, count=1)
                anchor_found = True
            else:
                tail = pattern.sub("", tail, count=1)

    new_section = section
    for category, names in by_category.items():
        for name in names:
            # The optional local comment header is removed together with
            # the provider. Other custom provider blocks remain untouched.
            pattern = re.compile(
                rf"(?m)(?:^  # [^\n]*\n){{0,5}}^  {re.escape(name)}:\n"
                r"(?:^    [^\n]*\n)+"
            )
            new_section, count = pattern.subn("", new_section)
            if count != 1:
                raise ValueError(f"Expected one provider declaration for {name}, found {count}")
    header = ""
    for category in CATEGORIES:
        header += (
            f"  {category}-combined:\n"
            "    <<: *RULE-PROVIDER\n"
            "    type: http\n"
            "    behavior: domain\n"
            "    format: mrs\n"
            f"    url: https://rules.reginald.win/{category}/mrs/combined.mrs\n"
            f"    path: {original_paths[category]}\n"
            "\n"
        )
    new_section = new_section.replace("rule-providers:\n", "rule-providers:\n" + header, 1)
    return text[:start] + new_section + tail


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
            continue
        updated = rewrite_config(original, SOURCES)
        modified.append((file, updated))
    # Validate all configs before touching any of them.
    for file, updated in modified:
        file.write_text(updated, encoding="utf-8")
        print(f"COMBINED_CONFIG {file.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
