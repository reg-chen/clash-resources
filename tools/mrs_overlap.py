"""Compare source-list domain keys during MRS builds (report-only).

Numbers are lexical domain-key intersections, not effective Mihomo rule coverage.
"""
from __future__ import annotations

import itertools
import re
from collections import defaultdict
from pathlib import Path

_DOMAIN = re.compile(r"(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def parse_domain_keys(raw: bytes, fmt: str) -> set[str]:
    """Parse plain domains and Mihomo/Clash DOMAIN / DOMAIN-SUFFIX lines."""
    result: set[str] = set()
    text = raw.decode("utf-8-sig", errors="replace")
    for original in text.splitlines():
        line = original.strip()
        if not line or line.startswith(("#", "!", "//", ";")) or line == "payload:":
            continue
        if line.startswith("- "):
            line = line[2:].strip()
        line = line.strip(" '\"\t\r")
        if "#" in line:
            line = line.split("#", 1)[0].strip()
        if line.startswith(("DOMAIN,", "DOMAIN-SUFFIX,")):
            parts = line.split(",")
            if len(parts) < 2:
                continue
            line = parts[1].strip()
        elif line.upper().startswith(("DOMAIN-KEYWORD,", "IP-CIDR,", "PROCESS-")):
            continue
        if line.startswith(("+.", "*.")):
            line = line[2:]
        line = line.rstrip(".").lower()
        if _DOMAIN.fullmatch(line):
            result.add(line)
    return result


def section_for(name: str) -> str:
    return name.split("-", 1)[0]


def summarize(domain_sets: dict[str, set[str]]) -> dict[str, list[dict]]:
    grouped: dict[str, dict[str, set[str]]] = defaultdict(dict)
    for name, keys in domain_sets.items():
        grouped[section_for(name)][name] = keys
    result = {}
    for group, members in grouped.items():
        rows = []
        names = sorted(members)
        for name in names:
            own = members[name]
            others = set().union(*(members[n] for n in names if n != name))
            rows.append({
                "name": name,
                "total": len(own),
                "overlap": len(own & others),
                "unique": len(own - others),
            })
        result[group] = rows
    return result


def render(domain_sets: dict[str, set[str]], notes: list[str]) -> str:
    lines = [
        "# MRS 來源交集與差集",
        "",
        "統計單位：來源中可解析的**網域字串**；僅比較完全相同的網域鍵，",
        "不計算 DOMAIN-SUFFIX 的子網域涵蓋，也不代表實際攔截／命中率。",
        "",
    ]
    for group, rows in sorted(summarize(domain_sets).items()):
        members = {k: v for k, v in domain_sets.items() if section_for(k) == group}
        union_size = len(set().union(*members.values())) if members else 0
        lines += [
            f"## {group.upper()}（聯集 {union_size:,}）",
            "",
            "| 來源 | 網域鍵 | 與同組其他來源重疊 | 同組獨有 |",
            "|---|---:|---:|---:|",
        ]
        for row in rows:
            lines.append(
                f"| {row['name']} | {row['total']:,} | {row['overlap']:,} | {row['unique']:,} |"
            )
        if group == "ads":
            lines.extend(["", "同組廣告來源兩兩交集：", "", "| 來源 A | 來源 B | 相同網域鍵 |", "|---|---|---:|"])
            for a, b in itertools.combinations(sorted(members), 2):
                lines.append(f"| {a} | {b} | {len(members[a] & members[b]):,} |")
        lines.append("")
    if notes:
        lines.extend(["## 來源備註", ""])
        lines.extend(f"- {note}" for note in notes)
        lines.append("")
    return "\n".join(lines)


def write_report(domain_sets: dict[str, set[str]], notes: list[str], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render(domain_sets, notes), encoding="utf-8")
