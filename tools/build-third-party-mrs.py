#!/usr/bin/env python3
"""Build third-party domain MRS files only when source content changes."""
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import urllib.request

from mrs_overlap import parse_domain_keys, write_report

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCES = json.loads((ROOT / "tools/third-party-mrs-sources.json").read_text())
STATE = ROOT / "tools/third-party-mrs-sha256.json"
old = json.loads(STATE.read_text()) if STATE.exists() else {}
new = dict(old)
changed = []
overlap_sets = {}
overlap_notes = []

for item in SOURCES:
    url = item["source"]
    req = urllib.request.Request(url, headers={"User-Agent": "clash-resources-mrs-builder/1.0", "Cache-Control": "no-cache"})
    try:
        with urllib.request.urlopen(req, timeout=90) as res:
            raw = res.read()
    except Exception as exc:
        raise RuntimeError(f"Upstream download failed for {item['name']}: {exc}") from exc
    if not raw or len(raw) < 10:
        raise RuntimeError(f"Empty or suspicious source: {item['name']}")
    digest = hashlib.sha256(raw).hexdigest()
    # Stats come from the same downloaded source bytes used for this MRS build.
    # Already-compiled MRS has no text representation; a separately fetched
    # canonical plain-domain list is explicitly identified as approximate.
    analysis_raw = raw
    analysis_fmt = item["format"]
    if item["format"] == "mrs":
        if item.get("analysis_source"):
            try:
                analysis_req = urllib.request.Request(
                    item["analysis_source"],
                    headers={"User-Agent": "clash-resources-mrs-overlap/1.0"}
                )
                with urllib.request.urlopen(analysis_req, timeout=90) as res:
                    analysis_raw = res.read()
                analysis_fmt = item.get("analysis_format", "text")
                overlap_notes.append(
                    f"{item['name']}: 以同專案純網域清單作代理資料，"
                    "非直接解析二進位 MRS；可能存在版本／收錄差異。"
                )
            except Exception as exc:
                overlap_notes.append(f"{item['name']}: 比對來源下載失敗（{type(exc).__name__}）；已略過。")
                analysis_raw = b""
        else:
            analysis_raw = b""
            overlap_notes.append(f"{item['name']}: 二進位 MRS 無可比對的文字來源；已略過。")
    if analysis_raw:
        parsed = parse_domain_keys(analysis_raw, analysis_fmt)
        if parsed:
            overlap_sets[item["name"]] = parsed
        else:
            overlap_notes.append(f"{item['name']}: 未解析出可比較的網域鍵；已略過。")
    target = ROOT / item["target"]
    if old.get(item["name"]) == digest and target.is_file() and target.stat().st_size:
        print(f"UNCHANGED {item['name']}")
        continue
    target.parent.mkdir(parents=True, exist_ok=True)
    source = target.with_suffix(".source.tmp")
    temp = target.with_suffix(".mrs.tmp")
    try:
        if item["format"] == "mrs":
            # Upstream already publishes MRS: mirror bytes, do not reconvert.
            if len(raw) < 512 or raw.lstrip().lower().startswith((b"<html", b"<!doctype", b"error:")):
                raise RuntimeError(f"Invalid upstream MRS response: {item['name']}")
            temp.write_bytes(raw)
        else:
            source.write_bytes(raw)
            subprocess.run(["./mihomo", "convert-ruleset", "domain", item["format"], str(source), str(temp)], check=True)
        if not temp.is_file() or temp.stat().st_size < 8:
            raise RuntimeError(f"No MRS output: {item['name']}")
        os.replace(temp, target)
        changed.append(item["target"])
        new[item["name"]] = digest
        print(f"BUILT {item['name']} {target} {target.stat().st_size} bytes")
    finally:
        source.unlink(missing_ok=True)
        temp.unlink(missing_ok=True)

# Analysis is strictly observational. A failure must never change a valid
# MRS build or block its ordinary state update.
try:
    report_path = pathlib.Path(os.environ.get("MRS_OVERLAP_REPORT", "/tmp/mrs-overlap.md"))
    write_report(overlap_sets, overlap_notes, report_path)
    print(f"OVERLAP_REPORT {report_path}")
except Exception as exc:
    print(f"WARNING: overlap report failed: {exc}", file=sys.stderr)

STATE.write_text(json.dumps(new, indent=2, sort_keys=True) + "\n")
print(f"Updated {len(changed)} providers")
