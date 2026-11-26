#!/usr/bin/env python3
"""Build combined domain MRS and explicitly requested standalone providers."""
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import urllib.request

from mrs_ip import FEODO_URL, IP_TARGET, parse_ip_rules, build_ip_mrs
from mrs_overlap import parse_domain_keys, write_report
from mrs_merge import CUSTOM_SOURCES, parse_domain_rules, parse_metamask_rules, build_merged_mrs
from mrs_provenance import pin_source_url, save_source_snapshot, verify_source_snapshots, commit_page

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCES = json.loads((ROOT / "tools/third-party-mrs-sources.json").read_text())
STATE = ROOT / "tools/third-party-mrs-sha256.json"
old = json.loads(STATE.read_text()) if STATE.exists() else {}
new = {}
PROVENANCE = ROOT / "tools/third-party-mrs-provenance.json"
previous = json.loads(PROVENANCE.read_text()) if PROVENANCE.exists() else {}
previous_inputs = {v["name"]: v for v in previous.get("inputs", []) if isinstance(v, dict) and "name" in v}
provenance_inputs = []
revision_cache = {}
changed = []
overlap_sets = {}
overlap_notes = []
merge_sets = {}
ip_rules = set()
ip_overlap_sets = {}
ip_excluded_counts = {}
skipped_details = []

for item in SOURCES:
    url = item["source"]
    is_ip = item.get("behavior") == "ipcidr"
    is_mixed = item.get("behavior") == "domain-ipcidr"
    live = item.get("source_type") == "live"
    if live:
        if not is_ip or url != FEODO_URL:
            raise ValueError("Unsupported live MRS source: " + url)
        pinned_url, commit_sha = url, None
    else:
        pinned_url, commit_sha = pin_source_url(url, revision_cache)
    req = urllib.request.Request(pinned_url, headers={"User-Agent": "clash-resources-mrs-builder/1.0", "Cache-Control": "no-cache"})
    try:
        with urllib.request.urlopen(req, timeout=90) as res:
            raw = res.read()
    except Exception as exc:
        raise RuntimeError(f"Upstream download failed for {item['name']}: {exc}") from exc
    if not raw or len(raw) < 10:
        raise RuntimeError(f"Empty or suspicious source: {item['name']}")
    digest = hashlib.sha256(raw).hexdigest()
    archived = save_source_snapshot(ROOT, item["name"], item["format"], raw)
    archive_rel = archived.relative_to(ROOT).as_posix()
    category = item["name"].split("-", 1)[0]
    output_paths = [IP_TARGET if is_ip else f"rules/{category}/mrs/combined.mrs"]
    if is_mixed:
        output_paths.append(IP_TARGET)
    if item.get("target"):
        output_paths.append(item["target"])
    record = {
        "name": item["name"], "output_paths": sorted(output_paths), "format": item["format"],
        "source_url": url, "source_commit_sha": commit_sha,
        "pinned_source_url": pinned_url,
        "source_sha256": digest, "source_size_bytes": len(raw),
        "source_snapshot_path": archive_rel,
        "source_commit_url": None if live else commit_page(url, commit_sha),
    }
    if live:
        # No immutable upstream revision exists. Archive exact response bytes;
        # the digest and the repository commit identify the downloaded version.
        record["source_type"] = "live"
        record["pinned_source_url"] = None
    old_record = previous_inputs.get(item["name"], {})
    # Avoid a new provenance commit when a branch advances but its file bytes
    # have not changed. The older immutable URL still points at those bytes.
    if (not live and all(old_record.get(k) == record[k] for k in
            ("name", "format", "source_url", "source_sha256", "source_size_bytes"))
            and old_record.get("pinned_source_url") and old_record.get("source_commit_sha")
            and old_record.get("source_snapshot_path") == archive_rel
            and old_record.get("source_commit_url")):
        # Preserve immutable source identity even when publication paths change.
        for key in ("pinned_source_url", "source_commit_sha", "source_commit_url"):
            record[key] = old_record[key]
    provenance_inputs.append(record)
    new[item["name"]] = digest
    if is_ip:
        values, excluded = parse_ip_rules(raw, feodo=live)
        print(f"IP {item['name']}: {len(values):,} public IPv4; excluded {len(excluded)} non-global")
        if excluded:
            skipped_details.append(f"{item['name']}: excluded {len(excluded)} non-global IPv4: " + ", ".join(excluded[:5]))
        ip_overlap_sets[item["name"]] = values
        ip_excluded_counts[item["name"]] = len(excluded)
        ip_rules.update(values)
        continue
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
                    f"{item['name']}: 使用官方編譯 MRS 的原始 YAML；"
                    "線上 MRS 與 YAML 發布時間可能不同。"
                )
            except Exception as exc:
                overlap_notes.append(f"{item['name']}: 比對來源下載失敗（{type(exc).__name__}）；已略過。")
                analysis_raw = b""
        else:
            analysis_raw = b""
            overlap_notes.append(f"{item['name']}: 二進位 MRS 無可比對的文字來源；已略過。")
    if analysis_raw and analysis_fmt == "json":
        if item["name"] != "security-metamask" or not is_mixed or item.get("target"):
            raise ValueError("Unsupported JSON MRS source")
        skipped = []
        values, addresses, excluded = parse_metamask_rules(analysis_raw, skipped_invalid=skipped)
        merge_sets[item["name"]] = values
        overlap_sets[item["name"]] = values
        ip_overlap_sets[item["name"]] = addresses
        ip_excluded_counts[item["name"]] = len(excluded)
        ip_rules.update(addresses)
        overlap_notes.append("security-metamask: 網域與公網 IPv4 分開統計；各自套用來源自身 allowlist，不納入 fuzzylist。IPv4 排除數包含允許清單及非公網位址。")
        if skipped:
            skipped_details.append(f"{item['name']}: skipped {len(skipped):,} unsupported entries (including IPv6)")
        if excluded:
            skipped_details.append(f"{item['name']}: excluded {len(excluded):,} allowlisted/non-global IPv4")
        print(f"JSON {item['name']}: {len(values):,} explicit domains; {len(addresses):,} public IPv4; "
              f"excluded {len(excluded):,} IPv4; skipped {len(skipped):,} unsupported entries")
    elif analysis_raw:
        parsed = parse_domain_keys(analysis_raw, analysis_fmt)
        if parsed:
            overlap_sets[item["name"]] = parsed
        else:
            overlap_notes.append(f"{item['name']}: 未解析出可比較的網域鍵；已略過。")
        # Strict parser: source formats that cannot be represented losslessly
        # in one domain MRS stop the build before YAML is migrated.
        skipped = []
        merge_sets[item["name"]] = parse_domain_rules(
            analysis_raw, analysis_fmt,
            skipped_invalid=skipped if analysis_fmt == "text" else None,
        )
        if skipped:
            total = len(merge_sets[item["name"]]) + len(skipped)
            details = "; ".join(f"line {n}: {value[:100]}" for n, value in skipped[:3])
            message = (f"{item['name']}: skipped {len(skipped):,}/{total:,} "
                       f"non-domain entries; examples: {details}")
            skipped_details.append(message)
            print(f"WARNING: {message}", file=sys.stderr)

    # All inputs feed their category union. Only an explicitly configured
    # target is separately compiled/published (currently anti-AD for iOS).
    if not item.get("target"):
        print(f"MERGE_ONLY {item['name']}")
        continue
    target = ROOT / item["target"]
    if old.get(item["name"]) == digest and target.is_file() and target.stat().st_size:
        print(f"UNCHANGED {item['name']}")
        continue
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_suffix(".mrs.tmp")
    try:
        if item["format"] == "mrs":
            # Upstream already publishes MRS: mirror bytes, do not reconvert.
            if len(raw) < 512 or raw.lstrip().lower().startswith((b"<html", b"<!doctype", b"error:")):
                raise RuntimeError(f"Invalid upstream MRS response: {item['name']}")
            temp.write_bytes(raw)
        else:
            # Read the exact archived bytes, not an independently re-fetched URL.
            subprocess.run(["./mihomo", "convert-ruleset", "domain", item["format"], str(archived), str(temp)], check=True)
        if not temp.is_file() or temp.stat().st_size < 8:
            raise RuntimeError(f"No MRS output: {item['name']}")
        os.replace(temp, target)
        changed.append(item["target"])
        print(f"BUILT {item['name']} {target} {target.stat().st_size} bytes")
    finally:
        temp.unlink(missing_ok=True)

# Merge repository-owned custom domains with their own category. Keep
# manually curated sources as readable TXT for review and later edits.
for item in CUSTOM_SOURCES:
    raw = (ROOT / item["path"]).read_bytes()
    merge_sets[item["name"]] = parse_domain_rules(raw, "text", allow_empty=True)
    overlap_sets[item["name"]] = parse_domain_keys(raw, "text")
    print(f"CUSTOM {item['name']} {len(merge_sets[item['name']])} rules")

# Three separate merged MRS outputs; never mix security/privacy/ads.
# The workflow switches YAML only after all three artifacts exist.
domain_sources = [s for s in SOURCES if s.get("behavior") != "ipcidr"]
outputs = build_merged_mrs(ROOT, [*domain_sources, *CUSTOM_SOURCES], merge_sets)
outputs.append(build_ip_mrs(ROOT, ip_rules))
for output in outputs:
    changed.append(str(output.relative_to(ROOT)))
    print(f"MERGED {output.relative_to(ROOT)} ({output.stat().st_size} bytes)")

# Report dropped non-domain entries. A full URL cannot be converted into
# a path-specific domain rule without potentially overblocking the host.
try:
    skipped_report = pathlib.Path("/tmp/mrs-skipped.md")
    skipped_report.write_text(
        "# 無法合併的非網域來源項目\n\n" +
        ("\n".join("- " + detail for detail in skipped_details)
         if skipped_details else "本次沒有略過非網域項目。") + "\n",
        encoding="utf-8",
    )
except Exception as exc:
    print(f"WARNING: skipped-entry report failed: {exc}", file=sys.stderr)

# Analysis is strictly observational. A failure must never change a valid
# MRS build or block its ordinary state update.
try:
    report_path = pathlib.Path(os.environ.get("MRS_OVERLAP_REPORT", "/tmp/mrs-overlap.md"))
    write_report(overlap_sets, overlap_notes, report_path,
                 ip_sets=ip_overlap_sets, ip_excluded=ip_excluded_counts)
    print(f"OVERLAP_REPORT {report_path}")
except Exception as exc:
    print(f"WARNING: overlap report failed: {exc}", file=sys.stderr)

# All saved inputs must match the *actual* bytes used by the converter.
verify_source_snapshots(ROOT, provenance_inputs)
# Clean up only previous snapshots listed in the old manifest that are no
# longer current. Never touch arbitrary files outside this managed directory.
active_archives = {entry["source_snapshot_path"] for entry in provenance_inputs}
for old_entry in previous_inputs.values():
    old_path = old_entry.get("source_snapshot_path")
    if (isinstance(old_path, str) and old_path not in active_archives
            and old_path.startswith("sources/mrs/")
            and pathlib.PurePosixPath(old_path).parent == pathlib.PurePosixPath("sources/mrs")):
        (ROOT / old_path).unlink(missing_ok=True)
STATE.write_text(json.dumps(new, indent=2, sort_keys=True) + "\n")
# Commit the current source files, manifest and compiled MRS atomically.
paths = sorted({*(s["target"] for s in SOURCES if s.get("target")),
                *(str(output.relative_to(ROOT)) for output in outputs)})
provenance_outputs = [
    {"path": path, "sha256": hashlib.sha256((ROOT / path).read_bytes()).hexdigest(),
     "size_bytes": (ROOT / path).stat().st_size}
    for path in paths
]
PROVENANCE.write_text(json.dumps({
    "schema": 2, "inputs": sorted(provenance_inputs, key=lambda v: v["name"]),
    "outputs": provenance_outputs,
}, indent=2, sort_keys=True) + "\n")
print(f"Updated {len(changed)} providers")
