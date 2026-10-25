#!/usr/bin/env python3
"""Build third-party domain MRS files only when source content changes."""
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCES = json.loads((ROOT / "tools/third-party-mrs-sources.json").read_text())
STATE = ROOT / "tools/third-party-mrs-sha256.json"
old = json.loads(STATE.read_text()) if STATE.exists() else {}
new = dict(old)
changed = []

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
    target = ROOT / item["target"]
    if old.get(item["name"]) == digest and target.is_file() and target.stat().st_size:
        print(f"UNCHANGED {item['name']}")
        continue
    target.parent.mkdir(parents=True, exist_ok=True)
    source = target.with_suffix(".source.tmp")
    temp = target.with_suffix(".mrs.tmp")
    try:
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

STATE.write_text(json.dumps(new, indent=2, sort_keys=True) + "\n")
print(f"Updated {len(changed)} providers")
