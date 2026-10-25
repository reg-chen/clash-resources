#!/usr/bin/env python3
"""Switch configured upstream domain providers to local MRS after successful builds."""
import json
import pathlib
import re

root = pathlib.Path(__file__).resolve().parent.parent
items = json.loads((root / "tools/third-party-mrs-sources.json").read_text())
for config in [root / "configs/desktop.yaml", root / "configs/android-firewall-only.yaml", root / "configs/ios-firewall-only.yaml", root / "configs/windows-firewall-only.yaml"]:
    text = config.read_text()
    original = text
    for item in items:
        name = re.escape(item["name"])
        pat = re.compile(r"(?ms)(^  " + name + r":\n)(.*?)(?=^  [\w-]+:\n|^# [=]+|^sub-rules:|^rules:)")
        match = pat.search(text)
        if not match:
            continue
        block = match.group(2)
        old_path = re.search(r"(?m)^(    path:\s*)([^\n]+)$", block)
        old_url = re.search(r"(?m)^(    url:\s*)([^\n]+)$", block)
        if old_path is None or old_url is None:
            raise RuntimeError(f"Incomplete rule provider: {item['name']} in {config}")
        path_val = old_path.group(2).strip()
        quote = '"' if path_val.startswith('"') else ("'" if path_val.startswith("'") else "")
        raw_path = path_val.strip("'\"")
        last_sep = max(raw_path.rfind("/"), raw_path.rfind("\\"))
        prefix = raw_path[:last_sep + 1]
        sep = "\\\\" if "\\\\" in raw_path else "/"
        filename = pathlib.PurePosixPath(item["target"]).name
        already_in_mrs = "/mrs/" in raw_path or "\\mrs\\" in raw_path
        new_path = (prefix if already_in_mrs else prefix + "mrs" + sep) + filename
        new_url = "https://rules.reginald.win/" + item["target"].removeprefix("rules/")
        block = block[:old_url.start(2)] + quote + new_url + quote + block[old_url.end(2):]
        old_path = re.search(r"(?m)^(    path:\s*)([^\n]+)$", block)
        block = block[:old_path.start(2)] + quote + new_path + quote + block[old_path.end(2):]
        if re.search(r"(?m)^    format:\s*", block):
            block = re.sub(r"(?m)^    format:\s*\w+", "    format: mrs", block, count=1)
        else:
            block = block.replace("    behavior: domain\n", "    behavior: domain\n    format: mrs\n", 1)
        text = text[:match.start(2)] + block + text[match.end(2):]
    if text != original:
        config.write_text(text)
        print(f"Updated {config.relative_to(root)}")
