"""Strict IPv4 host-list compiler; no broad networks or non-global addresses."""
import ipaddress
import re
import subprocess
from pathlib import Path

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
IP_TARGET = "rules/security/mrs/combined-ip.mrs"


def parse_ip_rules(raw, *, feodo=False):
    text = raw.decode("utf-8-sig")
    values = set()
    excluded = []
    count = 0
    for line in text.splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        address = ipaddress.IPv4Address(value)
        count += 1
        if not address.is_global or address.is_multicast or address.is_reserved:
            excluded.append(str(address))
            continue
        values.add(f"{address}/32")
    if feodo:
        # A successful empty feed is distinct from HTML, truncation, or errors.
        footer = re.search(r"(?m)^# END (\d+) entries\s*\Z", text)
        if ("abuse.ch Feodo Tracker Botnet C2 IP Blocklist" not in text
                or not footer or int(footer.group(1)) != count):
            raise ValueError("Invalid or incomplete Feodo recommended feed")
    elif not values:
        raise ValueError("No globally routable addresses in IP source")
    return values, excluded


def build_ip_mrs(root, rules, executable="./mihomo"):
    if not rules:
        raise ValueError("Empty combined security IP rules")
    target = Path(root) / IP_TARGET
    target.parent.mkdir(parents=True, exist_ok=True)
    source = target.with_suffix(".source.tmp")
    pending = target.with_suffix(".mrs.tmp")
    try:
        source.write_text("\n".join(sorted(rules, key=lambda x: int(ipaddress.IPv4Interface(x).ip))) + "\n",
                          encoding="utf-8")
        subprocess.run([executable, "convert-ruleset", "ipcidr", "text",
                        str(source), str(pending)], check=True,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if not pending.is_file() or pending.stat().st_size < 8:
            raise RuntimeError("Missing combined IP MRS")
        pending.replace(target)
        return target
    finally:
        source.unlink(missing_ok=True)
        pending.unlink(missing_ok=True)
