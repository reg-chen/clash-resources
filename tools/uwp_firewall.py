"""Windows UWP Package firewall rule export and idempotent import."""
from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

SID_PATTERN = re.compile(r"^S-1-15-2-(?:\d+-)*\d+$")


def bundled_script() -> Path:
    root = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    script = root / "uwp_firewall.ps1"
    if not script.is_file():
        raise FileNotFoundError(f"找不到 UWP 防火牆備份程式：{script}")
    return script


def inspect_backup(path: Path) -> dict[str, int]:
    """Validate basic JSON format before privileged import; never evaluate content."""
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict) or data.get("Schema") != 1 or data.get("Type") != "PersistentStore-UWP-PackageRules":
        raise ValueError("不是支援的 UWP 防火牆備份。")
    rules = data.get("Rules")
    if not isinstance(rules, list) or len(rules) > 50000:
        raise ValueError("備份內容無效或規則數量異常。")
    counts = {"total": len(rules), "allow": 0, "block": 0}
    for rule in rules:
        if not isinstance(rule, dict) or not SID_PATTERN.fullmatch(str(rule.get("PackageSID", ""))):
            raise ValueError("備份包含無效的 Package SID。")
        if rule.get("Direction") not in ("Inbound", "Outbound") or rule.get("Action") not in ("Allow", "Block"):
            raise ValueError("備份包含不支援的規則方向或動作。")
        counts[rule["Action"].lower()] += 1
    return counts


def _quote_ps(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _run(mode: str, target: Path, *, elevated: bool) -> dict:
    if sys.platform != "win32":
        raise RuntimeError("此功能僅支援 Windows。")
    if mode not in ("backup", "restore"):
        raise ValueError("不支援的操作。")
    script = bundled_script()
    target = target.expanduser().absolute()
    with tempfile.TemporaryDirectory(prefix="vpn-mihomo-uwp-") as temp:
        report = Path(temp) / "report.json"
        args = [
            "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", str(script), "-Mode", mode, "-Path", str(target),
            "-Report", str(report),
        ]
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        if elevated:
            argline = subprocess.list2cmdline(args)
            outer = (
                "$p = Start-Process -FilePath 'powershell.exe' "
                f"-ArgumentList {_quote_ps(argline)} -Verb RunAs -Wait -PassThru; "
                "exit $p.ExitCode"
            )
            encoded = base64.b64encode(outer.encode("utf-16-le")).decode("ascii")
            command = ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded]
        else:
            command = ["powershell.exe", *args]
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=300,
            creationflags=flags,
        )
        if not report.is_file():
            error = (result.stderr or result.stdout or "未產生執行報告").strip()
            raise RuntimeError(f"Windows 防火牆操作未完成：{error[-650:]}")
        summary = json.loads(report.read_text(encoding="utf-8-sig"))
        if result.returncode:
            summary["error"] = (result.stderr or result.stdout or "部分規則套用失敗").strip()
        return summary


def backup(path: Path) -> dict:
    if path.suffix.lower() != ".json":
        raise ValueError("請選擇 .json 備份檔。")
    return _run("backup", path, elevated=False)


def restore(path: Path) -> dict:
    inspect_backup(path)
    return _run("restore", path, elevated=True)
