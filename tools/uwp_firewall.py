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
    """Validate legacy v1 and AppIso-aware v2 snapshots without applying rules."""
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    legacy = data.get("Schema") == 1 and data.get("Type") == "PersistentStore-UWP-PackageRules" if isinstance(data, dict) else False
    current = data.get("Schema") == 2 and data.get("Type") == "UWP-PackageFirewallRules" if isinstance(data, dict) else False
    if not (legacy or current):
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
    if current:
        registry = data.get("AppIsoRules")
        if not isinstance(registry, list) or len(registry) > 200000:
            raise ValueError("AppIso 登錄備份內容無效或數量異常。")
        for entry in registry:
            if (not isinstance(entry, dict)
                or not isinstance(entry.get("Name"), str)
                or not 1 <= len(entry["Name"]) <= 256
                or entry.get("Kind") != "String"
                or not isinstance(entry.get("Data"), str)
                or len(entry["Data"]) > 65536):
                raise ValueError("AppIso 登錄備份包含不支援的資料。")
            action = re.search(r"(?:^|\|)Action=(Allow|Block)(?:\||$)", entry["Data"], re.IGNORECASE)
            if action:
                counts[action.group(1).lower()] += 1
        counts["appiso"] = len(registry)
        counts["netsecurity"] = len(rules)
        counts["total"] += len(registry)
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
            # Encode the full inner invocation, not Windows-quoted argv.
            # Start-Process joins -ArgumentList values; passing the paths
            # directly would break in directories containing spaces/quotes.
            inner = (
                f"& {_quote_ps(str(script))} -Mode {_quote_ps(mode)} "
                f"-Path {_quote_ps(str(target))} -Report {_quote_ps(str(report))}; "
                "exit $LASTEXITCODE"
            )
            inner_encoded = base64.b64encode(inner.encode("utf-16-le")).decode("ascii")
            outer = (
                "$p = Start-Process -FilePath 'powershell.exe' "
                "-ArgumentList @('-NoProfile','-NonInteractive',"
                f"'-ExecutionPolicy','Bypass','-EncodedCommand','{inner_encoded}') "
                "-Verb RunAs -Wait -PassThru; exit $p.ExitCode"
            )
            outer_encoded = base64.b64encode(outer.encode("utf-16-le")).decode("ascii")
            command = [
                "powershell.exe", "-NoProfile", "-NonInteractive",
                "-EncodedCommand", outer_encoded,
            ]
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
            errors = summary.get("Errors", [])
            detail = "; ".join(str(x) for x in errors[:5]) if errors else (
                result.stderr or result.stdout or "防火牆命令執行失敗"
            ).strip()
            raise RuntimeError(f"Windows 防火牆操作未完成（exit {result.returncode}）：{detail[-1000:]}")
        if mode == "backup":
            snapshot = inspect_backup(target)
            if snapshot["total"] <= 0:
                raise RuntimeError("沒有找到可備份的 UWP 防火牆規則；拒絕將空白檔案當作成功備份。")
            if snapshot["total"] != summary.get("Total"):
                raise RuntimeError(
                    f"UWP 備份數量不一致：JSON {snapshot['total']} 條，"
                    f"PowerShell 報告 {summary.get('Total')} 條。"
                )
        return summary


def backup(path: Path) -> dict:
    if path.suffix.lower() != ".json":
        raise ValueError("請選擇 .json 備份檔。")
    return _run("backup", path, elevated=False)


def restore(path: Path) -> dict:
    inspect_backup(path)
    return _run("restore", path, elevated=True)
