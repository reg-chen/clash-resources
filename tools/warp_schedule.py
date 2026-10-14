"""Windows Task Scheduler integration for headless WARP regeneration."""
from __future__ import annotations

import base64
import os
import subprocess
import sys
from pathlib import Path

TASK_NAME = "Clash WARP Refresh"
MODES = {"monthly", "daily", "interval"}

# EncodedCommand avoids shell quoting issues for exe paths containing spaces.
_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$service = New-Object -ComObject 'Schedule.Service'
$service.Connect()
$folder = $service.GetFolder('\')
$name = $env:WARP_TASK_NAME
if ($env:WARP_TASK_OPERATION -eq 'remove') {
    try { $folder.DeleteTask($name, 0); Write-Output 'Removed' }
    catch { if ($_.Exception.Message -match '0x80070002') { Write-Output 'Not found' } else { throw } }
    exit 0
}
$exe = $env:WARP_TASK_EXE
$outDir = $env:WARP_TASK_OUT
$mode = $env:WARP_TASK_MODE
$clock = $env:WARP_TASK_TIME
$intervalDays = [int]$env:WARP_TASK_INTERVAL
if (!(Test-Path -LiteralPath $exe -PathType Leaf)) { throw "EXE not found: $exe" }
if ($outDir.Contains('"')) { throw 'Output path contains invalid quotation mark' }
$definition = $service.NewTask(0)
$definition.RegistrationInfo.Description = 'Update Mihomo WARP WireGuard provider using VPN-Mihomo-Generator.exe'
$definition.Settings.Enabled = $true
$definition.Settings.StartWhenAvailable = $true
$definition.Settings.ExecutionTimeLimit = 'PT15M'
$definition.Settings.MultipleInstances = 2
$definition.Settings.DisallowStartIfOnBatteries = $false
$definition.Settings.StopIfGoingOnBatteries = $false
$triggerType = if ($mode -eq 'monthly') { 4 } else { 2 }
$trigger = $definition.Triggers.Create($triggerType)
$trigger.StartBoundary = (Get-Date -Format 'yyyy-MM-dd') + 'T' + $clock + ':00'
if ($mode -eq 'monthly') {
    $mask = 0
    foreach ($day in @(5,10,15,20,25,30)) { $mask = $mask -bor (1 -shl ($day - 1)) }
    $trigger.DaysOfMonth = $mask
    $trigger.MonthsOfYear = 4095
} elseif ($mode -eq 'interval') {
    if ($intervalDays -lt 1 -or $intervalDays -gt 365) { throw 'Invalid interval: 1 to 365 days' }
    $trigger.DaysInterval = $intervalDays
} else {
    $trigger.DaysInterval = 1
}
$trigger.Enabled = $true
$action = $definition.Actions.Create(0)
$action.Path = $exe
$action.Arguments = '--warp --out-dir "' + $outDir + '"'
$action.WorkingDirectory = Split-Path -Parent $exe
$definition.Principal.UserId = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$definition.Principal.LogonType = 3
$definition.Principal.RunLevel = 0
$null = $folder.RegisterTaskDefinition($name, $definition, 6, $null, $null, 3, $null)
Write-Output 'Installed'
"""


def configure_schedule(*, action: str, out_dir: Path | None = None,
                       mode: str = "monthly", time: str = "03:00", interval_days: int = 5) -> str:
    if sys.platform != "win32":
        raise RuntimeError("Windows 工作排程只支援 Windows。")
    if action not in {"install", "remove"}:
        raise ValueError("Unsupported schedule action")
    if mode not in MODES:
        raise ValueError("Unsupported schedule frequency")
    if isinstance(interval_days, bool) or not isinstance(interval_days, int) or not 1 <= interval_days <= 365:
        raise ValueError("排程間隔天數必須為 1 至 365 的整數。")
    import re
    if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", time):
        raise ValueError("Invalid HH:mm time")
    if action == "install" and (not out_dir or not str(out_dir).strip()):
        raise ValueError("請選擇輸出目錄。")
    exe = Path(sys.executable).resolve()
    if action == "install" and not getattr(sys, "frozen", False):
        raise RuntimeError("請使用打包後的 VPN-Mihomo-Generator.exe 安裝排程。")
    env = os.environ.copy()
    env.update({
        "WARP_TASK_NAME": TASK_NAME,
        "WARP_TASK_OPERATION": action,
        "WARP_TASK_EXE": str(exe),
        "WARP_TASK_OUT": str(out_dir or ""),
        "WARP_TASK_MODE": mode,
        "WARP_TASK_TIME": time,
        "WARP_TASK_INTERVAL": str(interval_days),
    })
    encoded = base64.b64encode(_SCRIPT.encode("utf-16le")).decode("ascii")
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        env=env, capture_output=True, text=True, timeout=45,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout or "工作排程操作失敗").strip())
    return result.stdout.strip()
