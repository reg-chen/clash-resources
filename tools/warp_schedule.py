"""Windows Task Scheduler integration for headless WARP regeneration."""
from __future__ import annotations

import re
from pathlib import Path

from toolkit_schedule import configure_task, script_for

TASK_NAME = "Clash WARP Refresh"
MODES = {"monthly", "daily", "interval"}

_SCRIPT = script_for(r"""
$outDir = $env:WARP_TASK_OUT
$mode = $env:WARP_TASK_MODE
$clock = $env:WARP_TASK_TIME
$intervalDays = [int]$env:WARP_TASK_INTERVAL
if ($outDir.Contains('"')) { throw 'Output path contains invalid quotation mark' }
$definition = $service.NewTask(0)
$definition.RegistrationInfo.Description = 'Update WARP WireGuard provider using VPN-Network-Toolkit.exe'
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
""")


def configure_schedule(*, action: str, out_dir: Path | None = None,
                       mode: str = "monthly", time: str = "03:00", interval_days: int = 5) -> str:
    if action not in {"install", "remove"}:
        raise ValueError("Unsupported schedule action")
    if action == "install":
        if mode not in MODES:
            raise ValueError("Unsupported schedule frequency")
        if isinstance(interval_days, bool) or not isinstance(interval_days, int) or not 1 <= interval_days <= 365:
            raise ValueError("排程間隔天數必須為 1 至 365 的整數。")
        if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", time):
            raise ValueError("Invalid HH:mm time")
        if not out_dir or not str(out_dir).strip():
            raise ValueError("請選擇輸出目錄。")
    return configure_task(TASK_NAME, action, _SCRIPT, {
        "WARP_TASK_OUT": str(out_dir or ""),
        "WARP_TASK_MODE": mode,
        "WARP_TASK_TIME": time,
        "WARP_TASK_INTERVAL": str(interval_days),
    })
