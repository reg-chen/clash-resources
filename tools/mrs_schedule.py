"""Current-user Windows Task Scheduler for local MRS."""
import base64
import os
import subprocess
import sys
from pathlib import Path

from local_mrs import TASK_NAME, validate_hours

_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$service = New-Object -ComObject 'Schedule.Service'
$service.Connect()
$folder = $service.GetFolder('\')
$name = $env:MRS_TASK_NAME
if ($env:MRS_TASK_ACTION -eq 'remove') {
    try { $folder.DeleteTask($name, 0); Write-Output 'Removed' }
    catch { if ($_.Exception.HResult -ne -2147024894) { throw }; Write-Output 'Not found' }
    exit 0
}
$hours = [int]$env:MRS_TASK_HOURS
$exe = $env:MRS_TASK_EXE
if (!(Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'Toolkit executable missing' }
$definition = $service.NewTask(0)
$definition.RegistrationInfo.Description = 'Compile private local MRS using VPN Network Toolkit'
$definition.Settings.Enabled = $true
$definition.Settings.StartWhenAvailable = $true
$definition.Settings.MultipleInstances = 2
$definition.Settings.ExecutionTimeLimit = 'PT45M'
$definition.Settings.DisallowStartIfOnBatteries = $false
$definition.Settings.StopIfGoingOnBatteries = $false
# A single time trigger with indefinite repetition preserves arbitrary N-hour
# intervals across midnight instead of restarting a daily repetition window.
$trigger = $definition.Triggers.Create(1)
$now = Get-Date
if ($hours -eq 24) {
    $start = $now.Date.AddHours(3).AddMinutes(20)
    if ($start -le $now) { $start = $start.AddDays(1) }
} else {
    $start = $now.Date.AddHours($now.Hour).AddMinutes(32)
    if ($start -le $now) { $start = $start.AddHours(1) }
}
$trigger.StartBoundary = $start.ToString('yyyy-MM-ddTHH:mm:ss')
$trigger.Repetition.Interval = [System.Xml.XmlConvert]::ToString([TimeSpan]::FromHours($hours))
# Omit Repetition.Duration: repeat indefinitely.
$trigger.Enabled = $true
$action = $definition.Actions.Create(0)
$action.Path = $exe
$action.Arguments = '--mrs'
$action.WorkingDirectory = Split-Path -Parent $exe
$definition.Principal.UserId = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$definition.Principal.LogonType = 3
$definition.Principal.RunLevel = 0
$null = $folder.RegisterTaskDefinition($name, $definition, 6, $null, $null, 3, $null)
Write-Output 'Installed'
"""


def configure(action, hours=2):
    if sys.platform != "win32":
        raise RuntimeError("Windows 工作排程只支援 Windows。")
    if action not in ("install", "remove"):
        raise ValueError("Invalid MRS schedule action")
    if action == "install":
        validate_hours(hours)
    if action == "install" and not getattr(sys, "frozen", False):
        raise RuntimeError("請使用打包後的 VPN-Network-Toolkit.exe 安裝排程。")
    env = os.environ.copy()
    env.update(MRS_TASK_NAME=TASK_NAME, MRS_TASK_ACTION=action, MRS_TASK_HOURS=str(hours),
               MRS_TASK_EXE=str(Path(sys.executable).resolve()))
    command = base64.b64encode(_SCRIPT.encode("utf-16le")).decode("ascii")
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", command],
                            env=env, capture_output=True, text=True, timeout=45,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout or "工作排程操作失敗").strip())
    return result.stdout.strip()
