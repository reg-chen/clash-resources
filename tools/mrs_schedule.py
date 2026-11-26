"""Current-user Windows Task Scheduler for local MRS."""
import base64
import os
import subprocess
import sys
from pathlib import Path

from local_mrs import TASK_NAME, profile_path, validate_hours

_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$service = New-Object -ComObject 'Schedule.Service'
$service.Connect()
$folder = $service.GetFolder('\')
$name = $env:MRS_TASK_NAME
$source = $env:MRS_TASK_SOURCE
$exe = $env:MRS_TASK_EXE
$directory = Split-Path -Parent $exe
$parent = Split-Path -Parent $directory
[void][IO.Directory]::CreateDirectory($parent)
# Serialize install/remove across GUI processes. Windows releases the handle
# on termination. Never remove the lock file while another process may use it.
$lock = [IO.File]::Open((Join-Path $parent 'scheduler.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
$previous = $null
$wasEnabled = $false
$disabled = $false
$committed = $false
$changed = $false
$backup = $null
$stage = $null
try {
    try { $previous = $folder.GetTask($name) }
    catch { if ($_.Exception.HResult -ne -2147024894) { throw } }
    if ($null -ne $previous) {
        $wasEnabled = $previous.Enabled
        if ($wasEnabled) { $previous.Enabled = $false; $disabled = $true }
        # No Stop() or forced termination: preserve ongoing builds.
        if ($previous.GetInstances(0).Count -gt 0 -or $previous.State -in 2,4) {
            throw 'MRS task is running or queued; retry after it finishes.'
        }
    }
    if ($env:MRS_TASK_ACTION -eq 'remove') {
        if ([IO.File]::Exists($exe)) {
            $backup = Join-Path $directory ([Guid]::NewGuid().ToString() + '.remove')
            [IO.File]::Move($exe, $backup)
            $changed = $true
        }
        if ($null -ne $previous) { $folder.DeleteTask($name, 0) }
        $committed = $true
        if ($backup) { [IO.File]::Delete($backup); $backup = $null }
        if ([IO.Directory]::Exists($directory) -and
                [IO.Directory]::GetFileSystemEntries($directory).Length -eq 0) {
            [IO.Directory]::Delete($directory)
        }
        Write-Output 'Removed'
        return
    }
    $hours = [int]$env:MRS_TASK_HOURS
    if (!(Test-Path -LiteralPath $source -PathType Leaf)) { throw 'Toolkit executable missing' }
    [void][IO.Directory]::CreateDirectory($directory)
    $sourceHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    $same = (Test-Path -LiteralPath $exe -PathType Leaf) -and
            ((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -eq $sourceHash)
    if (!$same) {
        $stage = Join-Path $directory ([Guid]::NewGuid().ToString() + '.new')
        [IO.File]::Copy($source, $stage, $false)
        if ((Get-FileHash -LiteralPath $stage -Algorithm SHA256).Hash -ne $sourceHash) {
            throw 'Copied Toolkit SHA256 mismatch'
        }
        if ([IO.File]::Exists($exe)) {
            $backup = Join-Path $directory ([Guid]::NewGuid().ToString() + '.bak')
            [IO.File]::Replace($stage, $exe, $backup)
        } else {
            [IO.File]::Move($stage, $exe)
        }
        $changed = $true
        $stage = $null
    }
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
    $committed = $true
    if ($backup) { [IO.File]::Delete($backup); $backup = $null }
    Write-Output 'Installed'
} catch {
    if (!$committed) {
        try {
            if ($changed) {
                if ($backup -and [IO.File]::Exists($backup)) {
                    if ([IO.File]::Exists($exe)) {
                        [IO.File]::Replace($backup, $exe, $null)
                    } else {
                        [IO.File]::Move($backup, $exe)
                    }
                    $backup = $null
                } elseif ([IO.File]::Exists($exe)) {
                    [IO.File]::Delete($exe)
                }
            }
        } finally {
            if ($disabled) { $previous.Enabled = $wasEnabled }
        }
    }
    throw
} finally {
    try {
        if ($stage -and [IO.File]::Exists($stage)) { [IO.File]::Delete($stage) }
    } finally {
        $lock.Dispose()
    }
}
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
    source = Path(sys.executable).resolve()
    target = profile_path().parent / "scheduler" / "VPN-Network-Toolkit.exe"
    env = os.environ.copy()
    env.update(MRS_TASK_NAME=TASK_NAME, MRS_TASK_ACTION=action, MRS_TASK_HOURS=str(hours),
               MRS_TASK_SOURCE=str(source), MRS_TASK_EXE=str(target))
    command = base64.b64encode(_SCRIPT.encode("utf-16le")).decode("ascii")
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", command],
                            env=env, capture_output=True, text=True, timeout=120,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout or "工作排程操作失敗").strip())
    return result.stdout.strip()
