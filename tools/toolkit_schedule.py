"""Shared Windows Task Scheduler executable lifecycle for WARP and MRS."""
from __future__ import annotations

import base64
import os
import subprocess
import sys
from pathlib import Path

TASK_NAMES = ("Clash Local MRS Refresh", "Clash WARP Refresh")

_PREFIX = r"""
$ErrorActionPreference = 'Stop'
$service = New-Object -ComObject 'Schedule.Service'
$service.Connect()
$folder = $service.GetFolder('\')
$name = $env:TOOLKIT_TASK_NAME
$source = $env:TOOLKIT_TASK_SOURCE
$exe = $env:TOOLKIT_TASK_EXE
$directory = Split-Path -Parent $exe
$parent = Split-Path -Parent $directory
[void][IO.Directory]::CreateDirectory($parent)
$lock = [IO.File]::Open((Join-Path $parent 'scheduler.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
$tasks = @{}
$enabled = @{}
$committed = $false
$changed = $false
$backup = $null
$stage = $null
try {
    # Inspect both registered tasks under the same lock, even if one is
    # disabled or still points to a legacy portable executable.
    foreach ($taskName in @('Clash Local MRS Refresh', 'Clash WARP Refresh')) {
        try { $task = $folder.GetTask($taskName) }
        catch {
            if ($_.Exception.HResult -ne -2147024894 -and
                $_.Exception.Message -notmatch '0x80070002') { throw }
            continue
        }
        if ($task.GetInstances(0).Count -gt 0 -or $task.State -in 2,4) {
            throw "Toolkit task is running or queued: $taskName"
        }
        $tasks[$taskName] = $task
        $enabled[$taskName] = $task.Enabled
        if ($task.Enabled) { $task.Enabled = $false }
        if ($task.GetInstances(0).Count -gt 0 -or $task.State -in 2,4) {
            throw "Toolkit task started during update: $taskName"
        }
    }
    if ($env:TOOLKIT_TASK_OPERATION -eq 'remove') {
        $otherExists = @($tasks.Keys | Where-Object { $_ -ne $name }).Count -gt 0
        if (!$otherExists -and [IO.File]::Exists($exe)) {
            $backup = Join-Path $directory ([Guid]::NewGuid().ToString() + '.remove')
            [IO.File]::Move($exe, $backup)
            $changed = $true
        }
        if ($tasks.ContainsKey($name)) { $folder.DeleteTask($name, 0) }
        $committed = $true
        if ($backup) { [IO.File]::Delete($backup); $backup = $null }
        if (!$otherExists -and [IO.Directory]::Exists($directory) -and
                [IO.Directory]::GetFileSystemEntries($directory).Length -eq 0) {
            [IO.Directory]::Delete($directory)
        }
        Write-Output 'Removed'
        return
    }
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
"""

_SUFFIX = r"""
    $null = $folder.RegisterTaskDefinition($name, $definition, 6, $null, $null, 3, $null)
    $committed = $true
    if ($backup) { [IO.File]::Delete($backup); $backup = $null }
    Write-Output 'Installed'
} catch {
    if (!$committed -and $changed) {
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
    throw
} finally {
    try {
        # Restore surviving tasks on success, all original tasks on failure.
        # Do not re-enable the task that was successfully replaced or removed.
        foreach ($taskName in $enabled.Keys) {
            if (!$committed -or $taskName -ne $name) {
                $tasks[$taskName].Enabled = $enabled[$taskName]
            }
        }
    } finally {
        try {
            if ($stage -and [IO.File]::Exists($stage)) { [IO.File]::Delete($stage) }
        } finally {
            $lock.Dispose()
        }
    }
}
"""


def script_for(definition):
    return _PREFIX + definition + _SUFFIX


def scheduler_executable():
    base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    return base / "reg-chen" / "VPN-Network-Toolkit" / "scheduler" / "VPN-Network-Toolkit.exe"


def configure_task(name, action, script, parameters):
    if sys.platform != "win32":
        raise RuntimeError("Windows 工作排程只支援 Windows。")
    if name not in TASK_NAMES or action not in ("install", "remove"):
        raise ValueError("Invalid Toolkit schedule operation")
    if action == "install" and not getattr(sys, "frozen", False):
        raise RuntimeError("請使用打包後的 VPN-Network-Toolkit.exe 安裝排程。")
    env = os.environ.copy()
    env.update(parameters)
    env.update(TOOLKIT_TASK_NAME=name, TOOLKIT_TASK_OPERATION=action,
               TOOLKIT_TASK_SOURCE=str(Path(sys.executable).resolve()),
               TOOLKIT_TASK_EXE=str(scheduler_executable()))
    command = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", command],
                            env=env, capture_output=True, text=True, timeout=120,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout or "工作排程操作失敗").strip())
    return result.stdout.strip()
