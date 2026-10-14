#Requires -Version 5.1
<#
.SYNOPSIS
  Install, replace, or remove a Windows scheduled task for WARP renewal.
.EXAMPLE
  .\Install-WarpSchedule.ps1
.EXAMPLE
  .\Install-WarpSchedule.ps1 -ExePath 'C:\Tools\VPN-Mihomo-Generator.exe' -Time '03:00'
.EXAMPLE
  .\Install-WarpSchedule.ps1 -ExePath 'C:\Tools\VPN-Mihomo-Generator.exe' -Time '03:00' -OutDir 'P:\Clash'
.EXAMPLE
  .\Install-WarpSchedule.ps1 -Remove
.NOTES
  Runs on calendar days 5, 10, 15, 20, 25 and 30 of every month.
  The task runs under the current user and requires that user to be logged on.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ExePath,
    [ValidatePattern('^([01]\d|2[0-3]):[0-5]\d$')]
    [string]$Time = '03:00',
    [string]$OutDir = 'P:\Clash',
    [string]$TaskName = 'Clash WARP Refresh',
    [switch]$Remove,
    [switch]$NonInteractive
)

$ErrorActionPreference = 'Stop'

# Running without arguments opens an interactive setup. Explicit CLI arguments
# continue to work without prompts for scripts and automation.
$interactive = (-not $NonInteractive) -and ($PSBoundParameters.Count -eq 0)
function Read-Default([string]$Prompt, [string]$Default) {
    $value = Read-Host "$Prompt [$Default]"
    if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
    return $value.Trim().Trim('"')
}

if ($interactive) {
    Write-Host ''
    Write-Host '=== WARP Windows 工作排程設定 ===' -ForegroundColor Cyan
    Write-Host '執行日期固定為每月 5、10、15、20、25、30 日。'
    Write-Host ''
    $choice = Read-Default '操作：1 建立/更新，2 刪除，0 取消' '1'
    switch ($choice) {
        '1' { }
        '2' { $Remove = $true }
        '0' { Write-Host '已取消。'; return }
        default { throw "未知的選項：$choice" }
    }
    $TaskName = Read-Default '排程名稱' $TaskName
    if (-not $Remove) {
        Write-Host '選擇 EXE，可直接輸入完整路徑，或按 Enter 開啟檔案瀏覽視窗。'
        $enteredExe = Read-Host 'VPN-Mihomo-Generator.exe 路徑（Enter 瀏覽）'
        if ([string]::IsNullOrWhiteSpace($enteredExe)) {
            Add-Type -AssemblyName System.Windows.Forms
            $dialog = New-Object System.Windows.Forms.OpenFileDialog
            $dialog.Title = '選取 VPN-Mihomo-Generator.exe'
            $dialog.Filter = 'Windows 執行檔 (*.exe)|*.exe'
            $dialog.FileName = 'VPN-Mihomo-Generator.exe'
            if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
                Write-Host '未選擇檔案，已取消。'; return
            }
            $ExePath = $dialog.FileName
            $dialog.Dispose()
        } else {
            $ExePath = $enteredExe.Trim().Trim('"')
        }
        do {
            $Time = Read-Default '執行時間（24 小時制 HH:mm）' $Time
            if ($Time -notmatch '^([01]\d|2[0-3]):[0-5]\d
if ($Remove) {
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $existing) { Write-Host "排程不存在：$TaskName"; return }
    if ($PSCmdlet.ShouldProcess($TaskName, '刪除工作排程')) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "已刪除排程：$TaskName"
    }
    return
}

if ([string]::IsNullOrWhiteSpace($ExePath)) {
    throw '請用 -ExePath 指定 VPN-Mihomo-Generator.exe 的完整路徑。'
}
$resolved = (Resolve-Path -LiteralPath $ExePath -ErrorAction Stop).ProviderPath
if ([IO.Path]::GetExtension($resolved) -ine '.exe') {
    throw "指定的檔案不是 EXE：$resolved"
}

# Task Scheduler actions do not go through PowerShell; quote executable and path explicitly.
$escapedDir = $OutDir.Replace('"', '\"')
$arguments = '--warp --out-dir "{0}"' -f $escapedDir

# ScheduledTasks' New-ScheduledTaskTrigger has no Monthly parameter on Windows PowerShell 5.1.
# Use native Task Scheduler COM calendar trigger for the exact day-of-month mask.
$service = New-Object -ComObject 'Schedule.Service'
$service.Connect()
$root = $service.GetFolder('\')
$definition = $service.NewTask(0)
$definition.RegistrationInfo.Description = '每月 5/10/15/20/25/30 日重新產生 Cloudflare WARP Mihomo provider。'
$definition.Settings.Enabled = $true
$definition.Settings.StartWhenAvailable = $true
$definition.Settings.ExecutionTimeLimit = 'PT15M'
$definition.Settings.MultipleInstances = 2 # IgnoreNew: do not overlap registrations.
$definition.Settings.DisallowStartIfOnBatteries = $false
$definition.Settings.StopIfGoingOnBatteries = $false

$trigger = $definition.Triggers.Create(4) # TASK_TRIGGER_MONTHLY
$trigger.StartBoundary = (Get-Date -Format 'yyyy-MM-dd') + 'T' + $Time + ':00'
$dayMask = 0
foreach ($day in @(5, 10, 15, 20, 25, 30)) { $dayMask = $dayMask -bor (1 -shl ($day - 1)) }
$trigger.DaysOfMonth = $dayMask
$trigger.MonthsOfYear = 4095 # Jan-Dec
$trigger.Enabled = $true

$taskAction = $definition.Actions.Create(0) # TASK_ACTION_EXEC
$taskAction.Path = $resolved
$taskAction.Arguments = $arguments
$taskAction.WorkingDirectory = Split-Path -Parent $resolved

# InteractiveToken is deliberate: P: may be a mapped drive unavailable to a background logon.
$definition.Principal.UserId = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$definition.Principal.LogonType = 3 # TASK_LOGON_INTERACTIVE_TOKEN
$definition.Principal.RunLevel = 0 # Least privilege

if ($PSCmdlet.ShouldProcess($TaskName, '建立或更新工作排程')) {
    $null = $root.RegisterTaskDefinition($TaskName, $definition, 6, $null, $null, 3, $null) # CREATE_OR_UPDATE
    Write-Host "已建立／更新：$TaskName"
    Write-Host "每月日期：5、10、15、20、25、30 日；時間：$Time"
    Write-Host "程式：$resolved"
    Write-Host "參數：$arguments"
    Write-Host "紀錄：$OutDir\logs\warp-generator.log"
    Write-Warning '此排程僅在目前 Windows 使用者已登入時執行。P: 若是網路磁碟，請確認登入時已掛載。'
}
) {
                Write-Warning '時間格式錯誤，請輸入例如 03:00。'
            }
        } while ($Time -notmatch '^([01]\d|2[0-3]):[0-5]\d
if ($Remove) {
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $existing) { Write-Host "排程不存在：$TaskName"; return }
    if ($PSCmdlet.ShouldProcess($TaskName, '刪除工作排程')) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "已刪除排程：$TaskName"
    }
    return
}

if ([string]::IsNullOrWhiteSpace($ExePath)) {
    throw '請用 -ExePath 指定 VPN-Mihomo-Generator.exe 的完整路徑。'
}
$resolved = (Resolve-Path -LiteralPath $ExePath -ErrorAction Stop).ProviderPath
if ([IO.Path]::GetExtension($resolved) -ine '.exe') {
    throw "指定的檔案不是 EXE：$resolved"
}

# Task Scheduler actions do not go through PowerShell; quote executable and path explicitly.
$escapedDir = $OutDir.Replace('"', '\"')
$arguments = '--warp --out-dir "{0}"' -f $escapedDir

# ScheduledTasks' New-ScheduledTaskTrigger has no Monthly parameter on Windows PowerShell 5.1.
# Use native Task Scheduler COM calendar trigger for the exact day-of-month mask.
$service = New-Object -ComObject 'Schedule.Service'
$service.Connect()
$root = $service.GetFolder('\')
$definition = $service.NewTask(0)
$definition.RegistrationInfo.Description = '每月 5/10/15/20/25/30 日重新產生 Cloudflare WARP Mihomo provider。'
$definition.Settings.Enabled = $true
$definition.Settings.StartWhenAvailable = $true
$definition.Settings.ExecutionTimeLimit = 'PT15M'
$definition.Settings.MultipleInstances = 2 # IgnoreNew: do not overlap registrations.
$definition.Settings.DisallowStartIfOnBatteries = $false
$definition.Settings.StopIfGoingOnBatteries = $false

$trigger = $definition.Triggers.Create(4) # TASK_TRIGGER_MONTHLY
$trigger.StartBoundary = (Get-Date -Format 'yyyy-MM-dd') + 'T' + $Time + ':00'
$dayMask = 0
foreach ($day in @(5, 10, 15, 20, 25, 30)) { $dayMask = $dayMask -bor (1 -shl ($day - 1)) }
$trigger.DaysOfMonth = $dayMask
$trigger.MonthsOfYear = 4095 # Jan-Dec
$trigger.Enabled = $true

$taskAction = $definition.Actions.Create(0) # TASK_ACTION_EXEC
$taskAction.Path = $resolved
$taskAction.Arguments = $arguments
$taskAction.WorkingDirectory = Split-Path -Parent $resolved

# InteractiveToken is deliberate: P: may be a mapped drive unavailable to a background logon.
$definition.Principal.UserId = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$definition.Principal.LogonType = 3 # TASK_LOGON_INTERACTIVE_TOKEN
$definition.Principal.RunLevel = 0 # Least privilege

if ($PSCmdlet.ShouldProcess($TaskName, '建立或更新工作排程')) {
    $null = $root.RegisterTaskDefinition($TaskName, $definition, 6, $null, $null, 3, $null) # CREATE_OR_UPDATE
    Write-Host "已建立／更新：$TaskName"
    Write-Host "每月日期：5、10、15、20、25、30 日；時間：$Time"
    Write-Host "程式：$resolved"
    Write-Host "參數：$arguments"
    Write-Host "紀錄：$OutDir\logs\warp-generator.log"
    Write-Warning '此排程僅在目前 Windows 使用者已登入時執行。P: 若是網路磁碟，請確認登入時已掛載。'
}
)
        $OutDir = Read-Default 'Mihomo 輸出目錄' $OutDir
        Write-Host ''
        Write-Host "排程：$TaskName"
        Write-Host "執行檔：$ExePath"
        Write-Host "執行時間：每月 5、10、15、20、25、30 日 $Time"
        Write-Host "輸出：$OutDir\providers\warp.yaml"
    } else {
        Write-Host "預計刪除：$TaskName"
    }
    $confirm = Read-Default '確認執行？(Y/N)' 'Y'
    if ($confirm -notmatch '^(?i:y|yes)
if ($Remove) {
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $existing) { Write-Host "排程不存在：$TaskName"; return }
    if ($PSCmdlet.ShouldProcess($TaskName, '刪除工作排程')) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "已刪除排程：$TaskName"
    }
    return
}

if ([string]::IsNullOrWhiteSpace($ExePath)) {
    throw '請用 -ExePath 指定 VPN-Mihomo-Generator.exe 的完整路徑。'
}
$resolved = (Resolve-Path -LiteralPath $ExePath -ErrorAction Stop).ProviderPath
if ([IO.Path]::GetExtension($resolved) -ine '.exe') {
    throw "指定的檔案不是 EXE：$resolved"
}

# Task Scheduler actions do not go through PowerShell; quote executable and path explicitly.
$escapedDir = $OutDir.Replace('"', '\"')
$arguments = '--warp --out-dir "{0}"' -f $escapedDir

# ScheduledTasks' New-ScheduledTaskTrigger has no Monthly parameter on Windows PowerShell 5.1.
# Use native Task Scheduler COM calendar trigger for the exact day-of-month mask.
$service = New-Object -ComObject 'Schedule.Service'
$service.Connect()
$root = $service.GetFolder('\')
$definition = $service.NewTask(0)
$definition.RegistrationInfo.Description = '每月 5/10/15/20/25/30 日重新產生 Cloudflare WARP Mihomo provider。'
$definition.Settings.Enabled = $true
$definition.Settings.StartWhenAvailable = $true
$definition.Settings.ExecutionTimeLimit = 'PT15M'
$definition.Settings.MultipleInstances = 2 # IgnoreNew: do not overlap registrations.
$definition.Settings.DisallowStartIfOnBatteries = $false
$definition.Settings.StopIfGoingOnBatteries = $false

$trigger = $definition.Triggers.Create(4) # TASK_TRIGGER_MONTHLY
$trigger.StartBoundary = (Get-Date -Format 'yyyy-MM-dd') + 'T' + $Time + ':00'
$dayMask = 0
foreach ($day in @(5, 10, 15, 20, 25, 30)) { $dayMask = $dayMask -bor (1 -shl ($day - 1)) }
$trigger.DaysOfMonth = $dayMask
$trigger.MonthsOfYear = 4095 # Jan-Dec
$trigger.Enabled = $true

$taskAction = $definition.Actions.Create(0) # TASK_ACTION_EXEC
$taskAction.Path = $resolved
$taskAction.Arguments = $arguments
$taskAction.WorkingDirectory = Split-Path -Parent $resolved

# InteractiveToken is deliberate: P: may be a mapped drive unavailable to a background logon.
$definition.Principal.UserId = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$definition.Principal.LogonType = 3 # TASK_LOGON_INTERACTIVE_TOKEN
$definition.Principal.RunLevel = 0 # Least privilege

if ($PSCmdlet.ShouldProcess($TaskName, '建立或更新工作排程')) {
    $null = $root.RegisterTaskDefinition($TaskName, $definition, 6, $null, $null, 3, $null) # CREATE_OR_UPDATE
    Write-Host "已建立／更新：$TaskName"
    Write-Host "每月日期：5、10、15、20、25、30 日；時間：$Time"
    Write-Host "程式：$resolved"
    Write-Host "參數：$arguments"
    Write-Host "紀錄：$OutDir\logs\warp-generator.log"
    Write-Warning '此排程僅在目前 Windows 使用者已登入時執行。P: 若是網路磁碟，請確認登入時已掛載。'
}
) {
        Write-Host '已取消。'; return
    }
}

if ($Remove) {
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $existing) { Write-Host "排程不存在：$TaskName"; return }
    if ($PSCmdlet.ShouldProcess($TaskName, '刪除工作排程')) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "已刪除排程：$TaskName"
    }
    return
}

if ([string]::IsNullOrWhiteSpace($ExePath)) {
    throw '請用 -ExePath 指定 VPN-Mihomo-Generator.exe 的完整路徑。'
}
$resolved = (Resolve-Path -LiteralPath $ExePath -ErrorAction Stop).ProviderPath
if ([IO.Path]::GetExtension($resolved) -ine '.exe') {
    throw "指定的檔案不是 EXE：$resolved"
}

# Task Scheduler actions do not go through PowerShell; quote executable and path explicitly.
$escapedDir = $OutDir.Replace('"', '\"')
$arguments = '--warp --out-dir "{0}"' -f $escapedDir

# ScheduledTasks' New-ScheduledTaskTrigger has no Monthly parameter on Windows PowerShell 5.1.
# Use native Task Scheduler COM calendar trigger for the exact day-of-month mask.
$service = New-Object -ComObject 'Schedule.Service'
$service.Connect()
$root = $service.GetFolder('\')
$definition = $service.NewTask(0)
$definition.RegistrationInfo.Description = '每月 5/10/15/20/25/30 日重新產生 Cloudflare WARP Mihomo provider。'
$definition.Settings.Enabled = $true
$definition.Settings.StartWhenAvailable = $true
$definition.Settings.ExecutionTimeLimit = 'PT15M'
$definition.Settings.MultipleInstances = 2 # IgnoreNew: do not overlap registrations.
$definition.Settings.DisallowStartIfOnBatteries = $false
$definition.Settings.StopIfGoingOnBatteries = $false

$trigger = $definition.Triggers.Create(4) # TASK_TRIGGER_MONTHLY
$trigger.StartBoundary = (Get-Date -Format 'yyyy-MM-dd') + 'T' + $Time + ':00'
$dayMask = 0
foreach ($day in @(5, 10, 15, 20, 25, 30)) { $dayMask = $dayMask -bor (1 -shl ($day - 1)) }
$trigger.DaysOfMonth = $dayMask
$trigger.MonthsOfYear = 4095 # Jan-Dec
$trigger.Enabled = $true

$taskAction = $definition.Actions.Create(0) # TASK_ACTION_EXEC
$taskAction.Path = $resolved
$taskAction.Arguments = $arguments
$taskAction.WorkingDirectory = Split-Path -Parent $resolved

# InteractiveToken is deliberate: P: may be a mapped drive unavailable to a background logon.
$definition.Principal.UserId = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$definition.Principal.LogonType = 3 # TASK_LOGON_INTERACTIVE_TOKEN
$definition.Principal.RunLevel = 0 # Least privilege

if ($PSCmdlet.ShouldProcess($TaskName, '建立或更新工作排程')) {
    $null = $root.RegisterTaskDefinition($TaskName, $definition, 6, $null, $null, 3, $null) # CREATE_OR_UPDATE
    Write-Host "已建立／更新：$TaskName"
    Write-Host "每月日期：5、10、15、20、25、30 日；時間：$Time"
    Write-Host "程式：$resolved"
    Write-Host "參數：$arguments"
    Write-Host "紀錄：$OutDir\logs\warp-generator.log"
    Write-Warning '此排程僅在目前 Windows 使用者已登入時執行。P: 若是網路磁碟，請確認登入時已掛載。'
}
