"""Current-user Windows Task Scheduler for local MRS."""
from local_mrs import TASK_NAME, validate_hours
from toolkit_schedule import configure_task, scheduler_executable, script_for

_SCRIPT = script_for(r"""
$hours = [int]$env:MRS_TASK_HOURS
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
""")


def configure(action, hours=2):
    if action not in ("install", "remove"):
        raise ValueError("Invalid MRS schedule action")
    if action == "install":
        validate_hours(hours)
    return configure_task(TASK_NAME, action, _SCRIPT, {"MRS_TASK_HOURS": str(hours)})
