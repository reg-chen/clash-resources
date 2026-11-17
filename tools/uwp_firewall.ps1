param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("backup", "restore")]
    [string]$Mode,
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [Parameter(Mandatory = $true)]
    [string]$Report,
    # CI-only: a clean GitHub runner may genuinely have no UWP isolation rules.
    [switch]$AllowEmpty
)
$ErrorActionPreference = "Stop"
Import-Module NetSecurity -ErrorAction Stop

# Package SIDs are derived from package FAMILY names (independent of version).
if (-not ("UwpFirewallSid" -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
public static class UwpFirewallSid {
    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    private static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr sid);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern IntPtr FreeSid(IntPtr sid);
    public static string ForPackage(string family) {
        IntPtr ptr;
        int result = DeriveAppContainerSidFromAppContainerName(family, out ptr);
        if (result != 0 || ptr == IntPtr.Zero) { return ""; }
        try { return new SecurityIdentifier(ptr).Value; }
        finally { FreeSid(ptr); }
    }
}
'@ -ErrorAction Stop
}

function Installed-Packages {
    $lookup = @{}
    # An elevated restore may run as a different admin user. Query all
    # installed AppX packages then, so a non-admin user's Store apps are
    # still resolvable by package family SID.
    $packages = if ($Mode -eq "restore") {
        @(Get-AppxPackage -AllUsers -ErrorAction Stop)
    } else {
        @(Get-AppxPackage -ErrorAction Stop)
    }
    foreach ($app in $packages) {
        $family = [string]$app.PackageFamilyName
        if (-not $family) { continue }
        $sid = [UwpFirewallSid]::ForPackage($family)
        if ($sid) { $lookup[$sid] = $family }
    }
    return ,$lookup
}

function String-Value($value) {
    if ($null -eq $value) { return "" }
    if ($value -is [System.Array]) { return (($value | ForEach-Object { [string]$_ }) -join ",") }
    return [string]$value
}

function Rule-Records($familyMap) {
    $output = @()
    foreach ($store in @("PersistentStore", "ConfigurableServiceStore")) {
        $filters = @(Get-NetFirewallApplicationFilter -PolicyStore $store -All -ErrorAction Stop)
        foreach ($app in $filters) {
        $sid = [string]$app.Package
        if ($sid -notmatch '^S-1-15-2-(?:[0-9]+-)*[0-9]+$') { continue }
        $rule = $app | Get-NetFirewallRule -ErrorAction Stop
        if ($null -eq $rule) { continue }
        $port = $rule | Get-NetFirewallPortFilter
        $address = $rule | Get-NetFirewallAddressFilter
        $interface = $rule | Get-NetFirewallInterfaceFilter
        $interfaceType = $rule | Get-NetFirewallInterfaceTypeFilter
        $service = $rule | Get-NetFirewallServiceFilter
        $security = $rule | Get-NetFirewallSecurityFilter
        $family = if ($familyMap.ContainsKey($sid)) { [string]$familyMap[$sid] } else { "" }
        $output += [pscustomobject]@{
            Name = [string]$rule.Name
            PolicyStore = $store
            Owner = [string]$rule.Owner
            DisplayName = [string]$rule.DisplayName
            Description = [string]$rule.Description
            Enabled = [string]$rule.Enabled
            Direction = [string]$rule.Direction
            Action = [string]$rule.Action
            Profile = [string]$rule.Profile
            EdgeTraversalPolicy = [string]$rule.EdgeTraversalPolicy
            PackageSID = $sid
            PackageFamilyName = $family
            Program = String-Value $app.Program
            Protocol = String-Value $port.Protocol
            LocalPort = String-Value $port.LocalPort
            RemotePort = String-Value $port.RemotePort
            IcmpType = String-Value $port.IcmpType
            LocalAddress = String-Value $address.LocalAddress
            RemoteAddress = String-Value $address.RemoteAddress
            InterfaceAlias = String-Value $interface.InterfaceAlias
            InterfaceType = String-Value $interfaceType.InterfaceType
            Service = String-Value $service.Service
            Authentication = String-Value $security.Authentication
            Encryption = String-Value $security.Encryption
            LocalUser = String-Value $security.LocalUser
            RemoteUser = String-Value $security.RemoteUser
            RemoteMachine = String-Value $security.RemoteMachine
            OverrideBlockRules = [string]$security.OverrideBlockRules
        }
        }
    }
    return $output
}

# Modern Windows AppContainer network-isolation rules are not returned by
# Get-NetFirewallRule. They live in this registry key; read verbatim for a
# lossless backup rather than trying to reconstruct their undocumented fields.
$AppIsoKey = "SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\AppIso\FirewallRules"
function AppIso-Records {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($AppIsoKey, $false)
    if ($null -eq $key) {
        if ($AllowEmpty) { return @() }
        throw "找不到或無法讀取 UWP AppIso 防火牆登錄機碼：HKLM:\$AppIsoKey。備份未完成。"
    }
    $records = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($name in $key.GetValueNames()) {
            $kind = $key.GetValueKind($name)
            if ($kind -ne [Microsoft.Win32.RegistryValueKind]::String) {
                throw "AppIso 防火牆包含不支援的登錄類型：$name ($kind)。備份未完成，以免遺漏規則。"
            }
            $raw = [string]$key.GetValue(
                $name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
            )
            $records.Add([pscustomobject]@{
                Name = [string]$name
                Kind = "String"
                Data = $raw
            })
        }
    } finally {
        $key.Close()
    }
    return $records.ToArray()
}

$identityFields = @(
    "PackageSID", "DisplayName", "Enabled", "Direction", "Action", "Profile",
    "EdgeTraversalPolicy", "Program", "Protocol", "LocalPort", "RemotePort",
    "IcmpType", "LocalAddress", "RemoteAddress", "InterfaceAlias",
    "InterfaceType", "Service", "Authentication", "Encryption",
    "LocalUser", "RemoteUser", "RemoteMachine", "OverrideBlockRules"
)

function Identity($rule) {
    $values = @()
    foreach ($key in $identityFields) { $values += (String-Value $rule.$key) }
    $payload = ConvertTo-Json -InputObject $values -Compress -Depth 4
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace "-", "").ToLowerInvariant()
    } finally { $sha.Dispose() }
}

function NonDefault($value) {
    return ((String-Value $value) -notin @("", "Any", "NotRequired", "False", "0"))
}

$families = Installed-Packages
$reportData = @{ Total = 0; Added = 0; Existing = 0; MissingPackage = 0; Unsupported = 0; Errors = @(); Warnings = @(); Sources = @{} }

if ($Mode -eq "backup") {
    $rules = @(Rule-Records $families)
    $appIsoRules = @(AppIso-Records)
    $reportData.Sources = @{
        PersistentStore = @($rules | Where-Object { $_.PolicyStore -eq "PersistentStore" }).Count
        ConfigurableServiceStore = @($rules | Where-Object { $_.PolicyStore -eq "ConfigurableServiceStore" }).Count
        AppIsoRegistry = $appIsoRules.Count
    }
    $reportData.Total = $rules.Count + $appIsoRules.Count
    if ($reportData.Total -eq 0 -and -not $AllowEmpty) {
        $reportData.Errors += "查詢結果為 0 條；已檢查 PersistentStore、ConfigurableServiceStore 與 AppIso 登錄規則。未產生空白備份，請確認防火牆服務／讀取權限。"
        $reportData | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Report -Encoding UTF8
        exit 3
    }
    $snapshot = [pscustomobject]@{
        Schema = 2
        ExportedAt = (Get-Date).ToUniversalTime().ToString("o")
        Type = "UWP-PackageFirewallRules"
        ComputerName = $env:COMPUTERNAME
        Rules = $rules
        AppIsoRules = $appIsoRules
    }
    $temporary = "$Path.partial"
    $snapshot | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $Path -Force
} else {
    $snapshot = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    $legacy = ($snapshot.Schema -eq 1 -and $snapshot.Type -eq "PersistentStore-UWP-PackageRules")
    $current = ($snapshot.Schema -eq 2 -and $snapshot.Type -eq "UWP-PackageFirewallRules")
    if (-not ($legacy -or $current)) {
        throw "Unsupported UWP firewall backup format."
    }
    # Registry AppIso rules are preserved byte-for-byte in the backup, but are
    # deliberately NOT written directly to HKLM during restore: Windows owns
    # these network-isolation values, and arbitrary registry writes bypass the
    # NetSecurity APIs. Report these explicitly rather than claiming success.
    if ($current) {
        $appIsoCount = @($snapshot.AppIsoRules).Count
        $reportData.Total += $appIsoCount
        $reportData.Unsupported += $appIsoCount
        if ($appIsoCount -gt 0) {
            $reportData.Warnings += "AppIso 登錄規則 $appIsoCount 條已保存在 JSON，但尚不支援安全自動還原；沒有修改登錄機碼。"
        }
    }
    $existing = @{}
    foreach ($rule in @(Rule-Records $families)) { $existing[(Identity $rule)] = $true }
    foreach ($record in @($snapshot.Rules)) {
        if ($null -eq $record) { continue }
        $reportData.Total++
        $sid = [string]$record.PackageSID
        if ($sid -notmatch '^S-1-15-2-(?:[0-9]+-)*[0-9]+$') {
            $reportData.Unsupported++
            continue
        }
        $family = [string]$record.PackageFamilyName
        if ($family -and -not $families.ContainsKey($sid)) {
            $reportData.MissingPackage++
            continue
        }
        # Without a verified installed family, do not create an orphan rule.
        if (-not $family -or -not $families.ContainsKey($sid) -or [string]$families[$sid] -ne $family) {
            $reportData.MissingPackage++
            continue
        }
        if ([string]$record.Direction -notin @("Inbound", "Outbound") -or
            [string]$record.Action -notin @("Allow", "Block") -or
            [string]$record.Enabled -notin @("True", "False")) {
            $reportData.Unsupported++
            continue
        }
        $hash = Identity $record
        if ($existing.ContainsKey($hash)) {
            $reportData.Existing++
            continue
        }
        # Never broaden a rule that uses conditions not restored below.
        # ConfigurableServiceStore AppContainer isolation rules can have
        # extra Windows-owned semantics; do not reinterpret them as manually
        # created PersistentStore rules.
        if ([string]$record.PolicyStore -notin @("", "PersistentStore") -or
            (NonDefault $record.Owner) -or
            (NonDefault $record.Authentication) -or
            (NonDefault $record.Encryption) -or
            (NonDefault $record.LocalUser) -or
            (NonDefault $record.RemoteUser) -or
            (NonDefault $record.RemoteMachine) -or
            (NonDefault $record.OverrideBlockRules)) {
            $reportData.Unsupported++
            continue
        }
        if (NonDefault $record.Program) {
            $programPath = [Environment]::ExpandEnvironmentVariables([string]$record.Program)
            if (-not (Test-Path -LiteralPath $programPath -PathType Leaf)) {
                $reportData.Unsupported++
                continue
            }
        }
        $args = @{
            Name = "regchen-uwp-$($hash.Substring(0,24))"
            DisplayName = [string]$record.DisplayName
            Direction = [string]$record.Direction
            Action = [string]$record.Action
            Enabled = [string]$record.Enabled
            Package = $sid
            PolicyStore = "PersistentStore"
            Group = "reg-chen UWP restored"
        }
        foreach ($key in @(
            "Description", "Profile", "EdgeTraversalPolicy", "Program",
            "Protocol", "LocalPort", "RemotePort", "IcmpType", "LocalAddress",
            "RemoteAddress", "InterfaceAlias", "InterfaceType", "Service"
        )) {
            $value = String-Value $record.$key
            if (NonDefault $value) { $args[$key] = $value }
        }
        # Protocol and port arguments are mutually constrained. Do not pass
        # IcmpType to TCP/UDP rules or ports to ICMP rules.
        if ($args.ContainsKey("IcmpType") -and
            [string]$record.Protocol -notin @("ICMPv4", "ICMPv6", "1", "58")) {
            $reportData.Unsupported++
            continue
        }
        try {
            New-NetFirewallRule @args -ErrorAction Stop | Out-Null
            $existing[$hash] = $true
            $reportData.Added++
        } catch {
            $reportData.Errors += "$($record.DisplayName): $($_.Exception.Message)"
        }
    }
}

$reportData | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Report -Encoding UTF8
if ($reportData.Errors.Count -gt 0) { exit 4 }
exit 0
