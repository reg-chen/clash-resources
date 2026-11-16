param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("backup", "restore")]
    [string]$Mode,
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [Parameter(Mandatory = $true)]
    [string]$Report
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
    $filters = @(Get-NetFirewallApplicationFilter -PolicyStore PersistentStore -All -ErrorAction Stop)
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
    return $output
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
$reportData = @{ Total = 0; Added = 0; Existing = 0; MissingPackage = 0; Unsupported = 0; Errors = @() }

if ($Mode -eq "backup") {
    $rules = @(Rule-Records $families)
    $snapshot = [pscustomobject]@{
        Schema = 1
        ExportedAt = (Get-Date).ToUniversalTime().ToString("o")
        Type = "PersistentStore-UWP-PackageRules"
        Rules = $rules
    }
    $temporary = "$Path.partial"
    $snapshot | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $Path -Force
    $reportData.Total = $rules.Count
} else {
    $snapshot = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($snapshot.Schema -ne 1 -or $snapshot.Type -ne "PersistentStore-UWP-PackageRules") {
        throw "Unsupported UWP firewall backup format."
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
        if (NonDefault $record.Authentication -or NonDefault $record.Encryption -or
            NonDefault $record.LocalUser -or NonDefault $record.RemoteUser -or
            NonDefault $record.RemoteMachine -or NonDefault $record.OverrideBlockRules) {
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
