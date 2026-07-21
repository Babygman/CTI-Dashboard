[CmdletBinding()]
param(
    [switch]$Remove
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ruleName = "CTI Dashboard TCP 8000"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) {
    throw "Run this script from an elevated PowerShell session."
}

$existingRules = @(
    Get-NetFirewallRule -DisplayName $ruleName `
        -ErrorAction SilentlyContinue
)

if ($Remove) {
    if ($existingRules.Count -gt 0) {
        $existingRules | Remove-NetFirewallRule
        Write-Host "Removed firewall rule: $ruleName"
    }
    else {
        Write-Host "Firewall rule is already absent: $ruleName"
    }
    exit 0
}

$recreateRule = $existingRules.Count -ne 1
if (-not $recreateRule) {
    $rule = $existingRules[0]
    $portFilter = $rule | Get-NetFirewallPortFilter
    $expectedProfiles = 3
    $recreateRule = (
        $rule.Direction -ne "Inbound" -or
        $rule.Action -ne "Allow" -or
        $rule.Profile -ne $expectedProfiles -or
        $portFilter.Protocol -ne "TCP" -or
        $portFilter.LocalPort -ne "8000"
    )
}

if ($recreateRule) {
    $existingRules | Remove-NetFirewallRule
    New-NetFirewallRule `
        -DisplayName $ruleName `
        -Direction Inbound `
        -Action Allow `
        -Protocol TCP `
        -LocalPort 8000 `
        -Profile Domain,Private `
        -Enabled True | Out-Null
    Write-Host "Created firewall rule: $ruleName"
}
else {
    Write-Host "Firewall rule is already configured: $ruleName"
}


