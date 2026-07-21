[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$NssmPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$serviceName = "CTIDashboard"
$displayName = "CTI Dashboard"

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )) {
        throw "Run this script from an elevated PowerShell session."
    }
}

function Invoke-Nssm {
    param([string[]]$NssmArguments)

    & $script:nssmExecutable @NssmArguments
    if ($LASTEXITCODE -ne 0) {
        throw "NSSM command failed with exit code $LASTEXITCODE."
    }
}

Assert-Administrator

$script:nssmExecutable = (Resolve-Path -LiteralPath $NssmPath).Path
if ([IO.Path]::GetFileName($script:nssmExecutable) -ne "nssm.exe") {
    throw "NssmPath must point to nssm.exe."
}
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    throw "Service $serviceName already exists. Uninstall it explicitly before reinstalling."
}

$projectDirectory = (Resolve-Path -LiteralPath (
    Join-Path $PSScriptRoot ".."
)).Path
$startScript = Join-Path $projectDirectory (
    "scripts\start-cti-dashboard.ps1"
)
if (-not (Test-Path -LiteralPath $startScript -PathType Leaf)) {
    throw "Startup script was not found: $startScript"
}

$logsDirectory = Join-Path $projectDirectory "logs"
if (-not (Test-Path -LiteralPath $logsDirectory)) {
    New-Item -ItemType Directory -Path $logsDirectory | Out-Null
}

$powerShellExecutable = Join-Path $env:SystemRoot (
    "System32\WindowsPowerShell\v1.0\powershell.exe"
)
$powerShellArguments = (
    "-NoProfile -NonInteractive -ExecutionPolicy Bypass " +
    "-File `"$startScript`""
)
$standardOutput = Join-Path $logsDirectory "cti-dashboard-stdout.log"
$standardError = Join-Path $logsDirectory "cti-dashboard-stderr.log"

Invoke-Nssm -NssmArguments @(
    "install", $serviceName, $powerShellExecutable
)
Invoke-Nssm -NssmArguments @(
    "set", $serviceName, "DisplayName", $displayName
)
Invoke-Nssm -NssmArguments @(
    "set", $serviceName, "Start", "SERVICE_AUTO_START"
)
Invoke-Nssm -NssmArguments @(
    "set", $serviceName, "AppDirectory", $projectDirectory
)
Invoke-Nssm -NssmArguments @(
    "set", $serviceName, "AppParameters", $powerShellArguments
)
Invoke-Nssm -NssmArguments @(
    "set", $serviceName, "AppStdout", $standardOutput
)
Invoke-Nssm -NssmArguments @(
    "set", $serviceName, "AppStderr", $standardError
)
Invoke-Nssm -NssmArguments @(
    "set", $serviceName, "AppRotateFiles", "1"
)
Invoke-Nssm -NssmArguments @(
    "set", $serviceName, "AppRotateOnline", "1"
)
Invoke-Nssm -NssmArguments @(
    "set", $serviceName, "AppRotateBytes", "10485760"
)
Invoke-Nssm -NssmArguments @(
    "set", $serviceName, "AppExit", "Default", "Restart"
)
Invoke-Nssm -NssmArguments @(
    "set", $serviceName, "AppRestartDelay", "5000"
)

& sc.exe failure $serviceName `
    "reset= 86400" `
    "actions= restart/5000/restart/5000/restart/5000"
if ($LASTEXITCODE -ne 0) {
    throw "Failed to configure Windows service recovery."
}
& sc.exe failureflag $serviceName "1"
if ($LASTEXITCODE -ne 0) {
    throw "Failed to enable Windows service recovery actions."
}

Write-Host "Installed $displayName ($serviceName) with Automatic startup."
Write-Host "The service was not started. Configure its Log On identity before starting it."
