[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-PositiveInteger {
    param(
        [AllowNull()]
        [string]$Value,
        [int]$Default,
        [int]$Maximum = [int]::MaxValue
    )

    $parsed = 0
    if (-not [int]::TryParse($Value, [ref]$parsed)) {
        return $Default
    }
    if ($parsed -lt 1 -or $parsed -gt $Maximum) {
        return $Default
    }
    return $parsed
}

try {
    $projectDirectory = (Resolve-Path -LiteralPath (
        Join-Path $PSScriptRoot ".."
    )).Path
    $waitressServe = Join-Path $projectDirectory (
        ".venv\Scripts\waitress-serve.exe"
    )
    if (-not (Test-Path -LiteralPath $waitressServe -PathType Leaf)) {
        throw "waitress-serve.exe was not found in the project virtual environment."
    }

    $listenHost = if ([string]::IsNullOrWhiteSpace($env:CTI_HOST)) {
        "0.0.0.0"
    }
    else {
        $env:CTI_HOST.Trim()
    }
    $listenPort = Get-PositiveInteger `
        -Value $env:CTI_PORT -Default 8000 -Maximum 65535
    $threadCount = Get-PositiveInteger `
        -Value $env:CTI_THREADS -Default 8

    $logsDirectory = Join-Path $projectDirectory "logs"
    if (-not (Test-Path -LiteralPath $logsDirectory)) {
        New-Item -ItemType Directory -Path $logsDirectory | Out-Null
    }

    Set-Location -LiteralPath $projectDirectory
    & $waitressServe `
        "--host=$listenHost" `
        "--port=$listenPort" `
        "--threads=$threadCount" `
        "--no-expose-tracebacks" `
        "wsgi:app"

    if ($LASTEXITCODE -ne 0) {
        throw "Waitress exited with code $LASTEXITCODE."
    }
    exit 0
}
catch {
    Write-Error "CTI Dashboard startup failed: $($_.Exception.Message)"
    exit 1
}
