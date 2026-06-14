<#
.SYNOPSIS
    Install the repo-forensics threat-DB refresh task on Windows.

.DESCRIPTION
    Windows equivalent of hooks/install_refresh_daemon.sh (which uses launchd on
    macOS). Registers a daily Windows Scheduled Task (plus one run at install)
    that runs refresh_threat_dbs.py in the background so the SessionStart hook
    stays fast and the IOC + CISA KEV caches stay current.

    Safe to run multiple times (re-registers with -Force).
    Set REPO_FORENSICS_DISABLE_REFRESH=1 in the environment to skip refreshing
    without uninstalling (the Python script honors the same kill switch).

    Uninstall: powershell -ExecutionPolicy Bypass -File hooks\uninstall_refresh_task.ps1

    Windows only. No admin rights required: the task is registered for the
    current user, mirroring the per-user macOS LaunchAgent.
#>

$ErrorActionPreference = 'Stop'
$TaskName = 'repo-forensics-refresh'

if ($env:OS -ne 'Windows_NT') {
    Write-Error '[install] This installer is Windows-only. On macOS use install_refresh_daemon.sh.'
    exit 1
}

# 1) Resolve a working Python 3. Each candidate is executed (not just located)
#    because Windows ships a fake python/python3 "App execution alias" that
#    exists on PATH but only prints a Microsoft Store nag and exits non-zero.
function Resolve-Python {
    $candidates = @(
        @{ Exe = 'py';      Pre = @('-3') },
        @{ Exe = 'python';  Pre = @() },
        @{ Exe = 'python3'; Pre = @() }
    )
    foreach ($c in $candidates) {
        $cmd = Get-Command $c.Exe -ErrorAction SilentlyContinue
        if (-not $cmd) { continue }
        $probe = @() + $c.Pre + @('-c', 'import sys; sys.exit(0 if sys.version_info[0] >= 3 else 1)')
        try {
            & $c.Exe @probe 2>$null
            if ($LASTEXITCODE -eq 0) {
                return [pscustomobject]@{ Path = $cmd.Source; Pre = $c.Pre }
            }
        } catch { }
    }
    return $null
}

$py = Resolve-Python
if (-not $py) {
    Write-Error '[install] No working Python 3 found (tried: py -3, python, python3).'
    exit 1
}

# 2) Resolve refresh_threat_dbs.py: prefer the newest copy under the plugin
#    cache, then fall back to this repo (source-tree / dev install).
$scriptRel = 'skills\repo-forensics\scripts\refresh_threat_dbs.py'
$scriptPath = $null

$cacheRoot = Join-Path $env:USERPROFILE '.claude\plugins\cache'
if (Test-Path $cacheRoot) {
    $hit = Get-ChildItem -Path $cacheRoot -Recurse -Filter 'refresh_threat_dbs.py' -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match 'repo-forensics' } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if ($hit) { $scriptPath = $hit.FullName }
}

if (-not $scriptPath) {
    $here = Split-Path -Parent $MyInvocation.MyCommand.Path
    $candidate = Join-Path (Split-Path -Parent $here) $scriptRel
    if (Test-Path $candidate) { $scriptPath = (Resolve-Path $candidate).Path }
}

if (-not $scriptPath -or -not (Test-Path $scriptPath)) {
    Write-Error "[install] refresh_threat_dbs.py not found (searched plugin cache and $scriptRel)."
    exit 1
}

# 3) Build the task action. Quote the script path; prepend any interpreter
#    prefix (e.g. -3 for the py launcher).
$argParts = @() + $py.Pre + @("`"$scriptPath`"")
$argString = [string]::Join(' ', $argParts)

$action = New-ScheduledTaskAction -Execute $py.Path -Argument $argString

# Daily refresh. -StartWhenAvailable (below) catches up a run missed while the
# machine was off, and the one-time Start-ScheduledTask after registration
# populates the caches at install; together these cover what the macOS
# LaunchAgent's RunAtLoad provides, without needing admin (an -AtLogOn trigger
# would default to all-users and require elevation). Battery/network tolerances
# match its low-priority background intent. Explicit [datetime] avoids fragile
# bareword parsing of the -At argument.
$trigger = New-ScheduledTaskTrigger -Daily -At ([datetime]'03:00')
$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 5) `
    -MultipleInstances IgnoreNew

# Per-user, no stored password, no admin. LogonType Interactive means the task
# runs only while the user is logged in, which intentionally matches the
# per-user macOS LaunchAgent (gui/$UID).
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited

# 4) Register (idempotent).
Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Principal $principal `
    -Description 'repo-forensics: daily IOC + CISA KEV threat database refresh.' `
    -Force | Out-Null

# Mirror launchd RunAtLoad: kick one refresh now so the IOC/KEV caches populate
# immediately instead of waiting for the first scheduled trigger. Non-fatal if
# it cannot start; the daily and logon triggers still cover it.
try { Start-ScheduledTask -TaskName $TaskName } catch { }

$logPath = Join-Path $env:USERPROFILE '.cache\repo-forensics\refresh.log'
Write-Host "[install] OK: scheduled task '$TaskName' registered (daily, ran once now)."
Write-Host "[install] Python:  $($py.Path) $($py.Pre -join ' ')"
Write-Host "[install] Script:  $scriptPath"
Write-Host "[install] Logs:    $logPath"
Write-Host "[install] Check:   schtasks /Query /TN $TaskName"
Write-Host "[install] Disable: set REPO_FORENSICS_DISABLE_REFRESH=1, or run uninstall_refresh_task.ps1"
