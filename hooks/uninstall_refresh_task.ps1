<#
.SYNOPSIS
    Remove the repo-forensics threat-DB refresh scheduled task on Windows.

.DESCRIPTION
    Windows equivalent of hooks/uninstall_refresh_daemon.sh. Safe to run even if
    the task was never installed.
#>

$ErrorActionPreference = 'Stop'
$TaskName = 'repo-forensics-refresh'

$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existing) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "[uninstall] Removed scheduled task '$TaskName'."
} else {
    Write-Host "[uninstall] No scheduled task '$TaskName' found (nothing to do)."
}
