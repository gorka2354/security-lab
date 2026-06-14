# register_contest_watch.ps1 -- (re)register the Windows Task that runs watch_contests.ps1 every 4 hours.
# This is the TIMING EDGE made always-on: a desktop balloon fires the moment a fresh, in-scope audit contest
# in our zone launches (Cantina/Sherlock/Code4rena), even when Claude Code is closed. Quiet otherwise.
#
#   Install:    powershell -ExecutionPolicy Bypass -File toolkit\register_contest_watch.ps1
#   Test now:   Start-ScheduledTask -TaskName 'security-lab-contest-watch'
#   Logs:       monitor\watch-last.log  (last scan)   monitor\ALERTS.md  (alert history)
#   Remove:     Unregister-ScheduledTask -TaskName 'security-lab-contest-watch' -Confirm:$false
#
# Runs as the current user, only when logged on (so the balloon can render). 10-min run cap; catches up a
# missed run (-StartWhenAvailable). Adjust cadence by editing -RepetitionInterval below.
$ps1 = Join-Path $PSScriptRoot 'watch_contests.ps1'
$action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$ps1`""
$trigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(2)) -RepetitionInterval (New-TimeSpan -Hours 4)
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
Register-ScheduledTask -TaskName 'security-lab-contest-watch' -Action $action -Trigger $trigger -Settings $settings `
  -Description 'security-lab: alert on fresh in-scope audit contests (timing edge)' -Force | Out-Null
Write-Host "registered 'security-lab-contest-watch' -- every 4h. Test: Start-ScheduledTask -TaskName security-lab-contest-watch"
