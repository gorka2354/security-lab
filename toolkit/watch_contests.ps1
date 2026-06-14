# watch_contests.ps1 -- run by Windows Task Scheduler (every few hours) to fire a desktop alert the moment a
# FRESH, in-scope audit contest in our zone launches (the timing edge). Quiet when there's nothing new.
# Register once via:  toolkit\register_contest_watch.ps1   (or schtasks, see that file).
$ErrorActionPreference = 'SilentlyContinue'
$repo = Split-Path -Parent $PSScriptRoot          # toolkit\..  = repo root
Set-Location $repo
New-Item -ItemType Directory -Path "$repo\monitor" -Force | Out-Null

$py = (Get-Command python).Source
if (-not $py) { $py = 'python' }
& $py "toolkit\contest_monitor.py" --alert *> "$repo\monitor\watch-last.log"
$code = $LASTEXITCODE

if ($code -eq 10) {
    $line = Get-Content "$repo\monitor\ALERTS.md" -Tail 1
    if (-not $line) { $line = "New fresh in-scope audit contest -- open Claude Code and /hunt it first-hours." }
    $body = $line.Substring(0, [Math]::Min(240, $line.Length))
    # primary: built-in NotifyIcon balloon (works from a logged-on user Task, no extra modules)
    try {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        $ni = New-Object System.Windows.Forms.NotifyIcon
        $ni.Icon = [System.Drawing.SystemIcons]::Information
        $ni.BalloonTipTitle = "security-lab: FRESH contest -> HUNT NOW"
        $ni.BalloonTipText = $body
        $ni.Visible = $true
        $ni.ShowBalloonTip(20000)
        Start-Sleep -Seconds 7
        $ni.Dispose()
    } catch {
        # fallback: a message box to the user's sessions (built-in, 100% reliable on Win Pro)
        msg * "security-lab FRESH contest: $body" 2>$null
    }
}
exit 0
