#!/bin/zsh
# watch_all.sh - one-shot watcher for the Mac cron lane (every 4h).
# Runs the parked-findings watch (watchlist.json) + the audit-contest monitor, and appends any
# FIREs/NEW contests to monitor/ALERTS.md. Exit 10 if anything fired (cron-friendly).
# Install: see the crontab line printed by `toolkit/watch_all.sh --install-hint`.
set -u
ROOT="${0:A:h:h}"   # repo root (this script is in toolkit/)
cd "$ROOT" || exit 1
export PATH="/opt/homebrew/bin:$HOME/.foundry/bin:$PATH"
# pick up ETHERSCAN_API_KEY etc. from the login shell profile (cron has a bare env)
[ -f "$HOME/.zshrc" ] && source "$HOME/.zshrc" 2>/dev/null
PY="$(command -v python3)"
STAMP="$(date '+%Y-%m-%d %H:%M')"

if [ "${1:-}" = "--install-hint" ]; then
  echo "Add to 'crontab -e' (runs every 4h, on the hour):"
  echo "0 */4 * * * $ROOT/toolkit/watch_all.sh >> $ROOT/monitor/watch-cron.log 2>&1"
  exit 0
fi

fired=0
ALERTS="$ROOT/monitor/ALERTS.md"

echo "=== watch_all $STAMP ==="

# 0) refresh the registry projection (cheap; keeps firstseen/lastupdated current)
"$PY" toolkit/registry.py >/dev/null 2>&1

# 0b) radar: impl-upgrade + bounty-launch over the registry -> hunts/_radar/QUEUE.md (exit 10 if NEW)
ROUT="$("$PY" toolkit/radar.py 2>&1)"; rrc=$?
echo "$ROUT"
if [ $rrc -eq 10 ]; then
  fired=1
  { echo ""; echo "## [RADAR] $STAMP -- new change(s) queued, see hunts/_radar/QUEUE.md"; echo '```'; echo "$ROUT"; echo '```'; } >> "$ALERTS"
fi

# 0c) fresh-deploy radar: new contracts from watched deployers/factories -> FRESH-DEPLOY.md (the freshness edge)
FOUT="$("$PY" toolkit/freshdeploy.py 2>&1)"; frc=$?
echo "$FOUT"
if [ $frc -eq 10 ]; then
  fired=1
  { echo ""; echo "## [FRESH-DEPLOY] $STAMP -- new deploy(s), see hunts/_radar/FRESH-DEPLOY.md"; echo '```'; echo "$FOUT"; echo '```'; } >> "$ALERTS"
fi

# 1) parked findings (exit 2 if any FIRED)
WOUT="$("$PY" toolkit/watch.py 2>&1)"; wrc=$?
echo "$WOUT"
if [ $wrc -eq 2 ]; then
  fired=1
  { echo ""; echo "## [WATCH FIRED] $STAMP"; echo '```'; echo "$WOUT" | grep -A3 FIRED; echo '```'; } >> "$ALERTS"
fi

# 2) audit-contest monitor (exit 10 if a NEW+FRESH+our-zone contest -> it writes ALERTS.md itself)
"$PY" toolkit/contest_monitor.py --alert >/dev/null 2>&1; crc=$?
[ $crc -eq 10 ] && fired=1 && echo "contest_monitor: NEW fresh contest -> see monitor/ALERTS.md"

[ $fired -eq 1 ] && echo ">>> something FIRED - check monitor/ALERTS.md" && exit 10
echo "all quiet."
exit 0
