#!/usr/bin/env bash
# sync-stand.sh - push the workstation's hunt outputs to the always-on mini-PC lab server, then refresh the
# dashboard's lab-state. Run after a hunt session so the Tailscale dashboard (http://100.81.218.50:8787)
# reflects new findings/verdicts.
#
# Ownership split (avoid two-writer clobber): the WORKSTATION owns findings/verdicts (registry, ledger,
# watch-targets, poc FINDING.md); the MINI-PC owns its monitor OUTPUT (watch-state, watch-events, dispatch-log
# -- written by its own crons). We push ONLY the workstation-owned files, never the stand-owned ones.
# The regenerable caches both sides refresh (programs / contacts / repo-meta) sync NEWEST-WINS both ways.
#
#   bash toolkit/sync-stand.sh
set -euo pipefail
STAND="${SECLAB_STAND:-egor@100.81.218.50}"
cd "$(dirname "$0")/.."

# Never sync stand->stand (the stand is the destination). Guards against SECLAB_AUTOSYNC firing on the mini-PC
# itself (env.sh is pushed there too), which would ssh to localhost and loop.
if [ "$(hostname 2>/dev/null)" = "egorka23" ]; then
    echo "[sync-stand] on the stand itself -> nothing to push"; exit 0
fi

# workstation-owned data + the dashboard code + the finding write-ups (stand-owned watch-*/dispatch-log excluded)
FILES=(toolkit web)
for f in registry.json REGISTRY.md triage-ledger.json watch-targets.json calibration.json links.json lab-state.json; do
    [ -f "monitor/$f" ] && FILES+=("monitor/$f")
done
while IFS= read -r p; do FILES+=("${p#./}"); done < <(find . -maxdepth 2 -name "FINDING.md" -path "*-poc*")
SSH=(ssh -o BatchMode=yes -o ConnectTimeout=12 "$STAND")

# SHARED regenerable caches have TWO writers -- the stand's 04:00 cron (programs.py fetch / contacts.py /
# gh_meta.py) and ad-hoc workstation runs -- so neither side owns them: the NEWEST copy wins, in both directions
# (tar keeps mtimes; --keep-newer-files never replaces a fresher file). Until 2026-09-25 they rode the overwrite
# push, so every sync replaced the stand's daily refresh with the workstation's weeks-old copy, and the
# workstation never saw a fresh one (programs.py list --open was reading an 08-26 store a month later).
SHARED=(monitor/programs.json monitor/contacts.json monitor/repo-meta.json)
NEWEST_WINS="--keep-newer-files --warning=no-ignore-newer"
if ! "${SSH[@]}" "cd ~/security-lab && tar czf - --ignore-failed-read ${SHARED[*]}" | tar xzf - $NEWEST_WINS; then
    echo "[sync-stand] WARN: could not pull the shared caches from the stand -- local copies may be stale" >&2
fi
PRESENT=(); for f in "${SHARED[@]}"; do [ -f "$f" ] && PRESENT+=("$f"); done
if [ ${#PRESENT[@]} -gt 0 ]; then
    tar czf - "${PRESENT[@]}" | "${SSH[@]}" "tar xzf - -C ~/security-lab $NEWEST_WINS"
fi
echo "[sync-stand] shared caches, newest wins:$(for f in "${PRESENT[@]}"; do printf ' %s@%s' "${f#monitor/}" "$(date -r "$f" +%m-%d_%H:%M)"; done)"

echo "[sync-stand] pushing ${#FILES[@]} path(s) -> $STAND ..."
# Remote: extract -> rebuild lab-state -> restart the dashboard ONLY IF toolkit code changed (the systemd
# service caches labstate/labcore in memory, so a .py change is invisible until restart; data-only syncs
# skip the restart so per-finding auto-syncs don't blip the dashboard). Hash guard via monitor/.toolkit-hash.
tar czf - "${FILES[@]}" \
  | "${SSH[@]}" \
      'tar xzf - -C ~/security-lab && cd ~/security-lab && . ~/.seclab_env \
       && python3 toolkit/labstate.py >/dev/null 2>&1 \
       && echo "[sync-stand] extracted + lab-state rebuilt ($(python3 -c "import json;print(len(json.load(open(\"monitor/lab-state.json\"))[\"findings\"]))") findings on the dashboard)" \
       && NEWH=$(cat toolkit/*.py 2>/dev/null | md5sum | cut -d" " -f1) \
       && OLDH=$(cat monitor/.toolkit-hash 2>/dev/null || echo none) \
       && if [ "$NEWH" != "$OLDH" ]; then echo "$NEWH" > monitor/.toolkit-hash; \
            (systemctl list-unit-files 2>/dev/null | grep -q seclab-dashboard \
             && sudo systemctl restart seclab-dashboard \
             && echo "[sync-stand] toolkit code changed -> dashboard service restarted") || true; \
          fi'
