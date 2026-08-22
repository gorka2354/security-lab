#!/usr/bin/env bash
# sync-stand.sh - push the workstation's hunt outputs to the always-on mini-PC lab server, then refresh the
# dashboard's lab-state. Run after a hunt session so the Tailscale dashboard (http://100.81.218.50:8787)
# reflects new findings/verdicts.
#
# Ownership split (avoid two-writer clobber): the WORKSTATION owns findings/verdicts (registry, ledger,
# watch-targets, poc FINDING.md); the MINI-PC owns its monitor OUTPUT (watch-state, watch-events, dispatch-log
# -- written by its own crons). We push ONLY the workstation-owned files, never the stand-owned ones.
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
for f in registry.json REGISTRY.md triage-ledger.json watch-targets.json programs.json calibration.json links.json repo-meta.json lab-state.json; do
    [ -f "monitor/$f" ] && FILES+=("monitor/$f")
done
while IFS= read -r p; do FILES+=("${p#./}"); done < <(find . -maxdepth 2 -name "FINDING.md" -path "*-poc*")

echo "[sync-stand] pushing ${#FILES[@]} path(s) -> $STAND ..."
tar czf - "${FILES[@]}" \
  | ssh -o BatchMode=yes -o ConnectTimeout=12 "$STAND" \
      'tar xzf - -C ~/security-lab && cd ~/security-lab && . ~/.seclab_env \
       && python3 toolkit/labstate.py >/dev/null 2>&1 \
       && echo "[sync-stand] extracted + lab-state rebuilt ($(python3 -c "import json;print(len(json.load(open(\"monitor/lab-state.json\"))[\"findings\"]))") findings on the dashboard)"'
