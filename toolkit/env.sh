# security-lab env — source this so forge/solc/python + the Etherscan key are always on hand.
#   source toolkit/env.sh
# Fixes the recurring friction: forge/solc not on PATH, and PATH getting clobbered mid-session
# (e.g. by the browse skill). Idempotent; safe to source repeatedly.

# core dirs first so coreutils survive a clobber, then brew + foundry
export PATH="/opt/homebrew/bin:$HOME/.foundry/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"

# Etherscan v2 key (a free key) — recover from ~/.zshrc if not already exported
if [ -z "$ETHERSCAN_API_KEY" ]; then
  export ETHERSCAN_API_KEY="$(grep -hoE 'ETHERSCAN_API_KEY=[A-Za-z0-9]+' "$HOME/.zshrc" 2>/dev/null | head -1 | cut -d= -f2)"
fi

# Auto-push findings/verdicts to the always-on mini-PC dashboard the moment they are logged (labcore._autosync).
# Debounced + best-effort; the stand guards against syncing itself (sync-stand.sh hostname check). Unset to disable.
export SECLAB_AUTOSYNC=1

# one-line status so a sourced shell knows what it has
printf 'env: forge=%s solc=%s python3=%s etherscan-key=%s\n' \
  "$(command -v forge >/dev/null 2>&1 && forge --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo MISSING)" \
  "$(command -v solc  >/dev/null 2>&1 && solc  --version 2>/dev/null | awk -F'[ +]' '/Version/{print $2}' || echo MISSING)" \
  "$(command -v python3 >/dev/null 2>&1 && echo ok || echo MISSING)" \
  "$([ -n "$ETHERSCAN_API_KEY" ] && echo set || echo MISSING)"
