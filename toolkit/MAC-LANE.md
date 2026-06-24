# MAC-LANE — running the engine on macOS (Apple Silicon)

Notes for working from a Mac (vs the Windows/WSL lane). Verified 2026-06-24, macOS arm64, engine green.

## The one gotcha: this network blocks the GitHub CDN
`github.com` and `ghcr.io` work, but **`raw.githubusercontent.com` and `objects.githubusercontent.com`
are reset/timed-out** (VPN/firewall). That breaks the two "official" install paths:
- `curl -L https://foundry.paradigm.xyz | bash` -> redirects to raw.githubusercontent -> RESET.
- `forge` auto-installing `solc` -> fetches the version list from raw.githubusercontent -> RESET.

**Fix: install everything via Homebrew (pours from ghcr.io, which works).**

## Setup (one-time)
```
brew install foundry      # forge/cast/anvil -> /opt/homebrew/bin (already on PATH; no ~/.foundry/bin)
brew install solidity     # system solc; brew's version matched the pinned 0.8.35 exactly
pip3 install web3         # the activity.py selector-hashing path + test suite SystemExit(1) without it
```
- No `export PATH="$HOME/.foundry/bin:$PATH"` needed on Mac — brew puts forge on PATH directly.
  (That CLAUDE.md note is Windows/WSL-only.)

## Building / testing a PoC
1. PoCs expect `forge-std` in `lib/` but it is NOT vendored and these are NOT real submodules of the
   parent repo (the `.gitmodules` is just a file). Clone it per PoC:
   `git clone --depth 1 https://github.com/foundry-rs/forge-std <poc>/lib/forge-std`  (github.com = OK)
2. Point forge at the system solc and skip the CDN:
   `forge test -vv --use /opt/homebrew/bin/solc --offline`
   - `--use <path>` = use the brew solc binary (skips svm download).
   - `--offline` = don't hit the version-list CDN.
   - Optional ergonomics: `alias forget='forge test --use /opt/homebrew/bin/solc --offline'`.

## Smoke test (proves the stack)
```
cd nomad-poc && git clone --depth 1 https://github.com/foundry-rs/forge-std lib/forge-std
forge test -vv --use /opt/homebrew/bin/solc --offline   # -> 2 passed (exploit drains bridge, fix reverts)
python3 toolkit/recon.py nomad-poc/src                   # -> recon report (python toolkit needs no forge)
```

## If the CDN block ever lifts
The normal `foundryup` + auto-solc path works fine; this lane is only for the blocked-CDN network.
