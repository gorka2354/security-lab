# Mini-PC dynamic/symbolic lane (standalone Linux)

The dynamic + symbolic fuzzing layer that does **not** install on the Windows box (no MSVC) runs on the
mini-PC test stand (`egor@100.81.218.50` via Tailscale, Ubuntu 24.04.4, 16c/19GB). This is the sibling of
`WSL-LANE.md` for a real standalone Linux host (no `wsl -d` prefix; normal `~` clone path). Set up + proven
working end-to-end 2026-08-15.

## Installed (all on PATH via ~/.bashrc; versions verified)

| Tool | Version | Install | Smoke |
|------|---------|---------|-------|
| Foundry (forge/anvil/cast/chisel) | 1.7.1 | `curl -L https://foundry.paradigm.xyz \| bash && foundryup` (→ `~/.foundry/bin`) | `forge --version` |
| slither | 0.11.6 | `pipx install slither-analyzer` (→ `~/.local/bin`) | `slither --version` |
| crytic-compile | 0.4.2 | `pipx install crytic-compile` | `crytic-compile --version` |
| solc-select + solc | 0.6.12…0.8.30 (default 0.8.28) | `pipx install solc-select` then `solc-select install <v>` | `solc --version` |
| echidna | 2.3.3 | prebuilt static binary → `/usr/local/bin/echidna` (sha256-pinned) | `echidna --version` |
| medusa | 1.5.1 | prebuilt binary → `~/.local/bin/medusa` (sha256-pinned) | `medusa --version` |
| halmos | 0.3.3 | `pipx install halmos` | `halmos --version` |
| ityfuzz | nightly-35b7f08 (EVM, Etherscan-v2) | `curl -L https://ity.fuzz.land/install.sh \| bash && ityfuzzup --version nightly-35b7f08962fdd0c2e02df7ef8a43164913d514d9` (→ `~/.ityfuzz/bin`) | `ityfuzz --help` |

`base` apt deps installed: build-essential pkg-config libssl-dev clang cmake unzip jq python3-dev python3-venv.
No Go/Rust toolchain needed — every fuzzer is a prebuilt binary. Docker 29.6.2 present (echidna has a Docker
fallback image if ever needed).

## Env + keys

- `~/.seclab_env` (chmod 600, NEVER committed) holds `ETHERSCAN_API_KEY` (Etherscan-v2) + `ETH_RPC_URL`.
  It is sourced from `~/.bashrc`. For non-interactive SSH runs, `source ~/.seclab_env` explicitly.
- The toolkit reads `ETHERSCAN_API_KEY` from the environment (never a file/commit).

## Running the lanes

Property/assertion fuzzing (echidna + medusa) + symbolic (halmos) on a local harness — proven on
`~/seclab-smoke/` (a planted sequence bug `inc()x3 → trigger(42) ⇒ pwned`), all three FOUND it
(echidna "falsified", medusa "[FAILED]", halmos counterexample `x = 0x2a`):

```bash
cd <foundry-project>
echidna . --contract CryticTester --config echidna.yaml --format text
medusa fuzz --config medusa.json
halmos --function check_<name>
forge test
```

Dynamic **on-chain fork-fuzz** (the headline: auto-find fund-loss on a LIVE contract) via the repo wrapper:

```bash
source ~/.seclab_env
python3 toolkit/ityfuzz_lane.py <ADDRESS> --chain eth --block <N> --timeout 600
# proven: WETH fork -> ABI(v2) fetch -> deploy -> fuzz, 50% instruction coverage, corpus written.
```

## ⚠️ ityfuzz nightly-35b7f08 gotchas (calibrated live)

1. **`--onchain-url` is IGNORED** by this build — `endpoint_url` stays the hardcoded per-chain default
   (`Chain::ETH → https://eth.merkle.io`, which now **403s**), so a bare onchain run panics
   `fail to get block timestamp` at `endpoints.rs:1092`. The override that IS read is the **`ETH_RPC_URL`**
   env var (`get_chain_rpc` checks it first, for every chain). `ityfuzz_lane.py` now injects it
   automatically (from `--rpc` / `ETH_RPC_URL` / a built-in publicnode `DEFAULT_RPC` map).
2. The stale-nightly-tag trap: bare `ityfuzzup` installs a ~2024 build predating Etherscan-v2. Always pin
   `nightly-35b7f08962fdd0c2e02df7ef8a43164913d514d9`.
3. Free public RPCs (publicnode) can rate-limit ityfuzz's storage-fetch burst → an occasional late panic
   (the campaign still ran + wrote coverage first; the lane parses partial output gracefully). A less
   rate-limited RPC removes it. Set a better one in `~/.seclab_env` `ETH_RPC_URL` if needed.
4. Non-eth chains: the Etherscan-v2 key is native on api.etherscan.io/v2 for ETH; per-chain ABI fetch may
   need a chain-native key or `--onchain-explorer-url` — verify empirically per chain.

## Not installed (deliberately)

heimdall (decompiler) — glibc-coupled manual binary, install on demand per `WSL-LANE.md` (0.9.x needs
glibc 2.39 = Ubuntu 24.04, which this box is). panoramix — must be an ISOLATED python env (drags old web3).
