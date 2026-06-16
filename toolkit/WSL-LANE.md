# WSL dynamic-layer lane (L2 Slither + L3 fuzz/symbolic)

The dynamic + symbolic layer (Slither, Echidna/Medusa, Halmos) does NOT install on this Windows box
(no MSVC -> `safe-pysha3`/native builds fail). It DOES install cleanly in **WSL Ubuntu**. This lane turns
L2 + symbolic from "aspirational / CI-only" into runnable locally. Verified 2026-06-10 (Ubuntu 22.04,
Python 3.10, gcc 11.4, forge 1.7.1, slither 0.11.5, halmos 0.1.13, solc 0.8.24).

The repo is reachable from WSL at `/mnt/c/Users/pesto/Desktop/security-lab` (run the Python toolkit straight
off the Windows checkout -- no copy). Per-target clones live under `hunts/_volume/`.

## One-time setup (in WSL)
```sh
# from a WSL Ubuntu shell:
python3 -m venv ~/seclab && source ~/seclab/bin/activate
pip install -U pip wheel
pip install halmos slither-analyzer solc-select        # halmos pulls z3; safe-pysha3 builds w/ gcc
solc-select install 0.8.24 && solc-select use 0.8.24   # match the target's pragma

# Foundry (halmos needs `forge build`):
curl -L https://foundry.paradigm.xyz | bash
~/.foundry/bin/foundryup
```

## Per-use (PATH for the lane)
```sh
export PATH="$HOME/seclab/bin:$HOME/.foundry/bin:$PATH"   # venv tools + forge
```
(`source ~/seclab/bin/activate` can be flaky under non-interactive `bash -lc`; putting the venv bin on PATH
explicitly is the reliable form.)

## L2 -- Slither + the L1n L2 corroboration (`analyze.py`)
```sh
R=/mnt/c/Users/pesto/Desktop/security-lab
python3 $R/toolkit/analyze.py <repo>          # recon (L1) + slither (L2) + spots flagged by BOTH (high-confidence)
slither <file.sol>                            # raw slither on a single standalone file
```
`analyze.py`'s headline feature (leads flagged by BOTH recon AND Slither at the same line) only works when
Slither runs -- i.e. here, not on Windows. **Slither must COMPILE the target**: a standalone file works as-is;
a hardhat/foundry monorepo (e.g. Mezo MUSD) needs its deps first (`cd <repo>/solidity && pnpm install`), else
slither degrades to recon-only ("did the target compile?").

## L3 symbolic -- Halmos (`scaffold.py --engine halmos`)
```sh
# generate the symbolic suite from a contract (on Windows or WSL):
python toolkit/scaffold.py <Contract.sol> <Name> --engine halmos --out <foundry-proj>/test
# then in WSL, inside a foundry project (foundry.toml + src/ + the check_ file):
halmos --function check_                       # makes args symbolic, PROVES the assert on ALL inputs
```
Halmos compiles via `forge build`, so it needs a foundry project (foundry.toml + src/; forge-std only if the
harness imports it). It auto-fetches the right solc.

## L3 fuzz -- Echidna / Medusa (`scaffold.py --engine chimera`)
Install the engines (precompiled Linux binaries -> `~/seclab/bin`):
```sh
curl -sL https://github.com/crytic/medusa/releases/download/v1.5.1/medusa-linux-x64.tar.gz | tar xz -C ~/seclab/bin
curl -sL https://github.com/crytic/echidna/releases/download/v2.3.2/echidna-2.3.2-x86_64-linux.tar.gz | tar xz -C ~/seclab/bin
```
Running a `scaffold.py --engine chimera` harness (props are `property_*`, the harness lives in `test/recon/`):
```sh
forge test --mc CryticToFoundry                                              # Foundry: the invariants + repro test
echidna . --contract CryticTester --config test/recon/echidna.yaml \
         --crytic-args "--foundry-compile-all"                               # --foundry-compile-all = include test/
medusa fuzz --config test/recon/medusa.json                                  # second engine
```
Two gotchas the generated configs now handle (found by dogfooding): echidna needs `prefix: "property_"` (else it
looks for `echidna_*` and tests nothing), and `--foundry-compile-all` so crytic-compile sees the test/ contracts.

For a hardhat/foundry target with its OWN echidna harness (e.g. MUSD's `EchidnaTest`, `echidna_*` prefix),
crytic-compile builds it (needs deps + a `.env` if the config uses dotenv-safer):
```sh
cd <repo>/solidity && cp -n .env.example .env && npx hardhat compile   # warm the solc cache (avoids transient HH502)
echidna . --config echidna.yaml --contract <TestContract>              # their property mode: echidna_* invariants
```
**Harness portability:** an echidna-tuned harness (specific deployer/senders + `balanceContract`) often REVERTS
on medusa's deploy model. That's the whole point of `scaffold.py --engine chimera`: ONE portable harness +
matching `echidna.yaml` + `medusa.json`, so both engines run the same `property_*`.

## Decompilation -- the UNVERIFIED-code lane (`reach_bytecode.py` -> panoramix -> `decompile_match.py`)

The ThetaNuts response: when `fetch_source` returns "no verified source", recover the bytecode and go
deeper. `reach_bytecode.py` (pure-Python, runs ON WINDOWS) recovers the function SURFACE from `eth_getCode`.
To get the MATH you must DECOMPILE -- and panoramix needs `signal.SIGALRM`/`setitimer` (Unix-only) so it
does NOT run natively on Windows. It runs in WSL.

> [!] **Do NOT `pip install panoramix-decompiler` on the Windows Python.** It pulls `web3==6.0.0b8` (an old
> beta) into the --user site, which SHADOWS the working global web3 and crashes on `import pkg_resources`
> (gone in 3.12) -> breaks `activity._selector` -> the golden suite goes red. If it happened:
> `pip uninstall -y panoramix-decompiler web3` restores the global web3 (6.20.0). Keep panoramix in WSL ONLY.

```sh
# in WSL: install panoramix once (Python 3.10 there has SIGALRM; isolate it, don't pollute)
wsl python3 -m pip install --user panoramix-decompiler
# RPCs are blocked from this box, so feed bytecode via a file (fetch it on Windows with Etherscan):
python toolkit/reach_bytecode.py <addr> <chain>          # WINDOWS: surface triage -> [!] vault-shaped?
#   (reach_bytecode writes the code; or: python -c "...get_code(addr)->_x.hex")
wsl bash -c "cd /mnt/c/.../security-lab && python3 toolkit/_decompile_probe.py <code.hex> - <out.txt>"
python toolkit/decompile_match.py <out.txt>              # WINDOWS: share-inflation matcher on the pseudocode
```
`decompile_match.py` is pure-regex (runs on Windows on the resulting text). panoramix is OLD (~2020): it
chokes on modern Solidity dispatchers (0.8.x metadata) -> `_fallback`-only, but decompiles OLDER bytecode
(ThetaNuts' era) well -- and it RESOLVES `totalSupply` by name, so the share-conversion `<backing> * <amt>
/ totalSupply` survives. Frontier still open: bytecode whose `totalSupply` panoramix can't name -> a
slot-based pass (which `storN` is the supply counter, incremented on mint?) is the next layer.

> [!] **heimdall is network-blocked on this box (2026-06-16).** bifrost native-Windows wants cargo (no Rust/MSVC); WSL has NO outbound network (bifrost downloads nothing); the github RELEASE-ASSET CDN (release-assets.githubusercontent.com) is blocked even though the github API answers. To get heimdall: download `heimdall-linux-amd64` via a real browser, drop it in the repo, `chmod +x` it in WSL. Until then panoramix (WSL) is the decompiler -- fine for older bytecode, weak on modern 0.8.x.

## Proven decompile (2026-06-16, the ThetaNuts frontier)
- `reach_bytecode.py 0xC2C3AE0a` (Windows) -> recovered **36/50 signatures** from raw unverified bytecode
  (deposit/withdraw/mint/claim/rebalance/vaults/Aave) -> `[!] UNVERIFIED but VAULT-SHAPED`.
- panoramix in WSL decompiled the 12,494-byte ThetaNuts -> 71KB pseudocode, `totalSupply` named.
- `decompile_match.py` on the dump -> **`[!] 18 proportional `backing * amount / totalSupply` sites, NO
  dead-shares guard -> round-to-zero / inflated redeem (ThetaNuts class)`**. End-to-end: an UNVERIFIED live
  contract triaged from bytecode all the way to the share-inflation math. Modern-Solidity PoC bytecode
  (0.8.35) decompiled to `_fallback` only -> panoramix's age is the limit, not the approach.

## Proven (2026-06-10)
- `slither HalmosDemo.sol` -> analyzed (101 detectors); `analyze.py ~/seclab-demo` -> L1 recon + L2 slither +
  corroboration section, all in WSL.
- `halmos --function check_dec` on a planted `unchecked { x -= a; }` underflow -> **Counterexample `a = 2^256-1`**.
- **Live on a real audited target (Mezo MUSD, cloned to `~/musd`, `pnpm install` + node 20):**
  - `slither .` on the whole MUSD -> **112 contracts, 96 results, 0 High/Medium** (clean, as expected for
    Cantina-audited Liquity-fork code). First L2 run on a real target locally.
  - `echidna . --config echidna.yaml --contract EchidnaTest` -> compiled in 18.5s, fuzzed 30k seqs (cov 65,727),
    **all 4 invariants PASSING incl `echidna_sum_of_debt`** (the hunt residual -> held at this depth).
  - medusa 1.5.1 installed + compiles MUSD, but the echidna-tuned harness reverts on its deploy model
    (use a chimera harness for both).
- **Chimera portability proven end-to-end (`scaffold.py --engine chimera` on StakingRewards):** ONE generated
  harness ran under **Foundry + Echidna + Medusa**. FIXED -> all green (Foundry 6/6, echidna 5/5, medusa 9/9);
  flip `BUGGY=true` -> **all three catch the planted insolvency** (`property_solvency` fails on echidna+medusa
  after a ~7-day time warp; Foundry's deterministic `test_solvency_after_duration` confirms it). Dogfooding this
  fixed the generated echidna.yaml (`prefix: "property_"`) and documented `--foundry-compile-all`.
- `forge 1.7.1` builds; node 20.20.2 + pnpm 8.13.1 for hardhat targets.

See [windows-dynamic-layer-needs-linux-lane] memory + `ROADMAP.md` (L3 row). ASCII only.
