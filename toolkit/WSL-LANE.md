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
```sh
# generate the chimera harness (Foundry+Echidna+Medusa from one harness):
python toolkit/scaffold.py <Contract.sol> <Name> --engine chimera --out <proj>/test/recon
# install the engines in WSL (Go/Rust; heavier than the pip tools):
#   medusa: https://github.com/crytic/medusa (Go binary)   echidna: https://github.com/crytic/echidna (or docker)
forge test --mc CryticToFoundry        # the SAME handlers/properties under Foundry
echidna . --contract CryticTester --config echidna.yaml
medusa fuzz
```

## Proven (2026-06-10)
- `slither HalmosDemo.sol` -> analyzed (101 detectors).
- `python3 analyze.py ~/seclab-demo` -> L1 recon + L2 slither + corroboration section, all in WSL.
- `halmos --function check_dec` on a planted `unchecked { x -= a; }` underflow -> **Counterexample
  `a = 2^256-1`** (symbolic lane catches the bug it should).
- `forge 1.7.1` builds.

See [windows-dynamic-layer-needs-linux-lane] memory + `ROADMAP.md` (L3 row). ASCII only.
