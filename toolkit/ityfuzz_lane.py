#!/usr/bin/env python3
"""ityfuzz_lane.py - DYNAMIC fork-fuzz lane (Tier-2 #1 of research/tooling-research/ROADMAP.md).

ItyFuzz (MIT, fuzzland) is a snapshot/bytecode-level fuzzer that AUTO-FINDS exploits on a FORKED on-chain
contract: it has an economic oracle (detects profit/fund-loss) and works on UNVERIFIED bytecode - hitting
both of our worst gaps at once. This wraps it as the post-DIG auto-confirm / auto-find step: point it at a
live address + chain + block, it fuzzes for fund-loss / arbitrary-call / selfdestruct / invariant bugs, and
we parse the result into a structured finding.

    python toolkit/ityfuzz_lane.py 0xADDR --chain eth --block 19000000 [--timeout 600] [--no-flashloan]
    python toolkit/ityfuzz_lane.py --check                 # is ityfuzz installed?

Graceful when ityfuzz is absent (prints the install path, never crashes the pipeline). build_cmd +
parse_output are pure -> golden-tested; we calibrate the exact flags/markers against real output on install.
Install (Mac/Linux, prebuilt binary): curl -L https://ity.fuzz.land/install.sh | bash && ityfuzzup
Stdlib only. White-hat: fuzz only in-scope authorized targets on a FORK (no mainnet txs).
"""
import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys

# ItyFuzz onchain mode takes chain NAMES (ETH/BSC/...), not chain ids.
CHAIN = {"eth": "ETH", "ethereum": "ETH", "bsc": "BSC", "bnb": "BSC", "polygon": "POLYGON", "matic": "POLYGON",
         "arbitrum": "ARBITRUM", "arb": "ARBITRUM", "base": "BASE", "optimism": "OPTIMISM", "op": "OPTIMISM",
         "avalanche": "AVALANCHE", "avax": "AVALANCHE", "fantom": "FANTOM", "ftm": "FANTOM", "blast": "BLAST"}

# Known-good public fork RPCs by chain name -> injected as ETH_RPC_URL (the build's real override; see run()).
# Keeps `ityfuzz_lane.py <addr> --chain eth` working out-of-box without a manual --rpc.
DEFAULT_RPC = {"eth": "https://ethereum-rpc.publicnode.com", "ethereum": "https://ethereum-rpc.publicnode.com",
               "bsc": "https://bsc-rpc.publicnode.com", "bnb": "https://bsc-rpc.publicnode.com",
               "polygon": "https://polygon-bor-rpc.publicnode.com", "matic": "https://polygon-bor-rpc.publicnode.com",
               "arbitrum": "https://arbitrum-one-rpc.publicnode.com", "arb": "https://arbitrum-one-rpc.publicnode.com",
               "base": "https://base-rpc.publicnode.com", "optimism": "https://optimism-rpc.publicnode.com",
               "op": "https://optimism-rpc.publicnode.com", "avalanche": "https://avalanche-c-chain-rpc.publicnode.com",
               "avax": "https://avalanche-c-chain-rpc.publicnode.com", "fantom": "https://fantom-rpc.publicnode.com",
               "ftm": "https://fantom-rpc.publicnode.com", "blast": "https://blast-rpc.publicnode.com"}

# bug/objective markers ItyFuzz prints when it finds something (heuristic, version-tolerant superset)
# calibrated against REAL ItyFuzz find output (echidna invariant: "Found vulnerabilities! [Echidna]: Invariant
# "x" violated"). `violat` + `vulnerab` + `echidna` all fire on it.
BUG_MARKERS = re.compile(
    r"(?i)(found\s+a?\s*solution|found\s+vulnerab|\[bug\]|bug\s*type|objective\s+found|fund\s*loss|"
    r"arbitrary\s*call|self.?destruct|price\s*manip|reentran|echidna|violat|typed_?bug|"
    r"assertion\s*fail|vulnerab)")
# economic-oracle profit ("Earned 1000000000000000000 wei", "profit: 5 ETH", ...)
PROFIT = re.compile(r"(?i)(?:earned|profit|gain|stolen)\D{0,12}(-?\d[\d,]*)\s*(wei|eth|gwei)?")
# fuzzer progress: "executions: 1124609" -- proves a REAL campaign ran (vs an early panic / unreachable target
# that yields found=False for the WRONG reason). Lets callers tell "fuzzed-clean" from "didn't-really-run".
EXECS = re.compile(r"executions:\s*([\d,]+)")

INSTALL = ("ityfuzz NOT installed. Prebuilt binary (Mac/Linux): "
           "curl -L https://ity.fuzz.land/install.sh | bash && ityfuzzup  "
           "(then re-run). Source build needs Rust+LLVM (heavy).")


def available():
    return shutil.which("ityfuzz") is not None


def build_cmd(address, chain, block, work_dir, flashloan=True, etherscan_key=None, rpc=None, explorer_url=None):
    """Construct the ItyFuzz onchain-fork invocation. Pure -> testable.
    KEY CONSTRAINT (calibrated live): ItyFuzz fetches the ABI from the chain's LEGACY explorer (eth ->
    api.etherscan.io, bsc -> api.bscscan.com, ...). Our Etherscan-v2 multichain key is native on ETH but is
    REJECTED by bscscan.com etc. -> non-eth chains need a chain-native key (or an --explorer-url v2 override)."""
    c = CHAIN.get(str(chain).lower(), str(chain).upper())
    # onchain mode in this ItyFuzz (nightly fb4e87a) = chain-type + target-type address; there is NO -o flag.
    cmd = ["ityfuzz", "evm", "-t", address, "--target-type", "address", "-c", c]
    cmd += ["-d", "all"]  # enable all STRUCTURAL bug oracles (assertion/arb-call/reentrancy/selfdestruct/...)
    if block:
        cmd += ["--onchain-block-number", str(block)]
    if rpc:
        cmd += ["--onchain-url", rpc]
    if explorer_url:
        cmd += ["--onchain-explorer-url", explorer_url]
    if etherscan_key:
        cmd += ["--onchain-etherscan-api-key", etherscan_key]
    if flashloan:
        cmd += ["-f"]                                   # flashloan / economic oracle
    cmd += ["--work-dir", work_dir]
    return cmd


def parse_output(text):
    """Parse ItyFuzz console output for found bugs + profit. Pure -> golden-tested.
    Returns {found, markers[], profit, n_signals}. Heuristic + version-tolerant."""
    markers = [ln.strip() for ln in (text or "").splitlines() if BUG_MARKERS.search(ln)]
    profit = None
    for m in PROFIT.finditer(text or ""):
        try:
            v = int(m.group(1).replace(",", ""))
        except Exception:
            continue
        profit = v if profit is None else max(profit, v)
    execs = 0
    for m in EXECS.finditer(text or ""):
        try:
            execs = max(execs, int(m.group(1).replace(",", "")))
        except Exception:
            continue
    return {"found": bool(markers), "markers": markers[:20], "profit": profit, "n_signals": len(markers),
            "execs": execs}


def run(address, chain="eth", block=None, timeout=600, flashloan=True, work_dir=None, etherscan_key=None,
        rpc=None, explorer_url=None, _runner=subprocess.run):
    """Run ItyFuzz against a forked target, parse the result. _runner injectable for tests."""
    if not available():
        return {"ok": False, "installed": False, "hint": INSTALL}
    work_dir = work_dir or os.path.join("/tmp", "ityfuzz", str(address)[:10])
    os.makedirs(work_dir, exist_ok=True)
    key = etherscan_key or os.environ.get("ETHERSCAN_API_KEY")
    cmd = build_cmd(address, chain, block, work_dir, flashloan=flashloan, etherscan_key=key, rpc=rpc,
                    explorer_url=explorer_url)
    # CALIBRATION (ityfuzz nightly-35b7f08, verified live 2026-08-15): --onchain-url is NOT honored by
    # this build -- endpoint_url stays the hardcoded per-chain default (Chain::ETH -> https://eth.merkle.io,
    # which now 403s), so a bare onchain run panics "fail to get block timestamp". The override that IS
    # read is the ETH_RPC_URL env var (endpoints.rs::get_chain_rpc checks it FIRST, ahead of the per-chain
    # default, for EVERY chain -- so it doubles as the universal fork-RPC override). Inject it here. We keep
    # --onchain-url in build_cmd too: harmless now, correct again if a future build wires it.
    env = os.environ.copy()
    eff_rpc = rpc or env.get("ETH_RPC_URL")
    if eff_rpc:
        env["ETH_RPC_URL"] = eff_rpc
    out = ""
    try:
        p = _runner(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        out = (p.stdout or "") + "\n" + (p.stderr or "")
    except subprocess.TimeoutExpired as e:              # EXPECTED: a fuzzer runs forever; parse what it printed
        out = (e.stdout or "") + "\n" + (e.stderr or "") if isinstance(e.stdout, str) else \
              ((e.stdout.decode() if e.stdout else "") + (e.stderr.decode() if e.stderr else ""))
    except Exception as e:
        return {"ok": False, "installed": True, "error": str(e)}
    res = parse_output(out)
    res.update({"ok": True, "installed": True, "address": address, "chain": chain, "block": block,
                "work_dir": work_dir})
    return res


def main():
    ap = argparse.ArgumentParser(description="ItyFuzz dynamic fork-fuzz lane (auto-find exploits on a fork)")
    ap.add_argument("address", nargs="?", help="target contract address")
    ap.add_argument("--chain", default="eth")
    ap.add_argument("--block", type=int, default=None, help="fork block (default: latest)")
    ap.add_argument("--timeout", type=int, default=600, help="seconds to fuzz (the fuzzer runs until this)")
    ap.add_argument("--flashloan", action="store_true",
                    help="opt-in the flashloan/economic (fund-loss/profit) oracle. OFF by default: nightly-35b7f08's "
                         "-f oracle fetches DEX pairs from pairs-all.infra.fuzz.land, which is DEAD (HTTP 000) -> it "
                         "panics on real non-WETH tokens. Structural detectors (-d all) run regardless. Enable only "
                         "with a working pair-service or a from-source build.")
    ap.add_argument("--rpc", default=None, help="onchain RPC url override")
    ap.add_argument("--explorer-url", default=None,
                    help="ABI-explorer url override (non-eth chains need a chain-native key; our v2 key is eth-only)")
    ap.add_argument("--check", action="store_true", help="just report whether ityfuzz is installed")
    a = ap.parse_args()

    if a.check or not a.address:
        print(f"[ityfuzz] installed: {available()}")
        if not available():
            print("[ityfuzz] " + INSTALL)
        if not a.address and not a.check:
            print("[ityfuzz] usage: ityfuzz_lane.py <address> --chain eth --block N")
        return

    if not available():
        print("[ityfuzz] " + INSTALL)
        sys.exit(0)
    if a.chain.lower() not in ("eth", "ethereum") and not a.explorer_url and os.environ.get("ETHERSCAN_API_KEY"):
        print("[ityfuzz] NOTE: non-eth chain — our Etherscan-v2 key is rejected by the legacy explorer "
              "(bscscan.com etc). Pass a chain-native key or --explorer-url, else ABI fetch fails.")
    if a.flashloan:
        print("[ityfuzz] WARNING: -f economic oracle needs pairs-all.infra.fuzz.land, which is DEAD in this "
              "nightly -> expect a panic on real non-WETH tokens. Structural detectors run either way.")
    # RPC precedence is CHAIN-AWARE: ETH_RPC_URL is ityfuzz's GLOBAL override (used for every chain), so on a
    # non-eth target we must prefer the chain-correct DEFAULT_RPC over a generic ETH_RPC_URL env (else an arb
    # target forks on eth). On eth, honor a custom ETH_RPC_URL first.
    _cl = a.chain.lower()
    if _cl in ("eth", "ethereum"):
        eff_rpc = a.rpc or os.environ.get("ETH_RPC_URL") or DEFAULT_RPC.get(_cl)
    else:
        eff_rpc = a.rpc or DEFAULT_RPC.get(_cl) or os.environ.get("ETH_RPC_URL")
    print(f"[ityfuzz] fuzzing {a.address} on {a.chain} @ block {a.block or 'latest'} for {a.timeout}s "
          f"(rpc={eff_rpc or 'ityfuzz-default'}, flashloan={a.flashloan}, detectors=all) ...")
    res = run(a.address, a.chain, a.block, timeout=a.timeout, flashloan=a.flashloan, rpc=eff_rpc,
              explorer_url=a.explorer_url)
    print(json.dumps(res, indent=1))
    if res.get("found"):
        print(f"\n[ityfuzz] >>> {res['n_signals']} bug-signal(s)"
              + (f", profit ~{res['profit']} wei" if res.get("profit") else "")
              + " -> VERIFY by hand (Gate-0 live+in-scope) before any disclosure. the researcher discloses.")
    sys.exit(10 if res.get("found") else 0)


if __name__ == "__main__":
    main()
