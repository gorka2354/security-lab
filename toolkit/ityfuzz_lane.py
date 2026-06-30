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

# bug/objective markers ItyFuzz prints when it finds something (heuristic, version-tolerant superset)
BUG_MARKERS = re.compile(
    r"(?i)(found\s+a?\s*solution|\[bug\]|bug\s*type|objective\s+found|fund\s*loss|arbitrary\s*call|"
    r"self.?destruct|price\s*manip|reentran|echidna|invariant\s*viol|typed_?bug|assertion\s*fail|vulnerab)")
# economic-oracle profit ("Earned 1000000000000000000 wei", "profit: 5 ETH", ...)
PROFIT = re.compile(r"(?i)(?:earned|profit|gain|stolen)\D{0,12}(-?\d[\d,]*)\s*(wei|eth|gwei)?")

INSTALL = ("ityfuzz NOT installed. Prebuilt binary (Mac/Linux): "
           "curl -L https://ity.fuzz.land/install.sh | bash && ityfuzzup  "
           "(then re-run). Source build needs Rust+LLVM (heavy).")


def available():
    return shutil.which("ityfuzz") is not None


def build_cmd(address, chain, block, work_dir, flashloan=True, etherscan_key=None, rpc=None):
    """Construct the ItyFuzz onchain-fork invocation. Pure -> testable."""
    c = CHAIN.get(str(chain).lower(), str(chain).upper())
    cmd = ["ityfuzz", "evm", "-o", "-t", address, "-c", c]
    if block:
        cmd += ["--onchain-block-number", str(block)]
    if rpc:
        cmd += ["--onchain-url", rpc]
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
    return {"found": bool(markers), "markers": markers[:20], "profit": profit, "n_signals": len(markers)}


def run(address, chain="eth", block=None, timeout=600, flashloan=True, work_dir=None, etherscan_key=None,
        rpc=None, _runner=subprocess.run):
    """Run ItyFuzz against a forked target, parse the result. _runner injectable for tests."""
    if not available():
        return {"ok": False, "installed": False, "hint": INSTALL}
    work_dir = work_dir or os.path.join("/tmp", "ityfuzz", str(address)[:10])
    os.makedirs(work_dir, exist_ok=True)
    key = etherscan_key or os.environ.get("ETHERSCAN_API_KEY")
    cmd = build_cmd(address, chain, block, work_dir, flashloan=flashloan, etherscan_key=key, rpc=rpc)
    out = ""
    try:
        p = _runner(cmd, capture_output=True, text=True, timeout=timeout)
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
    ap.add_argument("--no-flashloan", action="store_true", help="disable the flashloan/economic oracle")
    ap.add_argument("--rpc", default=None, help="onchain RPC url override")
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
    print(f"[ityfuzz] fuzzing {a.address} on {a.chain} @ block {a.block or 'latest'} for {a.timeout}s ...")
    res = run(a.address, a.chain, a.block, timeout=a.timeout, flashloan=not a.no_flashloan, rpc=a.rpc)
    print(json.dumps(res, indent=1))
    if res.get("found"):
        print(f"\n[ityfuzz] >>> {res['n_signals']} bug-signal(s)"
              + (f", profit ~{res['profit']} wei" if res.get("profit") else "")
              + " -> VERIFY by hand (Gate-0 live+in-scope) before any disclosure. egor discloses.")
    sys.exit(10 if res.get("found") else 0)


if __name__ == "__main__":
    main()
