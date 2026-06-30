#!/usr/bin/env python3
"""Golden tests for the ItyFuzz dynamic fork-fuzz lane (toolkit/ityfuzz_lane.py).

    python tests/test_ityfuzz.py

Pins: build_cmd flags + chain alias, parse_output (found markers + profit, clean->not-found), graceful
when the binary is absent (no crash, installed:False), and the timeout path (a fuzzer runs forever -> we
parse whatever it printed). Tool is mocked, so this runs with or without ityfuzz installed.
"""
import os
import subprocess
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "toolkit"))
import ityfuzz_lane as L   # noqa: E402

_p, _f = 0, 0


def check(cond, msg):
    global _p, _f
    if cond:
        _p += 1
    else:
        _f += 1
        print("  FAIL:", msg)


print("== build_cmd (onchain-fork invocation) ==")
cmd = L.build_cmd("0xABC", "eth", 19000000, "/tmp/wd", flashloan=True, etherscan_key="K")
check(cmd[:7] == ["ityfuzz", "evm", "-t", "0xABC", "--target-type", "address", "-c"],
      "evm -t <addr> --target-type address -c prefix (onchain via chain-type, no -o in this version)")
check("ETH" in cmd, "chain alias eth -> ETH")
check("--onchain-block-number" in cmd and "19000000" in cmd, "block passed")
check("-f" in cmd, "flashloan/economic oracle on by default")
check("--onchain-etherscan-api-key" in cmd and "K" in cmd, "etherscan key passed")
check("--work-dir" in cmd and "/tmp/wd" in cmd, "work-dir passed")
check("-f" not in L.build_cmd("0x1", "bsc", None, "/w", flashloan=False), "no-flashloan drops -f")
check("BSC" in L.build_cmd("0x1", "bsc", None, "/w"), "bsc -> BSC")

print("== parse_output (bug markers + economic profit) ==")
hit = """
  [INFO] fuzzing...
  ============ Found a solution! ============
  [BUG] Fund Loss detected via price manipulation
  Flashloan earned 1000000000000000000 wei
"""
r = L.parse_output(hit)
check(r["found"] is True and r["n_signals"] >= 2, "bug markers detected")
check(r["profit"] == 10 ** 18, "economic profit parsed (1e18 wei)")
clean = "[INFO] fuzzing...\n[INFO] 0 objectives, 12000 execs/sec\n[INFO] done, nothing found\n"
check(L.parse_output(clean)["found"] is False, "clean run -> not found")
check(L.parse_output("")["found"] is False, "empty -> not found")

print("== run(): graceful when ityfuzz absent ==")
_orig = L.available
L.available = lambda: False
try:
    res = L.run("0xABC", "eth", 1)
    check(res["ok"] is False and res["installed"] is False and "ity.fuzz.land" in res["hint"],
          "absent binary -> {ok:False, installed:False, install hint} (no crash)")
finally:
    L.available = _orig

print("== run(): parse path via injected runner (tool mocked present) ==")
L.available = lambda: True
try:
    fake = types.SimpleNamespace(stdout="[BUG] arbitrary call\nEarned 500 wei", stderr="")
    res = L.run("0xDEAD", "eth", 100, _runner=lambda *a, **k: fake)
    check(res["ok"] and res["found"] and res["profit"] == 500 and res["address"] == "0xDEAD",
          "mocked run -> parsed found + profit + meta")

    # timeout is the EXPECTED terminal state for a fuzzer; we parse what it printed
    def _timeout_runner(*a, **k):
        raise subprocess.TimeoutExpired(cmd="ityfuzz", timeout=1,
                                        output="[BUG] selfdestruct reachable", stderr="")
    res2 = L.run("0xBEEF", "eth", 100, _runner=_timeout_runner)
    check(res2["ok"] and res2["found"] and res2["n_signals"] >= 1, "timeout path parses printed bugs")
finally:
    L.available = _orig

print(f"\n{_p} passed, {_f} failed")
sys.exit(1 if _f else 0)
