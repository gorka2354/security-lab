#!/usr/bin/env python3
"""Golden tests for the known-bug fingerprint matcher (toolkit/fingerprint.py).

    python tests/test_fingerprint.py

Pins verdict() against the REAL library regexes: the vulnerable shape -> vuln?, the guarded shape -> safe,
the structurally-absent shape (the ApeChurch DeathFun lesson) -> n/a.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "toolkit"))
import fingerprint as F   # noqa: E402

_p, _f = 0, 0


def check(cond, msg):
    global _p, _f
    if cond:
        _p += 1
    else:
        _f += 1
        print("  FAIL:", msg)


FPS = {f["id"]: f for f in F.load()}
DF = FPS["deathfun-increasebet-replay"]
OR = FPS["chainlink-missing-staleness"]

print("== deathfun-increasebet-replay fingerprint ==")
# the vulnerable Abstract death.fun shape: signed increaseBet, betAmount +=, NO msg.value escrow / nonce
vuln = ("contract DeathFun { function increaseBet(uint256 g, uint256 amount, uint256 dl, bytes calldata sig) external payable {"
        " bytes32 h = keccak256(abi.encode('DeathFun:increaseBet', g, amount, dl)); _verifyAdminSignature(h, sig);"
        " games[g].betAmount += amount; } }")
check(F.verdict(vuln, DF) == "vuln?", "vulnerable increaseBet (signed, no msg.value/nonce) -> vuln?")
# guarded: same but require(msg.value == amount)
safe = vuln.replace("games[g].betAmount += amount;", "require(msg.value == amount, 'esc'); games[g].betAmount += amount;")
check(F.verdict(safe, DF) == "safe", "increaseBet WITH msg.value==amount escrow -> safe")
# the ApeChurch shape: VRF-on-chain, NO increaseBet / no signature -> structurally n/a (the lesson)
apechurch = ("contract DeathFun { function play(address u, bytes calldata d) external payable {"
             " uint256 bet = msg.value - vrfFee; games[id].currentPayout = bet; _requestRandom(id, 1, w); } }")
check(F.verdict(apechurch, DF) == "n/a", "no increaseBet/signature -> n/a (bug structurally absent, fast refute)")

print("== chainlink-missing-staleness fingerprint ==")
stale = ("contract O { function getUnderlyingPrice(address c) external view returns(uint){"
         " (,int a,/*upd*/,) = feed.latestRoundData(); if(a<=0) return 0; return uint(a); } }")
check(F.verdict(stale, OR) == "vuln?", "latestRoundData with commented/ignored updatedAt -> vuln?")
fresh = ("contract O { function p() external view returns(uint){ (,int a,,uint256 updatedAt,)=feed.latestRoundData();"
         " require(block.timestamp - updatedAt <= 3600); return uint(a); } }")
check(F.verdict(fresh, OR) == "safe", "real staleness check (block.timestamp - updatedAt) -> safe")
check(F.verdict("contract C { uint x; }", OR) == "n/a", "no latestRoundData -> n/a")

print("== scan() picks the strongest signal across files ==")
import tempfile   # noqa: E402
with tempfile.TemporaryDirectory() as d:
    open(os.path.join(d, "Clean.sol"), "w").write("contract A { uint x; }")
    open(os.path.join(d, "Oracle.sol"), "w").write(stale)
    res = F.scan(d, [OR])
    check(res["chainlink-missing-staleness"]["verdict"] == "vuln?", "scan flags the vulnerable file")
    check("Oracle.sol" in res["chainlink-missing-staleness"]["files"], "scan reports the offending file")

print(f"\n{_p} passed, {_f} failed")
sys.exit(1 if _f else 0)
