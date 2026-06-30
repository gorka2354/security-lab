#!/usr/bin/env python3
"""Golden tests for the test-mining lane (toolkit/testmine.py).

    python tests/test_testmine.py

Pins: mine_text (invariant stems + asserted subjects + noise filtering + assertion count) and record
(cross-project frequency = #projects, idempotent per project).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "toolkit"))
import testmine as T   # noqa: E402

_p, _f = 0, 0


def check(cond, msg):
    global _p, _f
    if cond:
        _p += 1
    else:
        _f += 1
        print("  FAIL:", msg)


SAMPLE = """
// SPDX-License-Identifier: MIT
contract VaultInvariant {
    function invariant_solvency() public { assertGe(vault.totalAssets(), vault.totalSupply()); }
    function echidna_no_loss() public returns (bool) { return token.balanceOf(a) >= dep; }
    function test_withdraw() public {
        assertEq(vault.convertToShares(1e18), expected);
        require(token.balanceOf(user) > 0);
        vm.prank(user); vm.warp(block.timestamp + 1);
    }
}
"""

print("== mine_text (invariants + subjects + noise filter) ==")
inv, subs, na = T.mine_text(SAMPLE)
check(set(inv) == {"solvency", "no_loss"}, "invariant/echidna fn stems extracted (prefix stripped)")
check(na == 3, "3 assertions counted (assertGe + assertEq + require)")
check(subs["totalassets"] >= 1 and subs["totalsupply"] >= 1 and subs["converttoshares"] >= 1
      and subs["balanceof"] >= 1, "asserted property subjects captured (the invariant surfaces)")
check("vm" not in subs and "prank" not in subs and "warp" not in subs and "require" not in subs,
      "test/vm scaffolding filtered out (noise)")

print("== record (cross-project frequency = #projects, idempotent) ==")
st = {"projects": {}, "subjects": {}, "invariant_stems": {}}
mined = {"invariants": ["solvency"], "subjects": {"totalassets": 5, "balanceof": 2},
         "n_test_files": 3, "n_assertions": 9}
T.record(st, "p1", mined, "2026-06-30")
check(st["subjects"]["totalassets"]["count"] == 1 and st["subjects"]["totalassets"]["projects"] == ["p1"],
      "first project -> count 1 (count = #PROJECTS, not #occurrences)")
T.record(st, "p2", mined, "2026-06-30")
check(st["subjects"]["totalassets"]["count"] == 2, "second project -> count 2")
T.record(st, "p1", mined, "2026-06-30")   # idempotent
check(st["subjects"]["totalassets"]["count"] == 2, "re-mining p1 does NOT double-count")
check(st["invariant_stems"]["solvency"]["count"] == 2, "invariant stems tallied by project too")
check(len(st["projects"]) == 2, "two projects recorded")

print(f"\n{_p} passed, {_f} failed")
sys.exit(1 if _f else 0)
