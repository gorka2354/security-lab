// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";

// ============================================================================
// TEMPLATE — research/patterns/pricing/index-manipulation.md  (Pattern 04)
//
// Invariant (§5): an Aave-style interest index must not jump by an unbounded ratio
// in a single accrual. On a near-EMPTY market, a premium spread over ~dust supply is
// a huge relative index move (dTRINITY: liquidityIndex 1.0 -> 6.2M RAY). A min-liquidity
// floor on the divisor caps the move.
//
// HOW TO USE: copy this file, replace MockReserve with your reserve/index math, keep
// invariant_indexMovePerAccrualBounded. The test_* pair proves the empty-market blowup.
//
// Self-validate: flip setUp() to `true`, run `forge test --mc IndexInflationInvariant`
// -> it FAILS (index explodes on the dust-supply market). Flip back to `false`.
// ============================================================================

/// Minimal Aave-like reserve. buggy=true divides the accruing premium by the raw
/// scaledSupply (which is ~dust on a fresh reserve) -> the index explodes. buggy=false
/// floors the divisor at FLOOR (a real min-liquidity seed) -> the move is bounded.
contract MockReserve {
    bool public buggy;
    uint256 public index = 1e27; // RAY, starts at 1.0
    uint256 public scaledSupply;
    uint256 internal constant FLOOR = 1e21; // min effective liquidity (fixed path)

    constructor(bool _b) {
        buggy = _b;
    }

    function deposit(uint256 amt) external returns (uint256 scaled) {
        scaled = amt * 1e27 / index;
        scaledSupply += scaled;
    }

    /// A premium (flash-loan fee, etc.) cumulated into the index, spread over supply.
    function accruePremium(uint256 premium) external {
        uint256 denom = buggy ? scaledSupply : (scaledSupply < FLOOR ? FLOOR : scaledSupply);
        if (denom == 0) denom = 1; // buggy empty market: divide by ~nothing
        index += premium * 1e27 / denom;
    }
}

/// The fuzzer drives this on a reserve seeded with only 1 wei (a near-empty market),
/// tracking the worst single-accrual index multiplier.
contract IndexHandler is Test {
    MockReserve public r;
    uint256 public maxJumpBps; // worst index_after/index_before ratio, in bps

    constructor(MockReserve _r) {
        r = _r;
        r.deposit(1); // dust seed -> the empty-market condition
    }

    function accrue(uint256 premium) external {
        premium = bound(premium, 1, 1e18);
        uint256 before = r.index();
        r.accruePremium(premium);
        uint256 jump = r.index() * 10000 / before;
        if (jump > maxJumpBps) maxJumpBps = jump;
    }

    function deposit(uint256 amt) external {
        r.deposit(bound(amt, 1, 1e24)); // a real deposit makes the market non-empty (safe)
    }
}

/// Reusable invariant skeleton — runs against the FIXED reserve (green).
contract IndexInflationInvariant is Test {
    MockReserve internal r;
    IndexHandler internal h;

    function setUp() public {
        r = new MockReserve(false); // FIXED — flip to `true` to watch this fail
        h = new IndexHandler(r);
        targetContract(address(h));
    }

    /// No single accrual may move the index by more than ~3x (10000 bps = no move).
    function invariant_indexMovePerAccrualBounded() public view {
        assertLt(h.maxJumpBps(), 30000, "index moved >3x in one accrual (empty-market inflation)");
    }
}

/// Self-check: one premium on a dust-supply market explodes the buggy index, not the fixed.
contract IndexInflationSelfCheck is Test {
    function _multiplier(bool buggy) internal returns (uint256) {
        MockReserve r = new MockReserve(buggy);
        r.deposit(1); // near-empty market
        uint256 before = r.index();
        r.accruePremium(1e18);
        return r.index() / before;
    }

    function test_buggy_indexExplodesOnEmptyMarket() public {
        assertGt(_multiplier(true), 1000, "buggy: dust supply must let the index blow up");
    }

    function test_fixed_indexBoundedOnEmptyMarket() public {
        assertLt(_multiplier(false), 2, "fixed: min-liquidity floor keeps the index move tiny");
    }
}
