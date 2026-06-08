// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";

// ============================================================================
// TEMPLATE — research/patterns/pricing/oracle-manipulation.md  (Pattern 02)
//
// Invariant (§5): a price source that feeds value/health decisions must NOT move
// within a single transaction when an attacker swaps the pool (flash manipulation).
// A spot reserve ratio moves instantly; a clamped/TWAP source does not.
//
// HOW TO USE: copy this file, replace MockPool with your AMM read + MockOracle with
// your price path, keep invariant_priceNotFlashManipulable. The fixed path mirrors
// Likwid's truncatedReserves (a rate-limited move) — the gold-standard mitigation.
//
// Self-validate: flip setUp() to `true` and run `forge test --mc SpotPriceInvariant`
// -> it FAILS (spot follows the swap). Flip back to `false` (committed = green).
// ============================================================================

/// Minimal constant-product pool. price = rY/rX, movable by swapping.
contract MockPool {
    uint256 public rX = 1e24;
    uint256 public rY = 1e24;

    function spotPrice() public view returns (uint256) {
        return rX == 0 ? 0 : rY * 1e18 / rX;
    }

    function swapXforY(uint256 dx) external {
        uint256 k = rX * rY;
        rX += dx;
        rY = k / rX;
    }
}

/// buggy=true  -> price() returns raw spot (manipulable in one tx).
/// buggy=false -> price() returns a stored value that only moves on poke(), and then
///                only by <= MAX_MOVE_BPS (rate-limited — the truncatedReserves idea).
contract MockOracle {
    MockPool public pool;
    bool public buggy;
    uint256 public stored = 1e18;
    uint256 internal constant MAX_MOVE_BPS = 100; // 1% per poke

    constructor(MockPool _p, bool _b) {
        pool = _p;
        buggy = _b;
    }

    function price() external view returns (uint256) {
        return buggy ? pool.spotPrice() : stored;
    }

    function poke() external {
        uint256 spot = pool.spotPrice();
        uint256 hi = stored + stored * MAX_MOVE_BPS / 10000;
        uint256 lo = stored - stored * MAX_MOVE_BPS / 10000;
        stored = spot > hi ? hi : (spot < lo ? lo : spot);
    }
}

/// The fuzzer drives this: each flashManipulate() does a single-tx swap and checks
/// whether the consumed price moved — exactly what an attacker would exploit.
contract SpotHandler is Test {
    MockPool public pool;
    MockOracle public oracle;
    bool public manipulated;

    constructor(MockPool _p, MockOracle _o) {
        pool = _p;
        oracle = _o;
    }

    function flashManipulate(uint256 dx) external {
        dx = bound(dx, 1e22, 1e24); // enough to meaningfully move spot
        uint256 priceBefore = oracle.price();
        pool.swapXforY(dx); // attacker moves the pool inside one tx
        uint256 priceDuring = oracle.price();
        uint256 slack = priceBefore / 50; // tolerate 2% (rate-limited move is fine)
        if (priceDuring > priceBefore + slack || priceDuring + slack < priceBefore) {
            manipulated = true;
        }
    }

    function poke() external {
        oracle.poke(); // the legitimate per-block update path
    }
}

/// Reusable invariant skeleton — runs against the FIXED (clamped) oracle (green).
contract SpotPriceInvariant is Test {
    MockPool internal pool;
    MockOracle internal oracle;
    SpotHandler internal h;

    function setUp() public {
        pool = new MockPool();
        oracle = new MockOracle(pool, false); // FIXED — flip to `true` to watch this fail
        h = new SpotHandler(pool, oracle);
        targetContract(address(h));
    }

    /// The consumed price must not jump within a single swap tx.
    function invariant_priceNotFlashManipulable() public view {
        assertFalse(h.manipulated(), "price source moved within one tx (spot manipulation)");
    }
}

/// Self-check: spot moves intra-tx, the clamped source does not.
contract SpotPriceSelfCheck is Test {
    function _swing(bool buggy) internal returns (uint256 priceBefore, uint256 priceDuring) {
        MockPool p = new MockPool();
        MockOracle o = new MockOracle(p, buggy);
        priceBefore = o.price();
        p.swapXforY(5e23);
        priceDuring = o.price();
    }

    function test_buggy_spotMovesIntraTx() public {
        (uint256 b, uint256 d) = _swing(true);
        assertGt(b > d ? b - d : d - b, b / 10, "buggy: spot must swing far on a big swap");
    }

    function test_fixed_priceStableIntraTx() public {
        (uint256 b, uint256 d) = _swing(false);
        assertEq(b, d, "fixed: clamped price must not move within the tx");
    }
}
