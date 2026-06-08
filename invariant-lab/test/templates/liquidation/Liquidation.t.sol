// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";

// ============================================================================
// TEMPLATE — research/patterns/liquidation/liquidation-math.md  (Pattern 05)
//
// Invariant (§5): a liquidation must only succeed against an UNHEALTHY position.
// Missing/incorrect health gating lets a liquidator seize collateral + bonus from a
// solvent borrower (theft). (Same harness extends to: no self-liq profit, bonus bound,
// rounding direction — add those checks against your target.)
//
// HOW TO USE: copy this file, replace MockLending with your lending market, keep
// invariant_noLiquidationOfHealthy. The deterministic test_* pair proves the bug bites.
//
// Self-validate: flip setUp() to `true`, run `forge test --mc LiquidationInvariant`
// -> it FAILS (a healthy borrower gets liquidated). Flip back to `false` (committed).
// ============================================================================

/// Minimal ERC20 test double (no allowance — keeps the template short).
contract TToken {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 a) external {
        balanceOf[to] += a;
    }

    function transfer(address to, uint256 a) external returns (bool) {
        balanceOf[msg.sender] -= a;
        balanceOf[to] += a;
        return true;
    }

    function transferFrom(address f, address to, uint256 a) external returns (bool) {
        balanceOf[f] -= a;
        balanceOf[to] += a;
        return true;
    }
}

/// Minimal single-market lender. buggy=true OMITS the health check in liquidate()
/// (so a solvent borrower can be liquidated); buggy=false requires health < 100%.
contract MockLending {
    TToken public coll;
    TToken public debt;
    bool public buggy;
    uint256 public price = 1e18; // 1 collateral = price/1e18 debt units
    uint256 internal constant BONUS_BPS = 1000; // 10% liquidation bonus

    struct Pos {
        uint256 c;
        uint256 d;
    }

    mapping(address => Pos) public pos;

    constructor(TToken _c, TToken _d, bool _b) {
        coll = _c;
        debt = _d;
        buggy = _b;
    }

    function open(address who, uint256 c, uint256 d) external {
        coll.transferFrom(who, address(this), c);
        pos[who].c += c;
        pos[who].d += d;
    }

    function setPrice(uint256 p) external {
        price = p;
    }

    /// health in bps: >10000 = over-collateralized (healthy), <10000 = liquidatable.
    function healthBps(address u) public view returns (uint256) {
        Pos memory p = pos[u];
        if (p.d == 0) return type(uint256).max;
        return (p.c * price / 1e18) * 10000 / p.d;
    }

    function liquidate(address u, uint256 repay) external {
        if (!buggy) require(healthBps(u) < 10000, "position is healthy"); // THE guard
        Pos storage p = pos[u];
        if (repay > p.d) repay = p.d;
        uint256 seize = (repay * (10000 + BONUS_BPS) / 10000) * 1e18 / price;
        if (seize > p.c) seize = p.c;
        debt.transferFrom(msg.sender, address(this), repay);
        p.d -= repay;
        p.c -= seize;
        coll.transfer(msg.sender, seize);
    }
}

/// The fuzzer drives this: it keeps the borrower SOLVENT (price stays high) and lets a
/// liquidator try to seize. A successful seizure of a healthy position is the bug.
contract LiqHandler is Test {
    MockLending public L;
    TToken public coll;
    TToken public debt;
    address public borrower = address(0xB0B);
    address public liquidator = address(0x110);
    bool public liquidatedHealthy;

    constructor(MockLending _L, TToken _c, TToken _d) {
        L = _L;
        coll = _c;
        debt = _d;
        coll.mint(borrower, 1e21);
        L.open(borrower, 1e21, 5e20); // 1000 collateral vs 500 debt -> 200% healthy
        debt.mint(liquidator, 1e24);
    }

    function tryLiquidate(uint256 repay) external {
        repay = bound(repay, 1, 5e20);
        bool wasHealthy = L.healthBps(borrower) >= 10000;
        (uint256 cBefore,) = L.pos(borrower);
        vm.prank(liquidator);
        try L.liquidate(borrower, repay) {
            (uint256 cAfter,) = L.pos(borrower);
            if (wasHealthy && cAfter < cBefore) liquidatedHealthy = true;
        } catch {}
    }

    /// Move the price, but only within a band that keeps the borrower solvent.
    function nudgePrice(uint256 p) external {
        L.setPrice(bound(p, 6e17, 2e18)); // health stays >= 120%
    }
}

/// Reusable invariant skeleton — runs against the FIXED lender (green).
contract LiquidationInvariant is Test {
    MockLending internal L;
    TToken internal coll;
    TToken internal debt;
    LiqHandler internal h;

    function setUp() public {
        coll = new TToken();
        debt = new TToken();
        L = new MockLending(coll, debt, false); // FIXED — flip to `true` to watch this fail
        h = new LiqHandler(L, coll, debt);
        targetContract(address(h));
    }

    function invariant_noLiquidationOfHealthy() public view {
        assertFalse(h.liquidatedHealthy(), "a solvent borrower was liquidated (missing health gate)");
    }
}

/// Self-check: a healthy position is liquidatable on buggy, protected on fixed.
contract LiquidationSelfCheck is Test {
    function _try(bool buggy) internal returns (bool seized) {
        TToken c = new TToken();
        TToken d = new TToken();
        MockLending L = new MockLending(c, d, buggy);
        address borrower = address(0xB0B);
        address liq = address(0x110);
        c.mint(borrower, 1e21);
        L.open(borrower, 1e21, 5e20); // 200% healthy
        d.mint(liq, 1e24);
        (uint256 cBefore,) = L.pos(borrower);
        vm.prank(liq);
        try L.liquidate(borrower, 1e20) {
            (uint256 cAfter,) = L.pos(borrower);
            seized = cAfter < cBefore;
        } catch {
            seized = false;
        }
    }

    function test_buggy_healthyIsLiquidatable() public {
        assertTrue(_try(true), "buggy: missing health gate lets a healthy position be seized");
    }

    function test_fixed_healthyIsProtected() public {
        assertFalse(_try(false), "fixed: a healthy position must be unliquidatable");
    }
}
