// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";

// ============================================================================
// TEMPLATE — research/patterns/accounting/reward-accounting.md  (Pattern 03)
//
// Invariant (§5): an actor can never be paid more than was accrued to them — the
// "already-claimed" marker must be consumed on every payout path. The bug: claim()
// pays without zeroing the entitlement, so the same reward is claimed twice.
//
// HOW TO USE: copy this file, replace MockRewards with your reward distributor, keep
// invariant_noClaimExceedsAccrual. The test_* pair proves the double-claim.
//
// Self-validate: flip setUp() to `true`, run `forge test --mc DoubleClaimInvariant`
// -> it FAILS (paid > accrued). Flip back to `false` (committed = green).
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
}

/// buggy=true: claim() pays but never zeroes owed[] -> re-claimable.
/// buggy=false: owed[] zeroed BEFORE the transfer (the consumed marker).
contract MockRewards {
    TToken public rwd;
    bool public buggy;
    mapping(address => uint256) public owed;
    mapping(address => uint256) public accruedTotal;
    mapping(address => uint256) public paidTotal;

    constructor(TToken _r, bool _b) {
        rwd = _r;
        buggy = _b;
    }

    function fund(uint256 a) external {
        rwd.mint(address(this), a);
    }

    function accrue(address u, uint256 a) external {
        owed[u] += a;
        accruedTotal[u] += a;
    }

    function claim() external {
        uint256 amt = owed[msg.sender];
        if (amt == 0) return;
        if (!buggy) owed[msg.sender] = 0; // consume the marker FIRST (CEI)
        rwd.transfer(msg.sender, amt);
        paidTotal[msg.sender] += amt;
        // buggy path: owed[msg.sender] still == amt -> the next claim pays it again
    }
}

/// The fuzzer drives this: fund once, accrue to 2 actors, then claim/accrue freely.
contract ClaimHandler is Test {
    MockRewards public R;
    address[2] public actors;

    constructor(MockRewards _R) {
        R = _R;
        actors[0] = address(0xA11);
        actors[1] = address(0xB22);
        R.fund(1e24);
        for (uint256 i; i < 2; ++i) {
            R.accrue(actors[i], 1e18);
        }
    }

    function claim(uint256 seed) external {
        vm.prank(actors[seed % 2]);
        R.claim();
    }

    function accrueMore(uint256 seed, uint256 a) external {
        R.accrue(actors[seed % 2], bound(a, 0, 1e18));
    }
}

/// Reusable invariant skeleton — runs against the FIXED distributor (green).
contract DoubleClaimInvariant is Test {
    TToken internal rwd;
    MockRewards internal R;
    ClaimHandler internal h;

    function setUp() public {
        rwd = new TToken();
        R = new MockRewards(rwd, false); // FIXED — flip to `true` to watch this fail
        h = new ClaimHandler(R);
        targetContract(address(h));
    }

    function invariant_noClaimExceedsAccrual() public view {
        for (uint256 i; i < 2; ++i) {
            address a = h.actors(i);
            assertLe(R.paidTotal(a), R.accruedTotal(a), "claimed more than accrued (double-claim)");
        }
    }
}

/// Self-check: a second claim pays again on buggy, pays zero on fixed.
contract DoubleClaimSelfCheck is Test {
    function _twoClaims(bool buggy) internal returns (uint256) {
        TToken r = new TToken();
        MockRewards R = new MockRewards(r, buggy);
        R.fund(1e24);
        address u = address(0xA11);
        R.accrue(u, 1e18);
        vm.prank(u);
        R.claim();
        vm.prank(u);
        R.claim(); // the replay
        return R.paidTotal(u);
    }

    function test_buggy_doubleClaimPaysTwice() public {
        assertEq(_twoClaims(true), 2e18, "buggy: the same reward is claimed twice");
    }

    function test_fixed_secondClaimPaysZero() public {
        assertEq(_twoClaims(false), 1e18, "fixed: the consumed marker blocks the replay");
    }
}
