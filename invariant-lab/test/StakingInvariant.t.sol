// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {MockERC20, StakingRewards} from "../src/Staking.sol";

// Worked example for the template library (see test/templates/). Synthetix-style staking
// with a planted rounding bug (StakingRewards `buggy` toggle: rewardRate += 1 wei/sec ->
// commits to paying rate*duration > what it was funded -> slow insolvency).
//
// Green-by-default convention (matches test/templates/): the invariant runs against the
// FIXED contract (passes), and a deterministic self-check proves the bug is real. Flip
// setUp() to `true` and run `forge test --mc StakingInvariant` to watch the invariant fail.

/// The Handler is what the fuzzer drives: it performs bounded, valid actions over a small set
/// of actors so the fuzzer explores real state, not reverts.
contract Handler is Test {
    StakingRewards public staking;
    MockERC20 public stk;
    MockERC20 public rwd;
    address[3] public actors;

    constructor(StakingRewards _s, MockERC20 _stk, MockERC20 _rwd) {
        staking = _s;
        stk = _stk;
        rwd = _rwd;
        actors[0] = address(0xA11);
        actors[1] = address(0xB22);
        actors[2] = address(0xC33);
        for (uint256 i; i < 3; ++i) {
            stk.mint(actors[i], 1e24);
            vm.prank(actors[i]);
            stk.approve(address(staking), type(uint256).max);
        }
        rwd.mint(address(this), 1e27); // handler funds the rewards
        rwd.approve(address(staking), type(uint256).max);
    }

    function _actor(uint256 s) internal view returns (address) {
        return actors[s % 3];
    }

    function stake(uint256 seed, uint256 amt) external {
        address a = _actor(seed);
        uint256 bal = stk.balanceOf(a);
        if (bal == 0) return;
        staking.stake(a, bound(amt, 1, bal));
    }

    function withdraw(uint256 seed, uint256 amt) external {
        address a = _actor(seed);
        uint256 b = staking.balanceOf(a);
        if (b == 0) return;
        staking.withdraw(a, bound(amt, 1, b));
    }

    function claim(uint256 seed) external {
        staking.getReward(_actor(seed));
    }

    function notify(uint256 amt) external {
        amt = bound(amt, 1e12, 1e22); // small amounts make the over-rate bite faster
        if (rwd.balanceOf(address(this)) < amt) return;
        staking.notifyReward(amt);
    }

    function warp(uint256 t) external {
        skip(bound(t, 1 hours, 2 days));
    }
}

/// Reusable invariant skeleton — runs against the FIXED staking (green).
contract StakingInvariant is Test {
    StakingRewards staking;
    MockERC20 stk;
    MockERC20 rwd;
    Handler handler;

    function setUp() public {
        vm.warp(1_700_000_000);
        stk = new MockERC20();
        rwd = new MockERC20();
        staking = new StakingRewards(stk, rwd, false); // FIXED — flip to `true` to watch this fail
        handler = new Handler(staking, stk, rwd);

        // CRUCIAL: make the handler the ONLY fuzz target, otherwise Foundry also fuzzes the
        // tokens/staking directly (random mints mask the bug).
        targetContract(address(handler));
        bytes4[] memory sel = new bytes4[](5);
        sel[0] = Handler.stake.selector;
        sel[1] = Handler.withdraw.selector;
        sel[2] = Handler.claim.selector;
        sel[3] = Handler.notify.selector;
        sel[4] = Handler.warp.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: sel}));
    }

    /// SOLVENCY: the contract must always hold enough reward tokens to cover everyone's
    /// earned-but-unclaimed rewards. The rounding bug breaks this.
    function invariant_solvency() public view {
        uint256 owed;
        for (uint256 i; i < 3; ++i) {
            owed += staking.earned(handler.actors(i));
        }
        assertGe(rwd.balanceOf(address(staking)), owed, "INSOLVENT: owes more than it holds");
    }
}

/// Self-check: proves the invariant is non-trivial — the buggy contract genuinely goes insolvent
/// (a single staker over one full duration is owed `duration` wei more than was funded).
contract StakingSelfCheck is Test {
    function _solvencyGap(bool buggy) internal returns (int256) {
        vm.warp(1_700_000_000);
        MockERC20 stk = new MockERC20();
        MockERC20 rwd = new MockERC20();
        StakingRewards s = new StakingRewards(stk, rwd, buggy);

        uint256 amount = 1e21;
        rwd.mint(address(this), amount);
        rwd.approve(address(s), type(uint256).max);
        s.notifyReward(amount); // funds `amount`; buggy sets rate = amount/duration + 1

        address alice = address(0xA11);
        stk.mint(alice, 1e18);
        vm.prank(alice);
        stk.approve(address(s), type(uint256).max);
        s.stake(alice, 1e18);

        skip(7 days); // the full reward duration elapses
        return int256(s.earned(alice)) - int256(rwd.balanceOf(address(s))); // >0 => insolvent
    }

    function test_buggy_becomesInsolvent() public {
        assertGt(_solvencyGap(true), 0, "buggy: owes more reward than it holds (the +1 rate bug)");
    }

    function test_fixed_staysSolvent() public {
        assertLe(_solvencyGap(false), 0, "fixed: never owes more than it holds");
    }
}
