// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {MockERC20, StakingRewards} from "../src/Staking.sol";

/// The Handler is what the fuzzer drives: it performs bounded, valid actions
/// over a small set of actors so the fuzzer explores real state, not reverts.
contract Handler is Test {
    StakingRewards public staking;
    MockERC20 public stk;
    MockERC20 public rwd;
    address[3] public actors;

    constructor(StakingRewards _s, MockERC20 _stk, MockERC20 _rwd) {
        staking = _s; stk = _stk; rwd = _rwd;
        actors[0] = address(0xA11); actors[1] = address(0xB22); actors[2] = address(0xC33);
        for (uint256 i; i < 3; ++i) {
            stk.mint(actors[i], 1e24);
            vm.prank(actors[i]);
            stk.approve(address(staking), type(uint256).max);
        }
        rwd.mint(address(this), 1e27);            // handler funds the rewards
        rwd.approve(address(staking), type(uint256).max);
    }

    function _actor(uint256 s) internal view returns (address) { return actors[s % 3]; }

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

    function claim(uint256 seed) external { staking.getReward(_actor(seed)); }

    function notify(uint256 amt) external {
        amt = bound(amt, 1e12, 1e22); // small amounts make the over-rate bite faster
        if (rwd.balanceOf(address(this)) < amt) return;
        staking.notifyReward(amt);
    }

    function warp(uint256 t) external { skip(bound(t, 1 hours, 2 days)); }
}

abstract contract StakingInvariantBase is Test {
    StakingRewards staking;
    MockERC20 stk;
    MockERC20 rwd;
    Handler handler;

    function _buggy() internal virtual returns (bool);

    function setUp() public {
        vm.warp(1_700_000_000);
        stk = new MockERC20();
        rwd = new MockERC20();
        staking = new StakingRewards(stk, rwd, _buggy());
        handler = new Handler(staking, stk, rwd);

        // CRUCIAL: make the handler the ONLY fuzz target, otherwise Foundry
        // also fuzzes the tokens/staking directly (random mints mask the bug).
        targetContract(address(handler));
        bytes4[] memory sel = new bytes4[](5);
        sel[0] = Handler.stake.selector;
        sel[1] = Handler.withdraw.selector;
        sel[2] = Handler.claim.selector;
        sel[3] = Handler.notify.selector;
        sel[4] = Handler.warp.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: sel}));
    }

    /// SOLVENCY: the contract must always hold enough reward tokens to cover
    /// everyone's earned-but-unclaimed rewards. The rounding bug breaks this.
    function invariant_solvency() public view {
        uint256 owed;
        for (uint256 i; i < 3; ++i) owed += staking.earned(handler.actors(i));
        assertGe(rwd.balanceOf(address(staking)), owed, "INSOLVENT: owes more than it holds");
    }
}

/// Planted bug -> the fuzzer should FAIL this with a counterexample.
contract BuggyStakingTest is StakingInvariantBase {
    function _buggy() internal pure override returns (bool) { return true; }
}

/// Fixed (round down) -> this should PASS.
contract FixedStakingTest is StakingInvariantBase {
    function _buggy() internal pure override returns (bool) { return false; }
}
