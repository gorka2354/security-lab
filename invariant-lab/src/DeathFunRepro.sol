// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @dev Minimal VERBATIM repro of death.fun's `DeathFun` (Abstract 2741, deployed impl
///      0x2c133230cfca00b9bf78c46dae03a97019d96551) -- only createGame + increaseBet + the signature
///      verifier, copied line-for-line from the verified source. Constructor replaces the upgradeable
///      initializer (upgradeable obviated for the unit PoC; the vulnerable logic is unchanged).
contract DeathFunRepro {
    uint256 public gameCounter;
    string public messagePrefix;
    mapping(address => bool) public isAdmin;
    mapping(string => uint256) public preliminaryToOnChainId;

    enum GameStatus { Active, Won, Lost }

    struct Game {
        uint256 createdAt;
        address player;
        uint256 betAmount;
        GameStatus status;
        uint256 payoutAmount;
        bytes32 gameSeedHash;
    }

    mapping(uint256 => Game) public games;

    error NotAuthorized();
    error SignatureExpired();
    error InvalidServerSignature();

    constructor(string memory _messagePrefix, address _admin) {
        messagePrefix = _messagePrefix;
        isAdmin[_admin] = true;
    }

    // VERBATIM from DeathFun.createGame (sig binds msg.sender + msg.value -> not the bug; here for setup)
    function createGame(
        string calldata preliminaryGameId,
        bytes32 gameSeedHash,
        string calldata algoVersion,
        string calldata gameConfig,
        uint256 deadline,
        bytes calldata serverSignature
    ) external payable {
        require(block.timestamp <= deadline, "Signature expired");
        bytes32 messageHash = keccak256(
            abi.encode(
                string.concat(messagePrefix, ":createGame"),
                preliminaryGameId, gameSeedHash, algoVersion, gameConfig,
                msg.sender, msg.value, deadline
            )
        );
        _verifyAnyAdminSignature(messageHash, serverSignature);
        require(preliminaryToOnChainId[preliminaryGameId] == 0, "exists");
        gameCounter += 1;
        uint256 onChainGameId = gameCounter;
        preliminaryToOnChainId[preliminaryGameId] = onChainGameId;
        games[onChainGameId] = Game({
            createdAt: block.timestamp, player: msg.sender, betAmount: msg.value,
            status: GameStatus.Active, payoutAmount: 0, gameSeedHash: gameSeedHash
        });
    }

    // VERBATIM from DeathFun.increaseBet -- the bug: sig binds NEITHER msg.value NOR a nonce,
    // and there is no consumed-signature / status guard -> free, replayable betAmount inflation.
    function increaseBet(uint256 onChainGameId, uint256 amount, uint256 deadline, bytes calldata serverSignature)
        external
        payable
    {
        if (block.timestamp > deadline) revert SignatureExpired();
        bytes32 messageHash = keccak256(
            abi.encode(string.concat(messagePrefix, ":increaseBet"), onChainGameId, amount, deadline)
        );
        _verifyAnyAdminSignature(messageHash, serverSignature);
        Game storage game = games[onChainGameId];
        if (game.player != msg.sender) revert NotAuthorized();
        game.betAmount += amount; // <-- amount is the signed param, NOT msg.value; no replay guard
    }

    // VERBATIM from DeathFun._verifyAnyAdminSignature
    function _verifyAnyAdminSignature(bytes32 _hash, bytes calldata _signature) internal view {
        // ECDSA.toEthSignedMessageHash(_hash) inlined (OZ5 moved it to MessageHashUtils); same EIP-191 prefix
        bytes32 prefixedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _hash));
        address recoveredSigner = ECDSA.recover(prefixedHash, _signature);
        if (recoveredSigner == address(0) || !isAdmin[recoveredSigner]) {
            revert InvalidServerSignature();
        }
    }
}
