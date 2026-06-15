// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice ERC1155-style item ledger (single-id mint, mirroring IGameItems.mint(to,id,amount)).
contract MockGameItems {
    mapping(address => mapping(uint256 => uint256)) public balanceOf;
    function mint(address to, uint256 id, uint256 amount) external {
        balanceOf[to][id] += amount;
    }
}

/// @title ImportExportModel
/// @notice Faithful, minimal reimplementation of Gigaverse `ImportExportSystem` (the "Ledgity method":
///         verbatim digest + loop). Mirrors the DEPLOYED code on Abstract (0xE1De5aD14...):
///   - verifySignature digest:            keccak256(abi.encodePacked(player, itemIds, itemAmounts, nonce))  [ImportExportSystem.sol:100]
///   - _exportItemsFromGame mint loop:    for i in itemIds.length: gameItems.mint(player, itemIds[i], itemAmounts[i])
///                                        -- NOTE: there is NO require(itemIds.length == itemAmounts.length).
///   - per-(player,nonce) one-shot nonce: keccak256("nonce", player, nonce)
/// @dev   The signer is an EOA, so the live `SignatureChecker.isValidSignatureNow` reduces to ecrecover==signer.
contract ImportExportModel {
    address public signer;
    mapping(bytes32 => bool) public usedNonce;
    MockGameItems public immutable gameItems;

    constructor(address _signer, MockGameItems _items) {
        signer = _signer;
        gameItems = _items;
    }

    /// The exact eth-signed digest the contract verifies. Two ADJACENT dynamic arrays (itemIds, itemAmounts)
    /// are packed with no length/separator -> the boundary between them is ambiguous (the collision site).
    function digest(address player, uint256[] calldata itemIds, uint256[] calldata itemAmounts, uint256 nonce)
        public pure returns (bytes32)
    {
        bytes32 messageHash = keccak256(abi.encodePacked(player, itemIds, itemAmounts, nonce)); // :100
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));    // :101
    }

    /// exportItemsFromGame: verify the signer's signature, consume the nonce, then mint per the
    /// CALLER-SUPPLIED (itemIds, itemAmounts) -- with NO equal-length check (faithful to the live loop).
    function exportItemsFromGame(
        address player,
        uint256[] calldata itemIds,
        uint256[] calldata itemAmounts,
        uint256 nonce,
        bytes calldata sig
    ) external {
        bytes32 ethHash = digest(player, itemIds, itemAmounts, nonce);
        (bytes32 r, bytes32 s, uint8 v) = _split(sig);
        require(ecrecover(ethHash, v, r, s) == signer, "bad sig");

        bytes32 nk = keccak256(abi.encodePacked("nonce", player, nonce));
        require(!usedNonce[nk], "nonce used");
        usedNonce[nk] = true;

        for (uint256 i = 0; i < itemIds.length; ++i) {
            gameItems.mint(player, itemIds[i], itemAmounts[i]); // indexes amts[i]; only needs amts.length >= ids.length
        }
    }

    function _split(bytes calldata sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "siglen");
        r = bytes32(sig[0:32]);
        s = bytes32(sig[32:64]);
        v = uint8(sig[64]);
    }
}
