// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Minimal Thetanuts-style "Index Vault" — custom (pre-4626) share-price rounding (2026-06, ~$2.1M).
/// redeem prices `backing * amount / totalSupply`; as totalSupply shrinks toward 0 (burns) the per-share
/// backing explodes and mint rounds shares to ~0. No minimum / dead-shares floor. Educational fixture.
contract IndexVault {
    uint256 public totalSupply;
    uint256 public backing;                          // total assets backing the index
    mapping(address => uint256) public shares;

    function mint(uint256 assets) external returns (uint256 minted) {
        backing += assets;
        minted = totalSupply == 0 ? assets : assets * totalSupply / backing;  // first-deposit case ONLY; no permanent floor
        shares[msg.sender] += minted;
        totalSupply += minted;
    }

    function redeem(uint256 amount) external returns (uint256 payout) {
        payout = backing * amount / totalSupply;     // <- per-share backing explodes as totalSupply -> 0
        shares[msg.sender] -= amount;
        totalSupply -= amount;
        backing -= payout;
    }
}
