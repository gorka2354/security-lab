// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "./IndexVaultModel.sol";

/// @notice CONTROL: the same share vault WITH the standard mitigation (dead-shares minimum +
/// reject round-to-zero deposits) -> the donation-inflation attack fails. Kept in its OWN file so
/// `recon.py` evaluates it per-file: the vulnerable IndexVaultModel.sol fires [!] (no guard), this
/// one stays clean (the MINIMUM_SHARES dead-share floor is the mitigation det_erc4626 looks for).
contract IndexVaultGuarded {
    IERC20 public immutable backingToken;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    uint256 constant MINIMUM_SHARES = 1e3; // seeded dead shares burned to address(0) on bootstrap

    constructor(IERC20 _backing) {
        backingToken = _backing;
    }

    function backing() public view returns (uint256) {
        return backingToken.balanceOf(address(this));
    }

    function deposit(uint256 assets) external returns (uint256 shares) {
        uint256 back = backing();
        if (totalSupply == 0) {
            shares = assets;
            // FIX: burn MINIMUM_SHARES to address(0) so totalSupply can never be driven to 1 and
            // `back` can't be donation-skewed past the dead-share floor.
            require(shares > MINIMUM_SHARES, "min");
            balanceOf[address(0)] += MINIMUM_SHARES;
            totalSupply += MINIMUM_SHARES;
            shares -= MINIMUM_SHARES;
        } else {
            shares = (assets * totalSupply) / back;
            require(shares > 0, "zero-shares"); // FIX: reject round-to-zero deposits
        }
        require(backingToken.transferFrom(msg.sender, address(this), assets), "pay");
        totalSupply += shares;
        balanceOf[msg.sender] += shares;
    }

    function redeem(uint256 amount) external returns (uint256 payout) {
        require(balanceOf[msg.sender] >= amount, "bal");
        payout = (backing() * amount) / totalSupply;
        totalSupply -= amount;
        balanceOf[msg.sender] -= amount;
        require(backingToken.transfer(msg.sender, payout), "send");
    }
}
