// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice FAITHFUL RECONSTRUCTION of the ThetaNuts legacy "Index Vault"
/// (0xC2C3AE0a7b405058558C9b4a63b373486CB86Ac7, Ethereum) share-accounting drained for ~$2.1M
/// on 2026-06-15. The on-chain contract is UNVERIFIED, so this is modelled from the SlowMist /
/// Blockaid post-mortem descriptions, NOT copied source. Confirmed properties:
///   - redeem/claim:  payout = backing * amount / totalSupply          (SlowMist + press, verbatim)
///   - deposit/mint:  shares = assets * totalSupply / backing          ("the deposit formula
///                    evaluated to 0 due to rounding during integer division" -> SlowMist)
///   - backing is BALANCE-BASED (vault's own backing-token balance) -> donatable via flash loan
///   - NO minimum-supply / dead-shares / virtual-offset guard (the ERC4626 mitigations)
///
/// Net: an attacker who is the (near-)sole holder donates a flash-loaned amount to spike `backing`,
/// which (a) makes a victim's deposit round to ZERO shares (their assets are absorbed) and
/// (b) inflates the attacker's redeem payout to the whole pool. Repeated mint/redeem cycles,
/// amplified by flash loans, drain it. This is the SAME economic class as the ERC4626
/// first-depositor inflation attack -- but in a BESPOKE pre-ERC4626 index vault with NO `ERC4626`
/// interface anywhere, which is exactly why a detector keyed on the literal type misses it.
contract IndexVaultModel {
    IERC20 public immutable backingToken; // e.g. USDC
    uint256 public totalSupply;           // index-token supply
    mapping(address => uint256) public balanceOf;

    constructor(IERC20 _backing) {
        backingToken = _backing;
    }

    /// balance-based backing -> a direct transfer (donation / flash loan) moves it.
    function backing() public view returns (uint256) {
        return backingToken.balanceOf(address(this));
    }

    /// Deposit `assets` of backing, receive index tokens:
    ///   shares = assets * totalSupply / backing       (price per share = backing/totalSupply)
    /// BUG: integer division floors. When `backing` is inflated (a flash-loan donation) so that
    /// `assets * totalSupply < backing`, shares == 0 -> the depositor pays `assets` and receives
    /// NOTHING; the value accrues to existing holders. "The deposit formula evaluated to 0."
    function deposit(uint256 assets) external returns (uint256 shares) {
        uint256 back = backing();
        if (totalSupply == 0) {
            shares = assets; // bootstrap 1:1
        } else {
            shares = (assets * totalSupply) / back; // <-- rounds to 0 when back is donation-inflated
        }
        require(backingToken.transferFrom(msg.sender, address(this), assets), "pay");
        totalSupply += shares;
        balanceOf[msg.sender] += shares;
    }

    /// Redeem `amount` index tokens for backing:
    ///   payout = backing * amount / totalSupply
    /// BUG: with no minimum-supply floor and balance-based backing, the (near-)sole holder's shares
    /// claim the WHOLE pool -- including a victim's just-absorbed deposit and any donation.
    function redeem(uint256 amount) external returns (uint256 payout) {
        require(balanceOf[msg.sender] >= amount, "bal");
        payout = (backing() * amount) / totalSupply; // confirmed formula
        totalSupply -= amount;
        balanceOf[msg.sender] -= amount;
        require(backingToken.transfer(msg.sender, payout), "send");
    }
}

/// Same vault WITH the standard mitigation (dead-shares minimum) -> the attack fails. Control.
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

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

/// Minimal USDC-like backing token for the PoC.
contract MockUSDC is IERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amt) external {
        balanceOf[to] += amt;
    }

    function approve(address spender, uint256 amt) external returns (bool) {
        allowance[msg.sender][spender] = amt;
        return true;
    }

    function transfer(address to, uint256 amt) external returns (bool) {
        balanceOf[msg.sender] -= amt;
        balanceOf[to] += amt;
        return true;
    }

    function transferFrom(address from, address to, uint256 amt) external returns (bool) {
        if (allowance[from][msg.sender] != type(uint256).max) {
            allowance[from][msg.sender] -= amt;
        }
        balanceOf[from] -= amt;
        balanceOf[to] += amt;
        return true;
    }
}
