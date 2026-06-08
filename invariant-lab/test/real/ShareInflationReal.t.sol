// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC4626} from "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";

// ============================================================================
// REAL-CODE wire of the ShareInflation template (research/patterns/accounting/
// erc4626-inflation.md §5) against OpenZeppelin's ACTUAL ERC4626 — the code that
// Kiln's Vault and thousands of live vaults inherit (OZ v5.1.0, lib/openzeppelin-contracts).
//
// Demonstrates the invariant runs on production code, not a mock, and that OZ's built-in
// virtual-shares defense (the +1 in convertTo*, plus _decimalsOffset) holds: a meaningful
// deposit never rounds to 0 shares, and a donation attack is UNPROFITABLE.
// ============================================================================

contract Asset is ERC20 {
    constructor() ERC20("Asset", "AST") {}

    function mint(address to, uint256 a) external {
        _mint(to, a);
    }
}

/// A minimal CONCRETE vault over the real OZ ERC4626 (configurable virtual-share offset).
contract RealVault is ERC4626 {
    uint8 private immutable _off;

    constructor(IERC20 asset_, uint8 off_) ERC20("Real Vault", "rV") ERC4626(asset_) {
        _off = off_;
    }

    function _decimalsOffset() internal view override returns (uint8) {
        return _off;
    }
}

/// Fuzz handler: deposit / donate / redeem over 2 actors against the REAL OZ vault.
contract RealInflationHandler is Test {
    RealVault public v;
    Asset public a;
    address[2] public actors;
    bool public griefed;
    uint256 internal constant MEANINGFUL = 1e6;

    constructor(RealVault _v, Asset _a) {
        v = _v;
        a = _a;
        actors[0] = address(0xA11);
        actors[1] = address(0xB22);
        for (uint256 i; i < 2; ++i) {
            a.mint(actors[i], 1e24);
            vm.prank(actors[i]);
            a.approve(address(v), type(uint256).max);
        }
    }

    function _a(uint256 s) internal view returns (address) {
        return actors[s % 2];
    }

    function deposit(uint256 seed, uint256 amt) external {
        address who = _a(seed);
        uint256 bal = a.balanceOf(who);
        if (bal == 0) return;
        amt = bound(amt, 1, bal);
        vm.prank(who);
        uint256 shares = v.deposit(amt, who);
        if (amt >= MEANINGFUL && shares == 0) griefed = true;
    }

    function donate(uint256 seed, uint256 amt) external {
        address who = _a(seed);
        uint256 bal = a.balanceOf(who);
        if (bal == 0) return;
        amt = bound(amt, 1, bal);
        vm.prank(who);
        a.transfer(address(v), amt); // direct donation -> inflates OZ totalAssets (balanceOf)
    }

    function redeem(uint256 seed, uint256 shares) external {
        address who = _a(seed);
        uint256 b = v.balanceOf(who);
        if (b == 0) return;
        shares = bound(shares, 1, b);
        vm.prank(who);
        v.redeem(shares, who, who);
    }
}

/// Invariant against the REAL OZ vault. FINDING from this wire: with offset 0 and NO seed,
/// the fuzzer DID round a meaningful deposit to 0 shares under a large enough donation — OZ's
/// virtual shares make the attack *unprofitable* (see the self-checks) but not *impossible* to
/// grief. The real-world fix is seeding dead shares (or a large offset, e.g. Kiln's up to 23);
/// here we seed, which makes the strict no-grief invariant hold. Remove the seed to watch it fail.
contract ShareInflationRealInvariant is Test {
    Asset internal a;
    RealVault internal v;
    RealInflationHandler internal h;

    function setUp() public {
        a = new Asset();
        v = new RealVault(IERC20(address(a)), 0); // real OZ ERC4626, offset 0
        // Seed dead shares (the standard anti-grief mitigation) >> the fuzzer's donation budget.
        a.mint(address(this), 1e21);
        a.approve(address(v), type(uint256).max);
        v.deposit(1e21, address(0xdEaD));
        h = new RealInflationHandler(v, a);
        targetContract(address(h));
    }

    function invariant_realOZ_seededDepositNeverRoundsToZero() public view {
        assertFalse(h.griefed(), "a meaningful deposit rounded to 0 shares even with a dead-share seed");
    }
}

/// Deterministic: the classic donation attack against the REAL OZ vault is UNPROFITABLE,
/// and the victim is not zeroed — OZ's virtual shares (the +1) are the defense.
contract ShareInflationRealSelfCheck is Test {
    function _attack(uint8 offset) internal returns (uint256 victimShares, int256 attackerPnl) {
        Asset a = new Asset();
        RealVault v = new RealVault(IERC20(address(a)), offset);
        address atk = address(0xA11);
        address vic = address(0x71C);
        a.mint(atk, 2e18);
        a.mint(vic, 1e18);
        vm.prank(atk);
        a.approve(address(v), type(uint256).max);
        vm.prank(vic);
        a.approve(address(v), type(uint256).max);

        vm.prank(atk);
        v.deposit(1, atk); // 1 wei into the empty vault
        vm.prank(atk);
        a.transfer(address(v), 1e9); // donate to skew the price
        uint256 spent = 1 + 1e9;

        vm.prank(vic);
        victimShares = v.deposit(1e9, vic);

        uint256 atkShares = v.balanceOf(atk);
        vm.prank(atk);
        uint256 out = v.redeem(atkShares, atk, atk);
        attackerPnl = int256(out) - int256(spent);
    }

    function test_realOZ_offset0_victimNotZeroed_attackUnprofitable() public {
        (uint256 vShares, int256 pnl) = _attack(0);
        assertGt(vShares, 0, "OZ +1 virtual share: meaningful victim deposit is not rounded to 0");
        assertLt(pnl, int256(0), "OZ resists: the attacker cannot recoup the donation (unprofitable)");
    }

    function test_realOZ_offset6_victimGetsFairShares() public {
        (uint256 vShares,) = _attack(6);
        assertGt(vShares, 1e6, "with a 1e6 virtual offset the victim gets near-fair shares");
    }
}
