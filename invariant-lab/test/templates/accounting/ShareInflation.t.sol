// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";

// ============================================================================
// TEMPLATE — research/patterns/accounting/erc4626-inflation.md  (Pattern 01)
//
// Invariant (§5): a meaningful deposit must never round to ZERO shares — that is the
// signature of a donation-skewed price swallowing later deposits (first-depositor attack).
//
// HOW TO USE: copy this file, delete the MockVault, point the Handler at YOUR
// ERC4626 vault + asset, keep the two invariants. The deterministic
// test_* pair below proves the property is non-trivial (buggy mock IS exploitable,
// fixed mock is safe) — that is the self-check that the invariant actually bites.
//
// Self-validate the INVARIANT too: flip setUp() to `new MockVault(t, true)` and run
//   forge test --mc ShareInflationInvariant
// it must FAIL with a counterexample. Flip back to `false` (committed = green).
// ============================================================================

/// Minimal ERC20 test double (no allowance bookkeeping — keeps the template short).
contract TToken {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 a) external {
        balanceOf[to] += a;
    }

    function transfer(address to, uint256 a) external returns (bool) {
        balanceOf[msg.sender] -= a;
        balanceOf[to] += a;
        return true;
    }

    function transferFrom(address f, address to, uint256 a) external returns (bool) {
        balanceOf[f] -= a;
        balanceOf[to] += a;
        return true;
    }
}

/// Minimal ERC4626-ish vault with a toggleable bug.
/// buggy=true  -> totalAssets() = asset.balanceOf(this) (balance-based) + NO virtual
///                offset: a raw donation moves the share price -> the dStake/Venus surface.
/// buggy=false -> internal accounting (donations ignored) + a virtual-share OFFSET:
///                deposits never round to zero, the donation vector is dead.
contract MockVault {
    TToken public asset;
    bool public buggy;
    uint256 public totalSupply; // shares
    uint256 internal _booked; // internally tracked assets (the fixed path)
    uint256 internal constant OFFSET = 1e3; // virtual shares (fixed path)

    mapping(address => uint256) public balanceOf; // shares per holder

    constructor(TToken _a, bool _buggy) {
        asset = _a;
        buggy = _buggy;
    }

    function totalAssets() public view returns (uint256) {
        return buggy ? asset.balanceOf(address(this)) : _booked;
    }

    function _supplyV() internal view returns (uint256) {
        return buggy ? totalSupply : totalSupply + OFFSET;
    }

    function _assetsV() internal view returns (uint256) {
        return buggy ? totalAssets() : totalAssets() + 1;
    }

    function convertToShares(uint256 a) public view returns (uint256) {
        uint256 ts = _supplyV();
        return ts == 0 ? a : a * ts / _assetsV();
    }

    function previewRedeem(uint256 shares) public view returns (uint256) {
        return totalSupply == 0 ? 0 : shares * totalAssets() / _supplyV();
    }

    function deposit(uint256 a, address to) external returns (uint256 shares) {
        shares = convertToShares(a);
        asset.transferFrom(msg.sender, address(this), a);
        _booked += a;
        totalSupply += shares;
        balanceOf[to] += shares;
    }

    function redeem(uint256 shares, address to) external returns (uint256 a) {
        a = previewRedeem(shares);
        balanceOf[msg.sender] -= shares;
        totalSupply -= shares;
        _booked -= a;
        asset.transfer(to, a);
    }
}

/// The fuzzer drives this: bounded deposit / donate / redeem over 2 actors.
contract InflationHandler is Test {
    MockVault public v;
    TToken public t;
    address[2] public actors;
    bool public griefed; // set if a MEANINGFUL deposit ever rounded to 0 shares
    uint256 internal constant MEANINGFUL = 1e6; // well above dust, well below any real attack

    constructor(MockVault _v, TToken _t) {
        v = _v;
        t = _t;
        actors[0] = address(0xA11);
        actors[1] = address(0xB22);
        for (uint256 i; i < 2; ++i) {
            t.mint(actors[i], 1e24);
        }
    }

    function _a(uint256 s) internal view returns (address) {
        return actors[s % 2];
    }

    function deposit(uint256 seed, uint256 amt) external {
        address a = _a(seed);
        uint256 bal = t.balanceOf(a);
        if (bal == 0) return;
        amt = bound(amt, 1, bal);
        vm.prank(a);
        uint256 shares = v.deposit(amt, a);
        if (amt >= MEANINGFUL && shares == 0) griefed = true; // the inflation signature
    }

    /// The attack primitive: send assets straight to the vault (NOT credited as a deposit).
    function donate(uint256 seed, uint256 amt) external {
        address a = _a(seed);
        uint256 bal = t.balanceOf(a);
        if (bal == 0) return;
        amt = bound(amt, 1, bal);
        vm.prank(a);
        t.transfer(address(v), amt);
    }

    function redeem(uint256 seed, uint256 shares) external {
        address a = _a(seed);
        uint256 b = v.balanceOf(a);
        if (b == 0) return;
        shares = bound(shares, 1, b);
        vm.prank(a);
        v.redeem(shares, a);
    }
}

/// Reusable invariant skeleton — runs against the FIXED vault (green). Copy & retarget.
contract ShareInflationInvariant is Test {
    MockVault internal v;
    TToken internal t;
    InflationHandler internal h;

    function setUp() public {
        t = new TToken();
        v = new MockVault(t, false); // FIXED — flip to `true` to watch this invariant fail
        h = new InflationHandler(v, t);
        targetContract(address(h));
    }

    /// The inflation signature: a meaningful deposit must never round to 0 shares (which is
    /// how a donation-skewed price lets the first depositor swallow later deposits).
    function invariant_meaningfulDepositNeverRoundsToZero() public view {
        assertFalse(h.griefed(), "a meaningful deposit was griefed to 0 shares (inflation)");
    }

    /// Solvency: the vault can always honor every holder's redemption.
    function invariant_vaultSolvent() public view {
        uint256 owed;
        for (uint256 i; i < 2; ++i) {
            owed += v.previewRedeem(v.balanceOf(h.actors(i)));
        }
        assertLe(owed, v.totalAssets(), "vault owes more than it holds");
    }
}

/// Self-check: proves the invariant is NON-trivial — the buggy mock is genuinely
/// exploitable (victim's deposit rounds to 0 shares) and the fixed mock is not.
contract ShareInflationSelfCheck is Test {
    function _attack(bool buggy) internal returns (uint256 victimShares) {
        TToken t = new TToken();
        MockVault v = new MockVault(t, buggy);
        address attacker = address(0xA11);
        address victim = address(0x71C);
        t.mint(attacker, 1e18);
        t.mint(victim, 1e18);

        vm.prank(attacker);
        v.deposit(1, attacker); // 1 wei -> 1 share (empty vault)
        vm.prank(attacker);
        t.transfer(address(v), 1e9); // donate to skew the price
        vm.prank(victim);
        victimShares = v.deposit(1e9, victim); // victim deposits at the skewed price
    }

    function test_buggy_victimRoundedToZeroShares() public {
        assertEq(_attack(true), 0, "buggy: donation should grief the victim to 0 shares");
    }

    function test_fixed_victimGetsFairShares() public {
        assertGt(_attack(false), 0, "fixed: victim must receive non-zero shares");
    }
}
