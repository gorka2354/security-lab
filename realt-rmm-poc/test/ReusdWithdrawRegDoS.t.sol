// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";

/*
  RealT RMM Marketplace V2 (Gnosis chainid 100) -- REUSDPoolManager withdrawReg() DoS.

  FINDING (Medium): REUSDPoolManager._syncReusdBalance() is the unconditional FIRST statement of
  withdrawReg(), borrowReusd(), repayReusdWithStable() and the admin syncReusdBalance(). It calls
  IERC20Mintable(REUSD).burn(aREUSD, aREUSD's REUSD balance). But the manager holds neither
  GOVERNANCE_ROLE nor BRIDGE_ROLE on the REUSD token, so that burn reverts with PERMISSION_ERROR
  (selector 0x03104826) whenever the REUSD aToken holds any REUSD -- which it has held (0.5 REUSD)
  continuously since block 46,016,118. Because withdrawReg() is the ONLY self-serve path for a user to
  reclaim REG collateral they locked in the subsidy program, a user who has finished repaying their
  REUSD debt (the withdraw precondition) is permanently unable to reclaim their REG. ~1,616.9 REG of
  user collateral sits in the manager today; the deprivation is prospective (every current locker still
  carries REUSD debt, so they revert UserHasReusdDebt first) -- the FIRST user to become withdraw-
  eligible is bricked. Recovery needs a privileged act (grant the manager the burn role, upgrade the
  manager, or admin-burn the aREUSD's REUSD by hand). It is also a hard blocker for the PHASE2/PHASE3
  paths (borrowReusd/repayReusdWithStable) that gate on the same sync.

  All state reads are on a Gnosis mainnet fork; no transaction is broadcast (white-hat, read-only).
*/

interface IManager {
    function withdrawReg() external;
    function getUserLockedReg(address user) external view returns (uint256);
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

// Aave's getReserveData returns a 15-field struct; we only need aTokenAddress. Declaring the struct
// (rather than a 15-tuple) keeps the ABI decode off the stack and avoids stack-too-deep without via-ir.
interface IPool {
    struct ReserveDataLegacy {
        uint256 configuration;
        uint128 liquidityIndex;
        uint128 currentLiquidityRate;
        uint128 variableBorrowIndex;
        uint128 currentVariableBorrowRate;
        uint128 currentStableBorrowRate;
        uint40 lastUpdateTimestamp;
        uint16 id;
        address aTokenAddress;
        address stableDebtTokenAddress;
        address variableDebtTokenAddress;
        address interestRateStrategyAddress;
        uint128 accruedToTreasury;
        uint128 unbacked;
        uint128 isolationModeTotalDebt;
    }
    function getReserveData(address asset) external view returns (ReserveDataLegacy memory);
}

contract ReusdWithdrawRegDoS is Test {
    // live Gnosis mainnet deployment (RealT RMM Marketplace V2)
    address constant MGR   = 0x371a02F425CFA011969085fF6ec4F8e53bD77360; // REUSDPoolManager (proxy)
    address constant REUSD = 0x3390742Ac0DCe14EA6Fcbd5Ae02e2303C5D62Ad9; // REUSD token (proxy)
    address constant AREUSD= 0xd04C3b20F08B1D51F7429b2205491183A7b3583F; // aREUSD aToken
    address constant REG   = 0x0AA1e96D2a46Ec6beB2923dE1E61Addf5F5f1dce; // REG collateral token
    address constant POOL  = 0xFb9b496519fCa8473fba1af0850B6B8F476BFdB3; // Pool (proxy)

    // _userInfo mapping is at storage slot 362 of the manager impl; regLock is the struct's first field.
    // slot(regLock[user]) = keccak256(abi.encode(user, 362)). Verified live against a real locker
    // (0xa3c3..e855 -> 50e18) before writing this test; each test re-asserts the readback, so a wrong
    // slot fails loudly instead of silently.
    uint256 constant USERINFO_SLOT = 362;

    // PERMISSION_ERROR() from the REUSD token (Reusdv2) -- the role gate on burn()
    bytes4 constant PERMISSION_ERROR = 0x03104826;

    uint256 gnosis;

    function setUp() public {
        // pin a recent block; aREUSD has held REUSD since block 46,016,118 so any recent block reproduces
        gnosis = vm.createSelectFork("gnosis", 47956260);
    }

    function _aReusdReusdBalance() internal view returns (uint256) {
        // resolve the aToken from the live Pool (proves AREUSD is the real REUSD aToken, not a guess)
        address aReusd = IPool(POOL).getReserveData(REUSD).aTokenAddress;
        assertEq(aReusd, AREUSD, "resolved aREUSD must match the constant");
        return IERC20(REUSD).balanceOf(aReusd);
    }

    function _giveRegLock(address user, uint256 amount) internal {
        bytes32 slot = keccak256(abi.encode(user, USERINFO_SLOT));
        vm.store(MGR, slot, bytes32(amount));
        // self-validate the slot: the public getter must now report exactly what we wrote
        assertEq(IManager(MGR).getUserLockedReg(user), amount, "USERINFO_SLOT is wrong -- getter mismatch");
    }

    /// The bug: an eligible user (regLock>0, zero REUSD debt) cannot reclaim REG.
    function test_withdrawReg_is_bricked_by_unauthorized_sync_burn() public {
        // precondition that arms the bug: the REUSD aToken holds a nonzero REUSD balance
        uint256 aReusdBal = _aReusdReusdBalance();
        assertGt(aReusdBal, 0, "precondition: aREUSD must hold REUSD for the burn to fire");
        console2.log("aREUSD REUSD balance (wei):", aReusdBal);

        // a fresh, withdraw-ELIGIBLE user: has locked REG, and (being fresh) carries zero REUSD debt
        address user = makeAddr("eligibleLocker");
        _giveRegLock(user, 50e18);

        // the ONLY self-serve REG-reclaim path reverts on the unauthorized sync burn, not on any user check
        vm.prank(user);
        vm.expectRevert(PERMISSION_ERROR);
        IManager(MGR).withdrawReg();
    }

    /// Root cause = the sync burn: neutralise ONLY the burn (empty the aREUSD REUSD balance) and the
    /// exact same call succeeds and returns the REG. Nothing else about the user changed.
    function test_root_cause_is_the_sync_burn() public {
        address user = makeAddr("eligibleLocker2");
        _giveRegLock(user, 50e18);

        // with REUSD in the aToken, the call is bricked...
        assertGt(_aReusdReusdBalance(), 0);
        vm.prank(user);
        vm.expectRevert(PERMISSION_ERROR);
        IManager(MGR).withdrawReg();

        // ...neutralise ONLY _syncReusdBalance (make its burn a no-op by zeroing the balance it burns)...
        deal(REUSD, AREUSD, 0);
        assertEq(_aReusdReusdBalance(), 0);

        // ...and the identical call now succeeds and delivers the locked REG to the user.
        uint256 before = IERC20(REG).balanceOf(user);
        vm.prank(user);
        IManager(MGR).withdrawReg();
        assertEq(IERC20(REG).balanceOf(user) - before, 50e18, "user should receive their 50 REG once the burn no-ops");
        assertEq(IManager(MGR).getUserLockedReg(user), 0, "regLock cleared");
    }

    /// Re-arm: a single wei of REUSD dust in the aToken bricks it again -> anyone can grief it permanently.
    function test_one_wei_of_reusd_dust_rearms_the_brick() public {
        address user = makeAddr("eligibleLocker3");
        _giveRegLock(user, 50e18);

        deal(REUSD, AREUSD, 1); // a single wei of REUSD is enough to make the burn fire and revert
        assertEq(_aReusdReusdBalance(), 1);

        vm.prank(user);
        vm.expectRevert(PERMISSION_ERROR);
        IManager(MGR).withdrawReg();
    }
}
