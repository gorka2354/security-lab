// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import {Test} from "forge-std/Test.sol";

/// @title WrappedLToken insolvency PoC (Ledgity Yield, scout-v2 find)
/// @notice Demonstrates the accrual mismatch between WrappedLToken.exchangeRate() (DAILY-COMPOUND)
///         and the underlying LToken's per-holder accrual (LINEAR within an APR period). The wrapper
///         promises more lTokens than it holds -> undercollateralized -> the last unwrapper is bricked.
/// @dev Reimplements the two formulas VERBATIM from the live code so the divergence is undeniable:
///   - wrapper rate:  WrappedLToken.sol:114-148 exchangeRate()  (daily-compound of baseRate at apr)
///   - underlying:    InvestUpgradeable.sol:265-292 _calculatePeriodRewards()  (growth = elapsedYears*apr, LINEAR)
contract WrappedLTokenInsolvencyPoC is Test {
    uint256 constant RAY = 1e27;

    // --- VERBATIM from WrappedLToken.exchangeRate() (WrappedLToken.sol:114-148) ---
    // aprStored = lToken.getAPR()(UD7x3) * RAY / 1000  (set in updateRateCheckpoint; "1% = 1 RAY").
    function wrapperExchangeRate(uint256 baseRate, uint256 aprStored, uint256 timeElapsed)
        internal
        pure
        returns (uint256 rate)
    {
        rate = baseRate;
        uint256 fullDays = timeElapsed / 1 days;
        uint256 remainingTime = timeElapsed % 1 days;
        uint256 aprBaseOneRay = aprStored / 100; // 100% = 1 RAY
        uint256 dailyRatio = aprBaseOneRay / 365;
        for (uint256 i = 0; i < fullDays; i++) {
            rate = (rate * (RAY + dailyRatio)) / RAY; // DAILY COMPOUND
        }
        if (remainingTime > 0) {
            uint256 remainingRatio = (aprBaseOneRay * remainingTime) / 365 days;
            rate = (rate * (RAY + remainingRatio)) / RAY;
        }
    }

    // --- VERBATIM logic from InvestUpgradeable._calculatePeriodRewards (InvestUpgradeable.sol:265-292) ---
    // growth = elapsedYears * apr ; rewards = invested * growth / 100  -> LINEAR in elapsed time.
    // aprUD7x3: 10000 == 10.000%.  rewards = invested * aprUD7x3 * elapsed / (1000*100*365days).
    function underlyingBalance(uint256 principal, uint256 aprUD7x3, uint256 elapsed)
        internal
        pure
        returns (uint256)
    {
        uint256 rewards = (principal * aprUD7x3 * elapsed) / (100000 * 365 days);
        return principal + rewards; // LINEAR accrual (no within-period compounding)
    }

    /// @notice The wrapper OWES more lTokens than the underlying balance it HOLDS -> undercollateralized.
    function test_wrapperOverProjects_vs_linearUnderlying() public {
        uint16 aprUD7x3 = 10000; // 10% APR, stable for the whole window (no checkpoint re-base)
        uint256 aprStored = (uint256(aprUD7x3) * RAY) / 1000; // == 10 * RAY
        uint256 principal = 1000e18; // lTokens wrapped at t0 (baseRate == RAY -> 1:1 -> 1000 wrapped)
        uint256 elapsed = 365 days;

        // After 1y of STABLE apr: redemption rate (daily-compound) vs underlying balance (linear)
        uint256 rate = wrapperExchangeRate(RAY, aprStored, elapsed);
        uint256 owedPerUser = (principal * rate) / RAY; // toRebasingAmount(1000 wrapped)
        uint256 heldPerUser = underlyingBalance(principal, aprUD7x3, elapsed);

        emit log_named_decimal_uint("wrapper owes  (daily-compound)", owedPerUser, 18);
        emit log_named_decimal_uint("wrapper holds (linear LToken) ", heldPerUser, 18);
        // The bug: the wrapper promises strictly MORE than the underlying actually accrues.
        assertGt(owedPerUser, heldPerUser, "expected daily-compound > linear (over-projection)");
    }

    /// @notice Two equal wrappers; after 1y the pool is short -> user A over-redeems, user B is bricked.
    function test_bankRun_lastUnwrapperBricked() public {
        uint16 aprUD7x3 = 10000; // 10%
        uint256 aprStored = (uint256(aprUD7x3) * RAY) / 1000;
        uint256 principal = 1000e18;
        uint256 elapsed = 365 days;

        // Wrapper holds both users' lTokens, accruing LINEARLY (per LToken's formula).
        uint256 poolHeld = underlyingBalance(2 * principal, aprUD7x3, elapsed); // ~2200e18

        // Each user redeems at the DAILY-COMPOUND rate (no balance cap in _unwrap).
        uint256 rate = wrapperExchangeRate(RAY, aprStored, elapsed);
        uint256 owedPerUser = (principal * rate) / RAY; // ~1105.16e18

        // User A unwraps first -> succeeds, draining the pool.
        assertGe(poolHeld, owedPerUser, "A should be coverable");
        uint256 afterA = poolHeld - owedPerUser;

        // User B unwraps -> the pool can no longer cover the (over-projected) obligation: lToken.transfer reverts.
        emit log_named_decimal_uint("pool left after A unwraps", afterA, 18);
        emit log_named_decimal_uint("user B is owed           ", owedPerUser, 18);
        assertLt(afterA, owedPerUser, "BUG: pool short -> B's lToken.transfer reverts (bank-run / insolvency)");
    }
}
