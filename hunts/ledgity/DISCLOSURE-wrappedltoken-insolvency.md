# Ledgity Yield — WrappedLToken progressive undercollateralization (daily-compound rate vs linear underlying accrual)

**Severity:** Medium (growing solvency deficit; value transfer from late to early unwrappers; last unwrapper bricked)
**Component:** `WrappedLToken` (non-rebasing wrapper for `LToken`)
**Status:** deployed; no external audit listed (DefiLlama `audits=0`); the contract is absent from the repo's own `audit/slither-report.md`.

## Summary
`WrappedLToken` represents wrapped (non-rebasing) value via an `exchangeRate()` that **daily-compounds**
the underlying APR. But the underlying `LToken` it custodies accrues a holder's balance **linearly within
each APR period**. Daily-compounding grows faster than linear, so the wrapper's redemption obligation
(`totalSupply * exchangeRate / RAY`) progressively exceeds the lTokens it actually holds
(`lToken.balanceOf(wrapper)`). The wrapper becomes undercollateralized: early unwrappers redeem at the
inflated rate and the last unwrapper's `lToken.transfer` reverts (bank-run / stuck funds).

## Affected code
- `WrappedLToken.sol:114-148` `exchangeRate()` — daily-compounds `baseRate` at `lastCheckpoint.apr`:
  ```solidity
  for (uint256 i = 0; i < fullDays; i++) compoundedRate = (compoundedRate * (RAY + dailyRatio)) / RAY;
  ```
- `WrappedLToken.sol:247` `_unwrap()` -> `toRebasingAmount(wrappedAmount) = wrappedAmount * exchangeRate() / RAY`,
  then `lToken.transfer(to, lTokenAmount_)` — **no cap against the actual balance held**.
- `WrappedLToken.sol:186` `updateRateCheckpoint()` — re-bases only when `lToken.getAPR()` CHANGES, and sets
  `baseRate = exchangeRate()` (the already-over-projected rate, **never reconciled to `lToken.balanceOf(this)`**),
  so the drift is locked in and compounds across periods.
- Mismatch source — `InvestUpgradeable.sol:265-292` `_calculatePeriodRewards()`: `growth = elapsedYears * apr`
  (LINEAR within a period; LToken auto-compounds only ACROSS APR checkpoints).

## Root cause
The wrapper tracks growth via a **parallel APR projection** (daily compounding) instead of the **actual
underlying balance** it holds. The two diverge for any `apr > 0` over a multi-day stable-APR window:
`exchangeRate()` (daily-compound) > underlying per-share accrual (linear) -> the wrapper owes more than it holds.

## Impact
- The wrapper is progressively undercollateralized. Unwraps are first-come-first-served at the inflated rate,
  so **early unwrappers over-redeem at the expense of late ones**; the final unwrapper's `lToken.transfer`
  reverts (cannot exit / stuck funds).
- Magnitude = the (daily-compound − linear) premium over the inter-checkpoint window: ~0.47% of wrapped TVL
  at 10% APR stable for one year (PoC below); larger at higher APR or longer stable periods, and it
  accumulates across periods (each checkpoint bakes the prior over-projection into `baseRate`).
- Not an instant drain — a slow solvency leak concentrated on the last exiters. Hence Medium.

## PoC (Foundry, deterministic — reimplements both formulas verbatim)
`invariant-lab/test/WrappedLTokenInsolvencyPoC.t.sol` — `forge test --match-contract WrappedLTokenInsolvencyPoC -vv`:
```
test_wrapperOverProjects_vs_linearUnderlying:
  wrapper owes  (daily-compound): 1105.155781...   (1000 wrapped, 10% APR, 1 year)
  wrapper holds (linear LToken) : 1100.000000...   -> over-projection 0.47%
test_bankRun_lastUnwrapperBricked:
  pool left after A unwraps: 1094.844218...
  user B is owed           : 1105.155781...        -> B's lToken.transfer reverts (insolvent)
```

## Recommendation
Make the wrapper **balance-backed** (the wstETH pattern), so it can never owe more than it holds:
`toRebasingAmount(wrapped) = wrapped * lToken.balanceOf(address(this)) / totalSupply()` (an ERC4626
`totalAssets() == lToken.balanceOf(this)`). Drop the parallel daily-compound `exchangeRate`/`baseRate`/
checkpoint machinery entirely — the underlying's own rebasing already reflects realized yield.

## Provenance & disclosure
Deployed, multi-chain (Base/Ethereum/Linea/Arbitrum/Sonic), ~$3M TVL, **no external audit** (DefiLlama
`audits=0`; not covered by the repo's Slither report). **No formal bug-bounty program was found** (no
Immunefi listing; the README cites only Slither + "security-first" branding). -> Responsible **direct
disclosure** to the Ledgity team (their official contact / security channel), white-hat, before any public
mention. (No paid program -> reputational, not a payout.)
