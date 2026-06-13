# Ledgity Yield — WrappedLToken progressive undercollateralization (daily-compound rate vs linear underlying accrual)

**Severity:** Latent / Informational (real code bug, but the buggy wrapper is UNDEPLOYED (generic) / EMPTY (Sonic) -> no live funds at risk today; see Verification). Would be Medium IF the wrapper is ever funded.
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

### Who bears the loss (honest framing)
This is a **user-side, protocol-neutral** issue. The wrapper holds a FIXED lToken pool (it accrues exactly its
linear share from `LToken`; the inflated `exchangeRate` is internal and does NOT make the wrapper over-claim
from the protocol). The over-projection only mis-**distributes** that pool: it is a **zero-sum redistribution
among wrapped-holders** (early exiters gain, late/last exiters lose / get bricked), plus a liveness tail (the
last holder is stuck, not destroyed — partial exit / await top-up). Therefore:
- **LToken supply / RWA backing / protocol treasury: unaffected.** No protocol funds are at risk.
- **The protocol only pays IF it chooses to backstop** the wrapper (top up lToken to make late users whole) —
  then it absorbs the ~0.5%/yr; otherwise the cost falls on late wrapped-holders.
- So this is "**user funds at risk + unfair exit ordering / griefable**", not "protocol drain". Real and worth
  fixing (user funds), but the team should not dismiss it as "we lose nothing" — *their users* do, by default.

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
`toRebasingAmount(wrapped) = wrapped * lToken.balanceOf(address(this)) / totalSupply()`. Drop the parallel
daily-compound `exchangeRate`/`baseRate`/checkpoint machinery entirely — the underlying's own rebasing
already reflects realized yield.

**The contract already computes the correct measure** — `totalAssets()` (WrappedLToken.sol:424-427) returns
`lToken.balanceOf(address(this))`. The redemption path just doesn't use it: `_unwrap` pays
`toRebasingAmount()` (the daily-compound projection) instead of the `totalAssets()/totalSupply()` share. So
the fix is to route redemption through the value the contract already tracks for ERC4626 — a small change,
not a redesign.

## Verification (2026-06-13, default branch `dev`) -- DEPLOYMENT GATE FAILS: not live today

The CODE bug is real and unfixed:
- `exchangeRate()` on `LedgityLabs/ledgity-v2-contracts@dev` still daily-compounds (the
  `for (i<fullDays) compoundedRate = compoundedRate*(RAY+dailyRatio)/RAY` loop is intact); `_unwrap` still pays
  `toRebasingAmount()` with **no cap** against `lToken.balanceOf(this)`.
- Unchanged since 2025-08-27 (last commit on the file = folder restructure); no SECURITY.md, no issue, not in
  the repo's own Slither report, DefiLlama `audits=0` -> unfixed and unreported.

But the **deployment gate fails**, so there is no live impact today:
- The generic `WrappedLToken` (this report's contract) is **NOT deployed** on any chain — `data/deployments.json`
  has no entry; Base/Arbitrum/Linea ship only the LToken (LUSDC), no wrapper.
- The ONLY deployed wrapper is `WrappedLTokenSonic` (Sonic, `0xeD758d19DC4086775Fe23c2EcC18F66Fb7F68262`), which
  **inherits** the buggy `exchangeRate`/`_unwrap` — but on-chain it is **empty**: `totalSupply()==0`,
  `exchangeRate()==0`, `totalAssets()` reverts (uninitialized). Zero wrapped value -> nothing to redistribute.
- The protocol's ~$3M TVL is in the LToken (LUSDC), **not** the wrapper; the wrapper is unused.

**Conclusion:** a real, latent code bug, but **no funds are at risk today**. Correct handling = a low-priority
"fix the wrapper before it is funded" courtesy note, NOT a "Medium, user funds at risk" disclosure. Re-evaluate
IF the wrapper is ever populated (totalSupply > 0).

## Provenance & disclosure
Deployed, multi-chain (Base/Ethereum/Linea/Arbitrum/Sonic), ~$3M TVL, **no external audit** (DefiLlama
`audits=0`; not covered by the repo's Slither report). **No formal bug-bounty program was found** (no
Immunefi listing; the README cites only Slither + "security-first" branding). -> Responsible **direct
disclosure** to the Ledgity team (their official contact / security channel), white-hat, before any public
mention. (No paid program -> reputational, not a payout.)
