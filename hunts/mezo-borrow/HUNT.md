# HUNT: Mezo Borrow (mezo-org/musd) -- fan-out candidate #2 (2026-06-13)

- **What:** BTC-backed MUSD CDP. Fork of **Liquity v1** (Threshold-USD lineage) + a **custom interest-accrual
  layer** bolted onto interest-FREE Liquity v1 + BorrowerOperationsSignatures meta-tx + PCV + refinance.
- **Reach:** the DefiLlama address `0x7b7c..0001` = MEZO **gov token** (not the CDP). Real CDP core resolved
  via docs -> `mezo-org/musd` (raw.githubusercontent). Clone: `hunts/_volume/fanout-mezo-borrow/src`.
- **Live:** ACTIVE, ~$29M. MUSD debt token `0xdD468A1DDc...F9F186` totalSupply ~29.2M. TroveManager
  `0x94AfB503...c193`, BorrowerOperations `0x44b1bac6...dEe031`, PriceFeed `0xc5aC5A88...fCa88` (Mezo mainnet).
- **forkdrift:** LIKELY FORK of Liquity (6 sigs). **Cantina-audited** (mezo-org/audits, mUSD 2025-04-15).
  Fork -> hunt the DRIFT (the custom interest layer Liquity's audit never covered).

## Deep L4 -- the interest-accrual layer (the one real drift surface) is HARDENED
Model: `interestNumerator = SUM(principal_i * rate_i)`; `updateSystemInterest()` accrues
`(now - lastUpdatedTime) * interestNumerator / (BPS * yr)`, mints to PCV + bumps ActivePool debt. Per-trove
interest tracked independently via `trove.lastInterestUpdateTime`.

**The lead was the accumulator-update ORDERING** (a new/removed principal must not accrue for time it didn't
exist). Verified across EVERY trove-mutating path -- all call `updateSystem(AndTrove)Interest` FIRST, before
any `interestNumerator` change:
- `_openTrove` -> `updateSystemInterest()` before addPrincipal (BorrowerOperations.sol:626)
- `_adjustTrove` -> `updateSystemAndTroveInterest(_borrower)` first (:769)
- `_closeTrove` -> first (:945)
- `_refinance` -> first (:1021), then removePrincipal(old,oldRate)+addPrincipal(old,newRate)
- `batchLiquidateTroves` -> `updateSystemInterest()` then per-trove `_updateTroveInterest` (TroveManager:662-667)
- `_updateTroveInterest` accrues `trove.interestOwed` at the OLD rate + sets `lastInterestUpdateTime = now`
  BEFORE the rate/principal change -> correct.

So the system aggregate and the per-trove accrual are always synced before the numerator moves. No mis-accrual
/ system-debt-vs-sum-of-trove-debt divergence reproduces. Other leads de-risked: PriceFeed only checks
staleness but the oracle is a Mezo **system predeploy** (protocol-trusted, not a manipulable market feed);
BorrowerOperationsSignatures meta-tx is skim-clean (signer==borrower, per-borrower nonce, deadline); PCV is
internally gated.

## Verdict: IE / hardened -- closed, not disclosed
Cantina-audited Liquity fork; the bespoke interest layer maintains accumulator-update discipline. Like eva,
the deep L4 finds no demonstrable exploit. **2/2 of the fan-out's deep-dived live candidates came back hardened**
-> the reachable space is hardened-dominated; finding-density is gated by FRESHNESS, not tooling (the memory
lesson, re-confirmed). See [[fanout-triage-workflow-validated]] + [[next-scout-v2-underreviewed-targets]].
