# HUNT — Morpho Midnight (live-target test of the upgraded pipeline)

**Target:** Morpho Midnight — non-custodial fixed-rate lending (isolated immutable markets, credit/debt units
settling at maturity). Morpho-org. Has `audits/` + Certora CVL formal proofs. 32 prod `.sol`.
**Goal of this pass:** first end-to-end run of the upgraded system (17 recon detectors → triage → invariant templates)
on real, fresh code. NOT a bounty submission — a system-validation + skill rep.
**Source:** `cache/cand-morpho-midnight/src` (cloned). Recon report: `cache/morpho-midnight-recon.txt`.

## What the NEW detectors surfaced (3 leads, all in `Midnight.sol`)
| Lead | Detector | Verdict |
|---|---|---|
| `liquidate` (590) | det_liquidation `[!]` | **refuted** — well-built |
| `claimSettlementFee` (309) | det_reward `[.]` | **refuted** — FP |
| `claimContinuousFee` (316) | det_reward `[.]` | **refuted** — FP |

## Triage (verify-before-claiming — read the real code)
**`liquidate` (590) — REFUTED, the liquidation is sound:**
- Health gate present: `require(... originalDebt > maxDebt ..., NotLiquidatable())` (629-633) — can't liquidate a
  solvent position (`maxDebt` = Σ collateral·price·lltv).
- Rounding is **protocol-favorable**: `repaidUnits` (liquidator pays) rounds **up** via `mulDivUp` (658-659);
  `seizedAssets` (liquidator receives) rounds **down** via `mulDivDown` (660-661). Correct direction.
- Close factor present: `maxRepaid` + `RecoveryCloseFactorConditionsViolated` (664-677).
- Bad debt explicitly socialized via `lossFactor`/`totalUnits` (635-650), not silently dropped.
- Self-liquidation not blocked but harmless (own collateral; only when already unhealthy).

**`claimSettlementFee` / `claimContinuousFee` — REFUTED, FPs:**
- Both gated to `feeClaimer` (admin fee-claim, not a per-user reward replay).
- Both **decrement the claimable accounting before the transfer** (`claimableSettlementFee[token] -= amount` 311;
  `continuousFeeCredit/totalUnits/withdrawable -= amount` 322-324) → entitlement consumed, CEI-correct.

## Outcome — no finding, but the system learned (2 precision fixes)
The detectors correctly *surfaced* real entry points; reading the code refuted each (expected for Morpho-org). The FPs
exposed two gaps, fixed + regression-tested (75 tests):
- **fix#21 `det_reward`:** a `-=` decrement of a claimable/balance var before the payout now counts as "entitlement
  consumed" (admin fee-claims no longer FP; `SafeTransferLib` no longer misread as a thin Lib-delegator).
- **fix#22 `det_liquidation`:** `[!]` reserved for **no visible health gate** (the liquidate-a-healthy bug); with a
  gate it's `[.]`, and the rounding note clarifies repaid-side up-rounding is protocol-favorable.

After the fixes: det_reward 2→0 on this target; det_liquidation `liquidate` `[!]`→`[.]`.

**Lesson (reinforced):** maintained, audited+formally-verified protocols are well-built — leads dissolve on a careful
read. The durable value of a "negative" hunt is the precision the system gains from real code.
