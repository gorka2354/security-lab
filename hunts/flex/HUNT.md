# HUNT — Flex (fixed-rate money market, Liquity-V2-style, Vyper core) — Ethereum mainnet

Sourced via the under-reviewed mixed-chains fan-out (2026-06-14). Deep-dive of the top DIG-CAREFUL lead:
**FLEX-002 — upfront-fee average-rate manipulation** (April-27 audit finding).

## Verdict: CONFIRMED-but-KNOWN + atomic exploit MITIGATED + cross-block residual marginal + NO scope -> NOT a finding.

### 1. The bug is live in deployed code
`src/trove_manager.vy:_get_upfront_fee` (1396-1402) prices the upfront fee off the **post-insertion** branch average:
```vyper
new_total_debt          = self.total_debt          + debt_amount               # 1396 (is_existing_debt=False)
new_total_weighted_debt = self.total_weighted_debt + debt_amount*annual_rate    # 1399
avg_interest_rate       = new_total_weighted_debt // new_total_debt             # 1402  <- after the new debt, no floor
```
This is exactly FLEX-002. The audit's **primary** structural fix (compute the average BEFORE the new debt + floor to `max(avg, k*borrower_rate)`) was **NOT applied**. Used by `open_trove:368`, `borrow:567`, `adjust_interest_rate:733`.

### 2. The atomic exploit the audit described is BLOCKED
The audit's High was an **atomic** round-trip: open a huge helper trove `H` at min rate (depress avg) -> do the real fee-bearing action (priced against the depressed avg) -> `close_trove(H)` in the same tx (zero elapsed interest = nearly free). The team's mitigation (audit rec#2, NOT rec#1) is a **same-block guard**:
```vyper
# close_trove:810  and  the borrow/repay path:644
assert convert(trove.last_debt_update_time, uint256) != block.timestamp, "same block"
```
`H` is opened at `block.timestamp` so it **cannot be closed in the same block** -> the atomic free round-trip reverts. The deployed code is NOT vulnerable to the exact attack the audit described.

### 3. Residual cross-block variant — mechanically possible, economically marginal
Open `H` in block N; in block N+1 do the real action (avg still depressed, `H` open) then `close_trove(H)` (its `last_debt_update_time` = block N != block N+1 -> guard passes). Bypasses the guard, BUT:
- `H` must post collateral >= `minimum_collateral_ratio * H_debt` and pays its **own** upfront fee + 1 block of interest.
- To depress the average meaningfully, `H_debt` ~ total market debt `D`.
- Profitability is self-limiting: the helper's upfront fee (min-rate on a large principal) tends to offset the saving (avg-delta on a smaller real position); strictly worse than the now-blocked atomic version. Profitable only in a **thin/new market** with a large attacker position. Conditional Medium at most.

### 4. Scope
**No authorized bounty** — no SECURITY policy / Immunefi / scope anywhere in the repo; solo project (`johnnyonline/Flex`). FLEX-002 is a **known** audit finding. -> not a disclosable-for-reward target. the operator could goodwill-notify the dev that the same-block guard leaves a (marginal) cross-block residual; no reward.

## Value of this dig (honest)
- Validated the **audit-drift lane**: recon is Solidity-tuned and saw 0 of the Vyper core -> the lead came from manual skim + audit cross-ref, and the deep-dive pinned (a) the live drift, (b) the partial mitigation, (c) the exact residual + why it's bounded.
- Another honest **confirmed-but-non-disclosable** (known + mitigated-atomic + no scope) -> consistent with the lab's ZERO-live-impact calibration: density is gated by FRESHNESS + SCOPE, not tooling.
