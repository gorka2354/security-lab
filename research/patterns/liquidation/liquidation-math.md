# Pattern 05 — Liquidation math

**Tier:** T2/T3 — pure business-logic + rounding. Almost nothing here is regex-catchable; the bug is in *who profits* and
*what state the position is in afterward*.
**One line:** the liquidation path lets the liquidator **take more than the bonus, leave the position unhealthy, profit
from their OWN position, or push bad debt onto others** — because a health check, close-factor, or rounding direction is wrong.

## 1. Mechanism
The recurring faults:
1. **Self-liquidation profit** — nothing stops `liquidator == borrower`; the liquidation *bonus* on your own collateral
   is a free withdrawal that bypasses normal exit limits/fees.
2. **Liquidating a healthy position** — the health check reads a **manipulable price** (→ [oracle-manipulation](../pricing/oracle-manipulation.md))
   or a stale index, so a flash-move makes a healthy position "liquidatable" for the bonus.
3. **Close-factor / threshold** — you can seize **100% when only 50% is allowed**, or the "leftover dust < threshold →
   liquidate all" branch is abusable to over-seize.
4. **Rounding direction** — `seize = mulDiv(repay, price·bonus, …)` rounds **up in the liquidator's favor**, or `debt`
   rounds down, so each liquidation skims a little; repeated, it's a drain.
5. **Bad-debt socialization** — when `collateral < debt`, the loss must go somewhere; if it's silently dropped or
   socialized to the wrong pool, an attacker can *create* bad debt and stick others with it.

## 2. Real examples
- **TermMax (first-hand) — well-built, studied as reference.** Liquidation path checked health post-action, bounded the
  bonus, and handled the collateral/debt rounding in the protocol's favor → no finding, but the *shape* is the checklist.
- **Crypto Unicorns lending bits (first-hand):** same triage — health recheck + close-factor present.
- **Class at large:** Aave/Compound-fork incidents almost always trace to (2) manipulable health price or (5) bad-debt
  mishandling on illiquid collateral.

## 3. The "tell"
- Find the liquidation entrypoint (`liquidate`, `liquidationCall`, `seize`, `close`). Read four things:
  1. **Health source** — manipulable (spot/index) or robust (TWAP/clamped/Chainlink-3-guard)?
  2. **`liquidator == borrower`** allowed? Any check?
  3. **Close-factor** — capped per call? Can the "dust → full" branch be triggered cheaply?
  4. **Rounding** — does `seize` round up and `repay`/`debt` round down (both favor the liquidator)?
- **The $-question:** *after a successful liquidation, is the position strictly healthier-or-closed and is liquidator
  profit ≤ the configured bonus?* If either can be violated → finding.

## 4. Detector idea (static, T0/T1) — det_liquidation
- Very limited. Flag a `liquidat*`/`seize`/`close` function that (a) has **no `from != msg.sender`-style** self-liq guard,
  or (b) computes `seize` with `mulDivUp`/`mulDivRoundingUp` while the *repay/debt* side rounds down. Emit as a **lead**.
- **Honest limit:** the core bugs (manipulable health, bad-debt routing) are economic/cross-file → **T3**. Don't pretend
  regex catches them; det_liquidation only surfaces the self-liq-guard gap and rounding asymmetry.

## 5. Hypothesis / invariant (T2/T3)
- **Hypothesis:** "can a liquidation leave the system worse — unhealthy position, liquidator profit > bonus, or new
  unaccounted bad debt?" Enumerate price source, self-liq, close-factor, rounding, bad-debt branch.
- **Invariants to fuzz:**
  - **No self-profit:** if `liquidator == borrower`, net value extracted ≤ 0 (or path reverts).
  - **Monotone health:** `healthFactor(after) ≥ healthFactor(before)` OR position fully closed.
  - **Bonus bound:** `liquidatorGain ≤ repay · maxBonus`.
  - **Bad-debt conservation:** `Σ debt − Σ collateralValue` only increases through the explicit socialization sink, never silently.

## 6. Mitigations to RECOGNIZE (avoid FP)
- **Post-action health recheck** + **close-factor cap** (TermMax had both).
- **Robust health price** (TWAP/clamped/Chainlink-3-guard) — kills the manipulable-health vector.
- **Protocol-favorable rounding** (seize down / debt up) and **explicit bad-debt sink** (reserve fund, socialization to a
  defined pool with accounting).
- **Self-liq either disallowed or economically neutral** (bonus doesn't apply to own position).
