# Parked leads — real bugs, no bounty yet (white-hat: dig only when a program opens)

These are DEPLOYED + funded protocols with a concrete bug hypothesis but **no in-scope authorized
bounty/contest** today. White-hat rules block digging now. `monitor/watchlist.json` watches each one's
launch surface (Immunefi + Cantina + Code4rena + Sherlock); `toolkit/watch_all.sh` runs it on cron
(every 4h) and appends FIREs to `monitor/ALERTS.md`. On FIRE → dig the preserved lead FIRST (timing edge).

Sourced 2026-06-26 from the `defillama-immunefi-wave` fan-out (`hunts/_fanout/2026-06-26-...md`).

---

## 1. Vena Finance — Pyth oracle missing guards  (Aave-V3 fork, Fluent L2, ~$19.9M TVL)
- **Core identity:** fork of `aave-v3-origin` (v0.8 lineage). Lending engine = verbatim Aave V3 (audited-by-lineage,
  NOT the surface). The custom **drift = the Pyth oracle stack** = the hunt surface.
- **Lead (TRIAGE-level hypothesis):**
  - `src/PythAggregatorAdapter.sol:19-35` — `latestAnswer()` reads the Pyth price with **NO `price > 0`** and
    **NO confidence-interval / staleness** guard → a zero/stale/wide-confidence push flows straight into `AaveOracle`.
  - `:34` — divide-before-multiply precision loss on high-exponent feeds.
  - `src/AaveOracle.sol:109` + `PythProAggregatorAdapter.decimals()` — base-currency-unit vs adapter-decimals mismatch.
- **Why it could pay:** mispriced collateral across the whole money market → over-borrow (price stale-high) or
  wrongful liquidation (stale-low / zero). Push-price dependent (needs Pyth to publish a bad value), so impact
  hinges on confirming the WEAK adapter (`PythAggregatorAdapter`) is the one actually wired for a live reserve
  (vs the hardened `PythProAggregatorAdapter`).
- **First step on FIRE:** read `AaveOracle.getSourceOfAsset(asset)` per live reserve (fluentscan `eth_call`) →
  which assets use the weak adapter. Then Foundry: feed a `price=0` / stale push, show a borrow/liq that shouldn't pass.
- **Artifacts:** `hunts/_volume/vena-finance/src/` (PythAggregatorAdapter.sol, PythProAggregatorAdapter.sol,
  VenaPythPrices.sol, AaveOracle.sol, Pool.sol). Re-source if cleaned: scout said no DefiLlama github; the agent
  pulled verified source from Fluent — re-fetch the reserve/oracle addresses via the Fluent explorer + `fetch_source`.

## 2. GAIB — sAID vault deposit-vs-exit valuation asymmetry  (AID synthetic dollar, ~$126M TVL)
- **Core identity:** greenfield custom ERC-4626 vault (`sAID`), no audited base matched. OZ `ERC4626Upgradeable`
  deposit/mint reused; the protocol **OVERRIDES the exit/redeem path** with a bespoke FIFO unstake queue,
  linear reward vesting, and an `unrealizedLoss` valuation — that override is the surface.
- **Lead (TRIAGE-level hypothesis):**
  - **Deposit-vs-exit asymmetry:** `sAID.sol:420` (`totalAssets`, OZ — no loss) vs `:514` (`totalAssetsWithLoss`) /
    `:538-547` (`convertWithLoss`). Deposits price WITHOUT the loss; redeems WITH it → a depositor in between may
    mint shares cheaply then exit, socializing/extracting value.
  - **Unbacked liquidity drain:** `:367` `deploy()` lowers `availableForUnstake` but **not** `trackedAssets`;
    `:382` `setUnrealizedLoss`; `:324-348` `processUnstakeQueue`.
  - **FIFO partial-fill head-advance:** `:301-349` (`:328-335` partial branch); `:389-399` `reconcileAssetBalance` sweep.
- **Why it could pay:** if deposit valuation (no loss) and redeem valuation (with loss) diverge while a queue is
  pending, an attacker mints at the high NAV and redeems against the asymmetry → drain of unbacked value. $126M TVL.
- **First step on FIRE:** Foundry differential — `deposit()` (OZ `totalAssets`, no loss) vs `unstake/redeem`
  (`totalAssetsWithLoss`) around a `setUnrealizedLoss` + `deploy()`; assert no free value.
- **Artifacts:** `fetched/1_0x05b6bb5e57a52c7c5c9c063ea0e721ea2ccc732d/src/sAID.sol`. Re-fetch:
  `python3 toolkit/fetch_source.py 0x05b6bb5e57a52c7c5c9c063ea0e721ea2ccc732d --chain 1 --proxy`.
- **Note:** docs claim an "Octane" (AI) audit only — lightweight; real review likely thin = higher EV when a program opens.

---

### Discipline
- Both are **hypotheses**, not confirmed bugs. Do the Foundry PoC + Gate-0 (live + in-scope) before any severity claim.
- Do NOT engage either protocol until `monitor/watchlist.json` FIREs (a real authorized program). egor discloses, never me.
