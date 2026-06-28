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

## 3. Panoptic V2 — LAUNCH-WATCH (no hypothesis yet)  (options AMM, ETH + Unichain, ~$1.3M TVL)
- **Source:** fresh DefiLlama listing 2026-06-19 (`freshfeed.py`, our-zone:option). Surfaced 2026-06-28.
- **Why parked (not dug):** bounty is **PAUSED** — Panoptic V1 bounty paused while completing V2 audits; the V2
  bounty (Cantina) "launches at V2 release", not live yet → white-hat: no authorized scope today.
- **Why it's worth a watch (high EV on launch):** options AMM = heavy custom math (liquidation / collateral
  settlement / oracle) = our **reasoning-tier zone** where regex-tier tools are blind. Fresh on-chain, EVM-reachable.
- **Hardened caveat:** already combed by **Nethermind NM-0701** + the **Code4rena "Panoptic: Next Core"** contest,
  and the issues were **mitigated**. So on launch the hunt is the **post-mitigation V2 drift** (incomplete fixes,
  new code added after the audit), NOT the audited base. Cross-ref the mitigated NM-0701 / C4 findings first.
- **Scope (from panoptic.xyz/docs/security/bug-bounties):** SemiFungiblePositionManager, PanopticFactory, and any
  pool deployed by PanopticFactory; chains = Ethereum mainnet + Unichain.
- **First step on FIRE:** confirm the live Cantina scope + V2 deployed addresses → `fetch_source` the factory +
  a live pool → diff vs the audited panoptic-v2-core commit (audit-drift) → recon/hypothesize on the drift only.
- **No artifacts yet** (no hypothesis): pre-study the options/liq/oracle math BEFORE fire to land in the first hours.

---

### Discipline
- #1 and #2 are **hypotheses**, not confirmed bugs; #3 is a launch-watch with no hypothesis yet. Do the Foundry
  PoC + Gate-0 (live + in-scope) before any severity claim.
- Do NOT engage any of these protocols until `monitor/watchlist.json` FIREs (a real authorized program). egor discloses, never me.
