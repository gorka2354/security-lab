# HUNT — Twyne (twyne-contracts-v1)

**Date:** 2026-06-26 · **Source:** fan-out (defillama-immunefi-wave) → DIG
**Bounty:** Immunefi `twyne`, NEW program, **max $50k**, chain = Ethereum mainnet.
**Scope rule:** *"All vaults deployed using `CollateralVaultFactory` are in scope."* Critical = direct theft / permanent freeze / protocol insolvency. High = 24h+ freeze, theft/freeze of unclaimed yield.
**Repo:** github.com/0xTwyne/twyne-contracts-v1 → `hunts/_volume/twyne` (release **June 16 2026**, 667 LOC custom in `src/twyne` + `src/TwyneFactory`; Euler EVC/EVK + Aave V3 are the audited bases = out of hunt-surface).

## Gate-0 (LIVE-FIRST) — PASS
- 11 in-scope mainnet addrs (Immunefi scope). 3 Intermediate Credit Vaults funded & accruing (active borrows):
  - aWSTETH-IV `0x7502…B561` ~15.27 awstETH · eWETH-IV `0x87b8…8Ca7` ~0.65 eWETH · eWSTETH-IV `0x7613…815f` ~0.014
  - `totalAssets > totalSupply` on all three ⇒ collateral vaults are live & borrowing. Fresh (10 days), modest TVL, real funds.
- VaultManager proxy `0x0acd…58aC` → impl `0x44134feb…1a40` (verified).

## Architecture (1-paragraph)
Twyne = leverage/credit-delegation layer on Euler. A **borrower** spins up a per-borrower **CollateralVault** (BeaconProxy via `CollateralVaultFactory`). The vault holds **eVault shares** (`asset()` = the intermediate vault's asset) as collateral, **reserves extra credit** from an **Intermediate Vault** (LP-supplied, EVK), and **borrows `targetAsset` from Euler**. A dynamic Twyne liq-LTV `λ̃_t` governs health. Two liquidation paths: **internal** `liquidate()` (Twyne, liquidator takes over the vault) and **external** `handleExternalLiquidation()` (Euler already seized) → 3-way split CLP/borrower/liquidator.

## Ranked hypotheses (TRIAGE-LEVEL — need PoC, not yet confirmed)

### H1 — `isRebalancing` asymmetry → permissionless `rebalance()` may strand a vault liquidatable  [TOP]
- `CollateralVaultBase._collateralScaledByLiqLTV1e8(bool isRebalancing,…)` (CollateralVaultBase.sol:454-469): dynamic leg uses
  `_totalCollateral = isRebalancing ? intermediateVault.cash() + totalAssets : totalAssets`.
- `_invariantCollateralAmount()` (EulerCollateralVault.sol:88-95) calls it with **isRebalancing=TRUE** (includes Euler vault `cash()`).
- `_canLiquidate()` scenario-2 (EulerCollateralVault.sol:162-168) calls it with **isRebalancing=FALSE**.
- `rebalance()` (CollateralVaultBase.sol:604-610) is **permissionless** (`callThroughEVC`, anyone) and repays excess credit down to the invariant target.
- **Risk:** the invariant target is computed *including* intermediate-vault cash, but the liquidation check excludes it. If `rebalance()` (called by an attacker) reduces `totalAssetsDepositedOrReserved` to a target that the liq-check (cash-excluded) deems insufficient, a **healthy borrower becomes liquidatable on demand** ⇒ forced liquidation / griefing / theft of liquidation incentive. **High→Critical if reproducible.**
- **Kill-gate:** build a fork scenario where a vault healthy under `_canLiquidate()` BEFORE `rebalance()` is `_canLiquidate()==true` AFTER. If `rebalance` is bounded so this can't happen (cash effect always conservative), H1 dies.

### H2 — oracle linearity + read-only-reentrancy in the liq path  [verify-cheap]
- `_canLiquidate` scenario-2 passes a **scaled amount** (`C·λ̃` in 1e8) into `EulerRouter.getQuote(amount, asset, UoA)` and *relies on getQuote being linear in amount* — explicit code comment (EulerCollateralVault.sol:163). `_getBC` (129-136) and `_convertBaseToCollateral` (176-183) also oracle-quote.
- Code itself warns `canLiquidate()` direct calls cause **read-only reentrancy** (CollateralVaultBase.sol:417); external views are `nonReentrantView`, but `_canLiquidate` runs inside `checkVaultStatus`/`liquidate` during EVC batches.
- **Kill-gate:** (a) read the *actual configured* EulerRouter oracle for each in-scope asset (wstETH/WETH) — is any non-linear (fixed component / piecewise)? (b) can an EVC batch reentrancy move `accountLiquidity`/`getQuote` mid-check to dodge liquidation or self-liquidate favorably?

### H3 — `handleExternalLiquidation` 3-way split (CLP senior-claim accounting)  [medium]
- `splitCollateralAfterExtLiq` (EulerCollateralVault.sol:226-274): reserves `userCollateral` to cover external debt first, then `releaseAmount = min(balance - userCollateral, maxRelease)` to CLP, then borrower/liquidator split via `collateralForBorrower`. `liquidatorReward = userCollateral - borrowerClaim`.
- **Kill-gate:** model a sequence where the liquidator or borrower extracts value that should belong to CLP (LPs), beyond intended bad-debt socialization.

### H2b — Case-3 integer-division rounding in `collateralForBorrower`  [low / likely intended]
- Boundary Case-1↔Case-3 is **continuous** (both → 0 at `λ_t = λ̃^max_t`), so no discontinuity steal. Residual: 1-wei rounding in the Case-3 division (514-516) + `Math.min` in `_convertBaseToCollateral` round *against the borrower* — dust, not Critical. Park.

## PoC plan (reuse existing harness)
- Harness: `test/twyne/mainnet/euler/EulerTestBase.t.sol` (+ `LiquidationMath.sol`, `EulerLiquidationTest`). Profile `mainnet` (Tenderly public RPC).
- **H1 first:** new test — deposit+borrow a healthy Euler collateral vault, snapshot `_canLiquidate()`, have a *third party* call `rebalance()`, re-check `_canLiquidate()`. Fuzz `twyneLiqLTV`, deposit size, intermediate-vault `cash()`.
- If H1 clean → H2 (dump configured oracles via `oracleRouter`) → H3 (split model).

## RESULT (2026-06-26) — no Critical found; all leads closed with PoC/proof

Built a mainnet-fork harness on top of the dev's `EulerTestBase` (foundry deps via recursive submodule + brew solc 0.8.35 `--offline`). Outcome:

- **H1 — REFUTED (fork PoC `test/.../H1_RebalanceHealth.t.sol` PASS + proof).** Logged state: at open `invariant == totalAssets` exactly, and a `cash()` spike (7.5→19 eWETH) produced **no** excess (chosen leg dominates, cash-independent). Proof: `scaled(isRebalancing=true) ≥ scaled(false)` always (cash≥0 sits inside `min(adjExt·TC, chosen)`), so the rebalance target reserves ≥ the liq-check basis → `rebalance()` can never strand a healthy vault liquidatable. The asymmetry is intentionally conservative (matches the `"rounds up, which is conservative"` comment). Ledger: `fp`.
- **H2 — REFUTED.** (a) Linearity: the live in-scope wstETH/USD oracle `0x6FA8…` `getQuote` is linear (`q(2x)=2·q(x)`; `q(1000x)` matches to ~3.8e5 wei, rel 2e-19) → the documented `getQuote(k·x)≈k·getQuote(x)` assumption holds. (b) Read-only-reentrancy: external views are `nonReentrantView` and the devs explicitly guard it. Ledger: `fp`.
- **Aave-side oracle (`AaveV3ATokenWrapperOracle` + direct `latestAnswer()` in `AaveV3CollateralVault` health math) — NOT a finding.** Pulled the live wrapper impl `0x41695d33…`: custom `latestAnswer()` is **byte-identical** to the **audited** Aave stata-token oracle (`getAssetPrice(wstETH)·_rate()/RAY`); `_rate()` = Aave liquidity index (monotonic, non-manipulable by donation — no share-price vector). Missing `price>0`/staleness is inherited Aave behavior + an accepted assumption (the collateral *is* an Aave position), not attacker-triggerable. Ledger: `known`.
- **H3 — deprioritised.** `handleExternalLiquidation` 3-way split is the dev's **most-fuzzed** area (case00–22 price-drop matrix + `testFuzz_handleExternalLiquidation_InterpolationWindow/_holistics`). Low finding-density; not re-derived. Ledger: `known`.
- **BridgeHookTarget / claimRewards / LeverageOperator — clean.** Hook gates borrow/liquidate to collateral-vaults + disables flashloan/pull-debt; `claimRewards` routes to the treasury (not the caller); operators are `nonReentrant` + MORPHO-gated (recon CEI flag = FP). Ledger: `fp`.

**Verdict:** Twyne v1 custom core (liquidation/rebalance/oracle) is well-architected and well-tested; no reachable Critical/High in the surface examined. Calibration: another fresh-but-hardened deploy — reinforces that finding-density is gated by freshness *and* test-coverage, not tooling. Engine value this session: end-to-end fork PoC lane proven on Mac (submodule+brew-solc+Tenderly-fork), H1 closed by **proof not vibes**.

## Notes / discipline
- White-hat: in-scope only; **egor discloses**, never me. Leads here were HYPOTHESES; each is now closed by PoC/proof/inheritance, recorded in the ledger (`twyne`, 6 entries, suppressed).
- Residual (low-EV, parked): a formal write-up of the Aave-oracle staleness *inconsistency* (Euler side has staleness, Aave side doesn't) could be an Informational/QA submission, not a paid Critical.
