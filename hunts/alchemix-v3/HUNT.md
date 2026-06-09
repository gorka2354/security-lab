# HUNT: Alchemix V3 (alchemix-finance/v3) -- via scout v3 Immunefi pipeline (END-TO-END validated)

The FULL new sourcing chain delivered a top-tier target: `scout --source immunefi` ranked **Alchemix**
([NEW PROGRAM], CDP/self-repaying-loans, scope updated 2026-06-08, max $300k) -> the in-scope code is
`alchemix-finance/v3` (Solidity, pushed 2026-06-02). DEPLOYED (broadcast/DeployV3{ETH,Arb,Optimism}; live
alETH 0x17573150...68B03) + in-scope + bountied + forkdrift: original code, NO audit evidence -> GREENFIELD,
high-EV. Clone gitignored `hunts/_volume/alchemix-v3`. PARTIAL pass (surface triaged; novel core-math parked).

## What it is -- self-repaying loans, V3 rewrite
NFT positions (`AlchemistV3Position`); each `Account{collateralBalance (MYT shares), debt}`. Deposit MYT
(a MultiStrategy ERC4626 yield share) -> borrow alAsset debt -> yield + `redeem` (Transmuter-driven) earmark
the debt away over time -> `liquidate` when collateralization <= lower bound. Core: `AlchemistV3.sol` (1886L),
`Transmuter.sol`, `AlchemistRouter`, MYT strategies. Novel accounting: earmark/redemption with Q128.128
**survival-ratio** epochs (`redeem`, AlchemistV3:655-729).

## Top lead VERIFIED -> FP (the discipline paid off)
- `external/AlEth.sol:65/73/81` -- `setWhitelist`/`pauseAlchemist`/`setCeiling` are `external` with NatSpec
  claiming "reverts if not admin" but **NO access control** -> looks like a 1-call **infinite-mint**
  (`setWhitelist(attacker,true)` -> `mint(attacker, INF)`). recon caught it (sibling-inconsistency). BUT
  **AlEth.sol is a TEST MOCK** -- its own header says "This version is modified for Alchemix V3 invariant
  testing", and the deploy scripts use the REAL token `CrossChainCanonicalAlchemicTokenV3` (AlTokenV3.sol),
  which extends the AUDITED `AlchemicTokenV2Base` (lib/v2-foundry) = role-gated. The mock is NOT deployed ->
  **FP, not a finding.** (Verify-before-claiming downgraded a "critical" to a mock.)
- `AlchemistV3.sol` liquidation (`_liquidate` 1048, `_doLiquidation` 1149): **no self-liq guard = by-design**
  (self-repaying -> self-liquidation just pays yourself the liquidator fee from your own collateral, no free
  value). Careful rounding (clamps seize to realized collateral). Not obviously broken.
- `deposit` (417) external-call-then-write "reentrancy" -> **intentional CEI** (state committed before the MYT
  pull; explicit code comment). MYT is their own ERC4626 share (no transfer hook).

## Parked -- the genuinely-novel core math (deserves a focused PoC deep-dive; their OWN fuzzing covers the
## MultiStrategy allocator heavily but NOT this core)
1. **Liquidation health-price = MYT ERC4626 share price** (`_isAccountHealthy` 1135 -> `_totalCollateralValue`
   -> `IVaultV2(myt).convertToAssets`). Is the MYT share price donation/manipulable enough to force-liquidate a
   healthy position OR dodge liquidation? (They guard `convertToAssets(1e18)==0`; caps exist -- verify the band.)
2. **earmark / redemption Q128.128 survival-ratio** (`redeem` 655, `_earmark`, `cumulativeEarmarked`,
   `_survivalAccumulator`, `_redemptionWeight` epoch/index). Rounding/precision in the survival ratio ->
   does `SUM(per-account earmarked) == cumulativeEarmarked` hold across redeem epochs? Value leak / stuck debt?
3. **deposit/withdraw + mint/repay round-trip** (hypothesizer inverse pairs): `collateralBalance += amount`
   commits BEFORE `_mytSharesDeposited += amount` (417/438) -- transient global-vs-sum desync during the MYT
   pull; if MYT (or a strategy) can reenter, exploitable? (Likely not, MYT is a plain share -- but confirm.)
4. `strategies/ERC4626Strategy.sol:13` first-depositor inflation (no virtual shares?) -- the MYT building block.
5. `Transmuter.sol:176/209` reentrancy + "reward payout, no claimed-marker" (double-claim?) -- the al<->underlying converter.
6. TODO/FIXME (incomplete logic): `PerpetualGauge:164`, `ZeroXSwapVerifier:128/141`.

## Status -- PARTIAL (greenfield, in-scope, bountied; surface triaged, core-math parked for PoC)
**Whole-session win:** the scout-v3 Immunefi pipeline reached a deployed, in-scope, BOUNTIED, unaudited,
novel target end-to-end -- exactly the goal. Top "critical" lead correctly verified as a test mock. Next:
focused PoC deep-dive on (1) MYT-share-price liquidation manipulation and (2) the earmark/redemption survival-
ratio conservation -- scaffold an invariant (SUM user debt/earmark == globals; liquidation never profits a
healthy account) in invariant-lab. Ledger: AlEth mock fp; core-math todo.
