# HUNT: EVA Protocol (EvaMarkets/contracts) -- surfaced by the fan-out triage (2026-06-13)

- **What:** async ERC4626 vault (`EvaVault`) that wraps Wildcat isolated-credit market tokens, with a
  bespoke **virtual 1:1 accounting** model (`totalAssets()==virtualAssets`, `totalSupply()==virtualShares`,
  kept rigidly equal) + a custom **LayerZero OFT** bridge + a **yield-skim** mint to treasury.
- **Repo:** `EvaMarkets/contracts` (public, greenfield, ~857 LoC core; last commit 2026-05-12 = the
  `depositFromMarket` feature). Clone: `hunts/_volume/fanout-eva-markets`.
- **Deployed (ETH mainnet, ~$6M TVL):** EVA-USDC `0x741bD193B6b40f8703d2e116FD1965421f290F58`
  ($2.74M), EVA-USDT `0x501eBf66d76A96D4FB26ccead42957653e16B8B8` ($3.17M), EVA-ETH
  `0xdBECD077c1C2feFDCB75f547d1b5a73BF8207e4C`; Wildcat-USDC market `0xC9499006a149C553d18171747ED19Aa7C6Dd19E2`;
  mastermind `0xEa2Bc9417f776fe5509a1e68Cd26e0D76BCD01b2`; impl `0xdc9f47c2cc5647be812f9ba3e2fc94ae16582e2e`.

## Gate 0 (LIVE-FIRST) -- PASS
Live + greenfield + **deployed impl == this repo** (the `depositFromMarket` selector is on-chain; reverts on
logic, not "no function"). `totalAssets()==totalSupply()==2,738,261,093,121` (exact 1:1). `excess()~$560`
skimmable now (genuine Wildcat yield -> by-design protocol revenue). **No bug-bounty program found** (not on
Immunefi) -> any finding is **direct white-hat disclosure, no payout**.

## L4 read (mine) -- main flows are CONSERVED; the agent's 2 "High" leads don't yield a profit vector
The accounting is rigidly 1:1: `virtualAssets == virtualShares` is preserved by every path (deposit/redeem/
skim all add equal amounts to both; `previewRedeem` is exact, no rounding edge). I traced both flagged leads:
- **skim() phantom-mint** -- `excess = (idle + Wildcat balanceOf + paidBacking) - (virtualAssets + pendingDebt)`
  minted 1:1 to treasury. A donation raises `available` but the donor LOSES it (it becomes real backing) and
  treasury's new shares ARE backed -> no attacker profit; it's just yield capture. **Not exploitable as traced.**
- **OFT vs virtual asymmetry** -- `_debit`/`_credit` burn/mint the REAL OZ ERC20 (so per-chain `balanceOf` !=
  global `virtualShares`) but `virtualShares` is the GLOBAL supply; bridge-out -> redeem -> backing stays
  conserved across chains in every interleaving I walked. **Not exploitable as traced.**

## Residual leads worth a Wildcat-depth dig (IF revisited)
The only places a real bug could hide all need **Wildcat-internal mechanics** (scaledBalance/scaleFactor,
interest accrual, withdrawal batches) + a differential Foundry PoC with a Wildcat mock:
1. **`depositFromMarket`** (EvaVault.sol:132-155) -- credits `shares = Wildcat balanceOf delta` as 1:1
   virtualShares. The FRESHEST, unaudited feature. Can the scaled-vs-normalized delta be inflated
   (self-transfer / rounding / rebase timing) to mint shares for < 1:1 backing? **Highest residual EV.**
2. **`market.balanceOf` inflation** feeding `skim()`/`excess()` -- is Wildcat's depositor balance ever
   transiently/manipulably high so a skim mints unbacked treasury shares that later under-collateralize?
3. **queue / `paidBacking` double-count** (WildcatWithdrawalLib) -- `market.balanceOf + paidBacking` across a
   `queueWithdrawal -> executeWithdrawal` window; verify no backing is counted twice in `excess()`.

## Verdict: PARK (live, real, but EV-moderate)
Greenfield + live $6M is attractive, but: no bounty (disclosure-only), main flows verify as conserved, and the
residual leads are Wildcat-protocol-dependent (a real deep-dive, not a quick add). **Re-open with a Wildcat
L4 + differential PoC** if egor wants to commit the session to it (start at lead #1, `depositFromMarket`).
Best live greenfield target the fan-out produced; the other 3 (mezo $29M fork+audited, punks Yuga priv-audited,
lazy operator-trust) rank below it. See [[feedback-loop-calibrate-and-disclosure-gap]].
