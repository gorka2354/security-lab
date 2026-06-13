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

## Deep L4 (2026-06-13, full read: core + OFT + storage + WildcatLib + mock + invariant/fuzz suite)
Verdict: **IE / hardened -- no demonstrable finding.** All four agent leads trace as CONSERVED once the
Wildcat mechanics are understood:
- **skim phantom-mint** -> a donation BECOMES backing; treasury's minted shares ARE backed; the team fuzzes
  donate()+skim() and their `invariant_backingCoversObligations` (available >= virtualAssets + pendingDebt) holds.
- **OFT vs virtual asymmetry** -> `virtualShares` is the GLOBAL (all-chain) supply; `_debit/_credit` move the
  real per-chain ERC20 while redeem/skim use virtual; bridge-out -> redeem keeps backing whole on every walk.
- **depositFromMarket** -> differential-fuzzed vs a wrap/unwrap proxy + scaleFactor-varying invariant
  (`shares == market.balanceOf(vault)`); credits the actual face value received, 1:1 backed.
- **paidBacking double-count** -> queued tokens are burned from `market.balanceOf` (disjoint sets);
  `executeWithdrawal` bumps `normalizedAmountWithdrawn` in lockstep with underlying leaving.
`virtualAssets == virtualShares` is rigidly preserved; no profit vector survives L4. Alchemix-class outcome
(core is hardened). Per VERIFY (FP > miss) -> do NOT disclose.

**Real mock-gap found, but it points the SAFE way:** the mocks mark `normalizedAmountPaid` full+instant on
`queueWithdrawal`; real Wildcat pays partial/delayed. So in production `paidBacking` UNDER-counts in the
queued-but-unrepaid window -> `excess()` is understated -> `skim()` reverts rather than over-mints, and
redeemers are still gated on real `underlying.balanceOf` in `_finalizeQueuedRequest`. Conservative, not
exploitable. **Courtesy note to the team (test-quality, NOT security):** their headline backing>=owed invariant
holds only because the mock assumes instant full Wildcat repayment; a realistic partial-repayment harness would
transiently violate it (harmlessly). Worth hardening the test, not a finding.

## Verdict: IE (insufficient evidence / hardened) -- closed, not disclosed
Best live greenfield target the fan-out produced ($6M, non-fork), but a deep L4 shows the bespoke virtual-1:1 +
Wildcat-wrapping + OFT accounting conserves across all paths. No bounty anyway (disclosure-only). Re-open ONLY
if a future Wildcat-specific edge (delinquency/reserve manipulation in the live market) surfaces. See
[[fanout-triage-workflow-validated]] + [[feedback-loop-calibrate-and-disclosure-gap]].
