# LuXMarket — `sell()` prices the whole batch at the pre-trade LMSR spot price → permissionless drain of the shared collateral pool (Critical)

**Severity:** Critical (permissionless, atomic, no preconditions, PoC-proven). Current funds-at-risk are small
(~50 USD₮0 in the deployed contract today) but 100% of the balance is drainable now and the magnitude scales
1:1 with any future TVL — and the collateral is a real liquid stablecoin (USD₮0, ~$112.6M supply).
**Status:** Live on X Layer mainnet, un-audited. PoC re-run independently: 2/2 PASS.
**Contract:** `LuxMarket` — `0xFb7154E06B068031502051D285dE910b16A5aF0D` (X Layer, chain 196). Collateral
= USD₮0 `0x779Ded0c9e1022225f8E0630b35a9b54bE713736` (6 dp). Source: `github.com/kingskuan/luxmarket-contracts`
(deployed bytecode revert-string-matched to `src/LuxMarket.sol` + `src/LMSRLib.sol`).
**Class:** LMSR AMM cost-curve accounting — `sell()` uses the spot price for a whole batch instead of
integrating the reverse cost curve (reasoning-tier; no T0 detector catches it — recon fired 0 relevant hits).
**Disclosure intent:** private, goodwill (no open Sherlock/C4/Cantina/Immunefi program matched). White-hat,
read-only analysis over public deployed code; PoC runs against a local fork of the team's own source. No funds
or live state were touched.

---

## Finding 1 (Critical) — `sell()` over-pays every non-trivial sell → risk-free round-trip drain

`buy()` correctly charges the LMSR cost **integral** `cost(q+shares) − cost(q)` (via `LMSRLib.costToBuy()`).
But `sell()` pays out `priceOf(qUp, qDown, b) * shares` — the **single pre-trade spot (marginal) price** applied
to the *entire* sold batch, rather than the reverse integral `cost(q) − cost(q−shares)`:

```solidity
// src/LuxMarket.sol  sell() (lines ~161-191)
uint256 price  = priceOf(m.qUp, m.qDown, m.b);   // pre-trade SPOT price of the side being sold
uint256 payout = price * shares / 1e18;          // whole batch valued at the top-of-range price
```

Because `price(q)` is **monotonically increasing** in the side being sold, valuing the whole batch at the
pre-trade (highest) marginal price *strictly over-pays* every sell larger than dust. A single **same-block
`buy()` then `sell()`** round-trip therefore returns more than it cost — risk-free profit, paid out of the
**shared collateral pool** (per the project's own README, *all markets collateralize into this single
contract*), i.e. out of every other user's deposits in unrelated markets.

**PoC** (`test/PoolDrainPoC.t.sol::testSellOverpaysAndUndercollateralizesVictim`, PASS, against the exact
cloned source + a MockUSDT):
- attacker `buy()` 800e18 UP shares in market A → real LMSR cost **477.953485 USDT**
- attacker `sell()` ~800e18 shares back in the **same test** (no oracle report, no settlement, no time passing)
  → receives **551.979584 USDT**
- **net +74.026099 USDT (≈15.5%) risk-free from one round trip**
- the contract's real USDT balance drops to **206.90**, i.e. **below** an honest victim's legitimate,
  completely unrelated deposit (280.93) in a *different* market — the victim is now under-collateralized purely
  from the attacker's round trip in market A.

Exploitable by **any address**, atomically (one or two txs, same block), with **no oracle/settlement
dependency and no privileged role** — the easiest-to-trigger, highest-severity class (fund theft, no
preconditions). 100% of the contract's current balance is drainable this way today; magnitude scales with TVL.

**Fix:** `sell()` must compute the payout via the true reverse LMSR cost integral (a `costToSell()` /
`cost(q) − cost(q−shares)` analog), exactly mirroring what `buy()`/`costToBuy()` already do — never
`spotPrice * shares`.

## Finding 2 (High, same root cause) — `sell()` never decrements `poolUp/poolDown` → stale-pool double-dip at `redeem()`

`sell()` decrements `Market.qUp/qDown` and `sharesUp/sharesDown` but **never** decrements `Market.poolUp/poolDown`.
`redeem()` (lines ~245-276) pays `poolWin * held / totalWin`, where `totalWin = qUp` (correctly shrunk by sells)
but `poolWin = m.poolUp` (**stale**, never shrunk). The two variables that must move together desync on every sell.

**PoC** (`test/PoolDrainPoC.t.sol::testStalePoolUpWouldDoubleDipIfFundsRemained`, PASS): after buy 800e18 then
sell ~800e18 back, `qUp` collapses to 1 wei but `poolUp` stays at the full original 477.95 — so the attacker's
residual 1-wei position is 100% of `totalWin`, entitling them on paper to reclaim the **entire stale `poolUp`
again** at `redeem()` — a second extraction layered on Finding 1. (In the PoC it reverts on a
`totalCollateralLocked` underflow only because Finding 1 already drained the small shared pool below what this
second dip needs; once the pool is larger — e.g. after future deposits — this is an independent additional drain.)

**Fix:** `sell()` must symmetrically decrement `m.poolUp/m.poolDown` by the same delta `buy()` adds, once the
payout is computed correctly per Finding 1.

## Reproduction

```bash
git clone https://github.com/kingskuan/luxmarket-contracts && cd luxmarket-contracts
# drop test/PoolDrainPoC.t.sol (in this folder) into test/
forge test --match-path test/PoolDrainPoC.t.sol -vv
# => 2 passed; testSell... prints "attacker net P&L after buy+sell only : 74026099"
```

## Secondary (lower severity, worth fixing in the same rewrite)

- **Medium/Low — losing-side collateral stranded forever.** `redeem()` only distributes `poolWin` (the winning
  side's own collateral); `poolLose` is never distributed and there is **no** owner-sweep/rescue function
  anywhere (recon's owner-drain detector fired 0). Every settled market permanently strands the losing side's
  entire pool. Not attacker-theft, but permanent value destruction vs any reasonable design (winners should
  split `poolUp+poolDown`, or the owner should reclaim the house edge).
- **Low/robustness — `LMSRLib` unguarded oversized trades.** `exp1()` bounds only its own fractional input;
  `costToBuy()` doesn't enforce `ln1Plus`'s documented `0≤x≤1`, and `expDiv()`'s int-part loop silently
  truncates ≥80. A single `buy()` of 20,000e18 shares against `b=1000e18` (q/b=20) panics with an opaque
  arithmetic overflow instead of a clean bounded revert. Availability/UX, not theft; add `require(x≤ONE)`-style
  guards / a max-trade-size tied to `b`.
- **Informational — centralized resolution (disclosed MVP).** The owner EOA is both market creator and dispute
  arbiter (README labels this MVP). `reportOutcome()` is correctly single-shot; `settle()`/`redeem()` are
  correctly double-settle/double-redeem guarded in isolation from Findings 1–2. README's placeholder USDT addr
  is stale vs the real deployed USD₮0 — doc drift only.

---

*Researcher discloses, not the tool. Prepared for private, responsible disclosure to the LuXMarket team; it
documents a permissionless fund-loss bug in publicly deployed code and contains no exploit against live funds
(the PoC runs only against a local fork of the team's own source).*
