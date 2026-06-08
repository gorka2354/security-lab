# Pattern 04 — Interest-index / accumulator manipulation (empty-market)

**Tier:** T2/T3 — the cousin of oracle-manipulation. The smell (an accumulator divided by a tiny `totalSupply`) is T1;
the exploit (seed an empty market, inflate the index, borrow against the phantom) is a multi-step economic sequence.
**One line:** a per-reserve **accumulator** (`liquidityIndex`, `borrowIndex`, `pricePerShare`) compounds as
`+= delta / totalSupply`; on an **empty or near-empty market** a small absolute `delta` is a huge *relative* jump, so an
attacker inflates the index and then values/borrows/redeems against it.

## 1. Mechanism
- Aave-style: `liquidityIndex *= (1 + ratePerSec·dt)` and fees/premiums **cumulate to the index** divided by scaled
  supply. When `totalScaledSupply → 0`, `delta/supply → ∞` per unit of fee → the index moves orders of magnitude in one tx.
- The attacker **controls both inputs on an empty market**: seed 1 wei, drive a fee/premium (flash-loan repay premium,
  or a self-borrow/repay), watch the index balloon, then mint/borrow/redeem where `actual = scaled · index`.
- Same shape as ERC4626 first-depositor inflation, but on a *lending index* instead of a *share price* → links
  [erc4626-inflation](../accounting/erc4626-inflation.md) and [oracle-manipulation](oracle-manipulation.md).

## 2. Real examples
- **dTRINITY / dLEND, Mar-2026, ~$257k (first-hand).** Aave-fork `liquidityIndex` on an **empty cbBTC reserve** was
  pushed **1.0 → ~6.2M RAY** via repeated flash-loan-premium accrual, then the attacker borrowed against the phantom
  index. (Initially mistaken for a dStake ERC4626-inflation bug — the known-check corrected it to the *index* cousin.)
- **Aave-fork family generally:** any fork that lets a reserve be listed and used as collateral while
  `totalLiquidity ≈ 0`, with premiums/fees cumulated to the index and no growth cap.

## 3. The "tell"
- Aave/Compound fork? Grep `liquidityIndex`, `variableBorrowIndex`, `cumulateToLiquidityIndex`,
  `_updateIndexes`, `getReserveNormalizedIncome`, `accrueToTreasury`.
- **The $-question:** *can a reserve reach a usable (collateral/borrow) state while its scaled supply is ~0, and can the
  attacker push fees/premiums into its index in the same window?* If yes → inflation lead.
- Check: is there a **min-liquidity to list**, an **index growth cap per block/tx**, or a **new-reserve-can't-be-collateral**
  guard? Absence on a fork = the lead is live.

## 4. Detector idea (static, T0/T1) — det_index
- Flag an index/accumulator update of the form `index += / *= (something / totalScaledSupply)` (or
  `cumulateToLiquidityIndex(amount)`) **with no floor/cap on the divisor and no min-supply guard** → "empty-market index
  inflation — verify new-reserve collateral gating". Emit as a **lead**.
- **Honest limit:** whether the market can actually be empty *and* collateralizable is config + cross-file → T2. Regex
  only finds the divide-by-supply accumulator; the exploitability is the hypothesis layer.

## 5. Hypothesis / invariant (T2/T3)
- **Hypothesis:** "for each accumulator, what's the max single-tx relative move, and is the market collateralizable while
  supply is dust?" The accumulators with unbounded move on a fresh reserve = the leads.
- **Invariant to fuzz:** a flash-loan round-trip (borrow→repay, or seed→fee→drain) on a reserve **cannot move its index
  by more than X bps in one tx**, AND **a reserve with scaledSupply < floor cannot back a borrow**. Harness: list a fresh
  reserve, seed 1 wei, run premium-accrual loop, assert index delta bounded and borrow reverts.

## 6. Mitigations to RECOGNIZE (avoid FP)
- **Min-liquidity / seed on listing** (a real initial deposit so `supply` is never dust) — most maintained Aave-v3
  deployments seed reserves.
- **New reserve can't be collateral** until matured / governance-flagged; **isolation mode**; **supply caps**.
- **Index growth cap** per block, or fees routed to treasury **not** cumulated into the index on empty markets.
- **Composite/clamped index** (rate-limited move) — same family as Likwid `truncatedReserves` in the oracle pattern.
