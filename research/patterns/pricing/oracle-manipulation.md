# Pattern 02 — Price-oracle manipulation

**Tier:** T2/T3 — the *source* is often T1-spottable; the *exploit* (is it movable for 1 block, who consumes it) is reasoning.
**One line:** a protocol reads a price from a source an attacker can move **within a single transaction** (spot AMM
reserves, a single shallow pool, a `balanceOf`-derived rate, a stale/unchecked feed), then borrows/swaps/liquidates
against the moved price. **17.3% of all major exploits (2023-2025), >$165.8M** — OWASP **SC02:2025/2026**.

## 1. Mechanism
The unsafe price source, in order of how often it bites:
1. **Spot AMM reserves / `getAmountOut` on a single pool** — `price = reserveB/reserveA` read live. A flash-loaned swap
   moves it, the protocol reads the moved value, attacker reverts the swap. Mid-price (no slippage) is the worst.
2. **`token.balanceOf(pool)` / LP-token value via balances** — donate/skew balances → mis-valued LP or collateral.
3. **Vault share rate as price** — see [erc4626-inflation](../accounting/erc4626-inflation.md) flavor (b) (Venus, Inertia).
4. **Chainlink/feed misuse** — no staleness (`updatedAt`), no `answeredInRound`, no `price>0`, wrong `decimals`, or a
   single feed for a thinly-traded asset. (Our `det_oracle` 3-guard checklist lives here — T1.)
5. **Read-only reentrancy** — read the price *during* a victim contract's callback (e.g. Curve `get_virtual_price`
   mid-remove_liquidity) when balances are transiently inconsistent. No state is written by the attacker — pure read.

## 2. Real examples
- **The class at scale:** price manipulation = **17.3% of major exploits, >$165.8M** (Jan-2023…May-2025).
- **Venus / Inertia (2025-2026):** vault-rate-as-oracle (see pattern 01) — flash-loan donation → liquidate/borrow.
- **Read-only reentrancy** (Curve-LP pricers, 2022-2023): price read mid-callback when `get_virtual_price` is skewed.
- **Classic spot-price drains** (Harvest, Cheese Bank, Warp, bZx): single-DEX spot used as the oracle.
- **dTRINITY, Mar-2026, $257k (first-hand class):** not a *price* feed but the cousin — **Aave-fork `liquidityIndex`**
  pushed 1.0→6.2M RAY on an empty cbBTC reserve via repeated flash-loan-premium accrual, then borrowed against the
  phantom index. (Empty-market + manipulable-accumulator = the same family as oracle manipulation.)

## 3. The "tell"
- Find every **price read** feeding a value/health/swap-bound decision: `getPrice`, `latestRoundData`, `getAmountOut`,
  `reserve0/reserve1`, `getReserves`, `balanceOf(pool)`, `get_virtual_price`, `convertToAssets`, `pricePerShare`.
- For each ask the **single $-question:** *can the attacker move this source within one tx, and does the protocol read
  it at that moment?* Spot reserves / single shallow pool / balanceOf → YES. TWAP / clamped / multi-source → usually no.
- Chainlink path: are all 3 guards present (staleness via `updatedAt` + `price>0` + correct `decimals`)? (T1 — det_oracle.)
- Any price read **inside or reachable from an external-call callback** (ERC777/ERC721 hooks, LP remove) → read-only reentrancy.

## 4. Detector idea (static, T0/T1) — det_oracle (+ a cross-file note)
- Keep the 3-guard Chainlink checklist (have it). **Add a "spot-reserve pricing" sub-check:** flag a value/health
  function whose body reads `getReserves`/`reserve0`/`reserve1`/`balanceOf(<pool>)` and divides/`mulDiv`s by it →
  "spot-AMM price — manipulable in 1 block unless TWAP/clamped". 
- **Honest limit:** det_oracle FP'd on Cap (the staleness guard lived in the *caller*, not the adapter file) → this is
  cross-file. So emit it as **a lead to verify, not a verdict** + always trace to the consumer. (Backlog: cross-file
  consumer trace = T2, the `hypothesize.py` job, not regex.)

## 5. Hypothesis / invariant (T2/T3)
- **Hypothesis:** "every price source — is it manipulable in 1 block?" Enumerate sources (above) → for each, classify
  spot(manipulable) vs TWAP/clamped/multi(resistant). The manipulable ones feeding collateral/liquidation = the leads.
- **Invariant to fuzz:** `value(position)` (or `health`, or `amountOut`) **must be ~unchanged** by a flash-swap that
  moves the pool and reverts in the same tx. Harness: snapshot value → flash-swap pool ±X → re-read value → assert delta
  bounded. If a single-block swap moves a liquidation/borrow decision → finding.
- **Read-only-reentrancy invariant:** the priced quantity read during any external callback equals its settled value.

## 6. Mitigations to RECOGNIZE (avoid FP)
- **TWAP / rate-limited reserves** — the price moves toward spot only at a bounded rate per unit time, so a 1-block swap
  can't move it. **First-hand example to study: Likwid `truncatedReserves`** =
  `PriceMath.transferReserves(prevTruncated, spot, timeElapsed, priceMoveSpeedPPM)` — a clamped move; `liquidateCall`
  prices off `truncatedReserves`, NOT spot → our flash-swap hypothesis was correctly **refuted**. *This is the gold
  standard to recognize; if you see a "truncated/clamped/EMA reserve" used for valuation, the spot-manip lead is dead.*
- **Chainlink with all 3 guards** (staleness + >0 + decimals) and a deep-market asset.
- **Multiple independent sources** + deviation/median (Chainlink + a TWAP fallback, e.g. dTRINITY's composite wrapper).
- **Self-defeating manipulation** — if the same pool is both manipulated AND the venue you must trade through to profit,
  the round-trip slippage+fee can exceed the gain (check the math before calling it safe — shallow pools break this).
- **Read-only-reentrancy lock** — a `nonReentrant`-style check on the *view* path (Curve added these post-2023).
