# PulsoMarket — `buyShares()`/`sellShares()` price the whole batch at the pre-trade spot price → risk-free atomic round-trip drains the pool + the market-creator's seed (Critical)

**Severity:** Critical (permissionless, atomic, single-transaction, no flash-loan / no oracle manipulation,
works on the *first trade* of any market). Bounded per round-trip by `seedReserve`, but every newly created
market is drainable, so the class is systemic.

**Status:** **Pre-mainnet.** Deployed only to Polygon **Amoy testnet** (chain 80002) as of 2026-08-22; the
README states *"Mainnet addresses will be published post-audit"* and *"Planned third-party audit by Hacken.io
prior to mainnet deployment. This repo is the audit-ready snapshot."* **$0 is at risk today** — this is a
white-hat **pre-launch disclosure** so the bug never reaches production. PoC re-derived independently below.

**Repo / commit:** `github.com/Littania/pulso-market` @ `60aac48` (2026-04-16). `contracts/PulsoMarket.sol`
(Solidity ^0.8.22, plain EVM). Testnet: `PulsoFactory 0x047327Ea642735343B0869176EB868E7c294715b`,
`MockUSDC 0xACc348EE35c398f0A745488901f7D9C8226e170E` (Amoy).

**Class:** prediction-market AMM cost-curve accounting — both legs use `spot_price × quantity` for the whole
batch instead of integrating the cost curve over the shares minted/burned. Same root class as the LuXMarket
Critical (see `../luxmarket-poc/FINDING.md`), but here it is present on **both** buy and sell, so a single
buy→sell round trip samples the price asymmetrically around one state transition and prints money.

**Disclosure intent:** private, goodwill, pre-launch (no open Sherlock/C4/Cantina/Immunefi program matched a
testnet repo). White-hat, read-only: analysis is source-read + exact integer-math simulation of the deployed
code. No testnet or mainnet state was touched. **The researcher discloses, not the tool.**

---

## The bug — spot price for the whole batch, on both legs

The market prices YES/NO as a **spot ratio** of virtual+real shares (`PulsoMarket.sol:209-229`):

```solidity
function getPriceYes() public view returns (uint256) {
    uint256 yesTotal = totalYesShares + liquidityDepth;
    uint256 noTotal  = totalNoShares + liquidityDepth;
    uint256 total    = yesTotal + noTotal;
    ...
    uint256 price = (yesTotal * PRECISION) / total;   // spot ratio, PRECISION = 1e6
}
```

**`buyShares()` mints the entire batch at the price BEFORE minting** (`PulsoMarket.sol:238-288`):

```solidity
uint256 price = getPriceYes();                 // BEFORE minting  -> low
sharesOut = (net * PRECISION) / price;          // whole batch at that one price
totalYesShares += sharesOut;                     // now the price is HIGHER
```

**`sellShares()` pays the entire batch at the price BEFORE burning** (`PulsoMarket.sol:297-343`):

```solidity
uint256 price = getPriceYes();                 // BEFORE burning  -> == post-buy price -> HIGH
...
uint256 gross = Math.mulDiv(amount, price, PRECISION);   // whole batch at that one price
```

Neither leg integrates the curve. So for a buy-then-sell of the **same** shares in one transaction:

* the buy prices the batch at `p0` (spot **before** the buy pushes the price up),
* the sell prices the *same* batch at `p1` (spot **after** the buy, i.e. the elevated price, read **before**
  the sell's own impact is applied),
* and buying YES always pushes the YES price up, so `p1 > p0` ⇒ `gross = shares·p1 > shares·p0 = net paid`.

The attacker gets back **more USDC than they put in**. The difference is paid out of `totalUsdcPool` and then
`seedReserve` (the market creator's own deposit). Break-even is a price move `> 1/(1-fee)² ≈ 3.07 %`
(fee = 1.5 %/leg) — trivially exceeded by a single sizeable buy, because on a fresh market the buy alone moves
the price from 0.50 toward ~1.00.

No preconditions: `buyShares`/`sellShares` are ordinary external functions (only `nonReentrant`, `onlyActive`),
callable atomically from an attacker contract in one tx. No flash loan, no second party, no oracle. The
attacker-supplied `minOut`/`minUsdc` are **not** a defense — the attacker sets them himself.

---

## PoC — exact integer-math replica of the deployed code (independently re-derived)

`poc_sim.py` in this folder replays the **exact** Solidity integer semantics (`PRECISION=1e6`, `FEE_BPS=150`,
floor division, `Math.mulDiv` = floor) on a fresh market with **factory defaults**
(`initialLiquidity = 1000 USDC`, `virtualMultiplier = 10×` ⇒ `liquidityDepth = 10 000 USDC`,
`PulsoFactory.sol:22-23,87`). One attacker contract, one transaction, `buyShares(YES, X)` then
`sellShares(YES, allShares)`:

```
buy   322 USDC -> priceBuy 50.00c priceSell 51.54c | out   322.02 | PROFIT    +0.02 ( +0.0%)  [break-even]
buy  1000 USDC -> priceBuy 50.00c priceSell 54.48c | out  1057.22 | PROFIT   +57.22 ( +5.7%)
buy  3757 USDC -> priceBuy 50.00c priceSell 63.51c | out  4629.71 | PROFIT  +872.71 (+23.2%)  pool->0  seed->0.43
buy  5000 USDC -> REVERT (require fromSeed <= seedReserve)
```

A single **3 757 USDC** round trip nets the attacker **+872.71 USDC (23.2 %)** and empties both the trader
pool (→ 0) and ~99.96 % of the creator's 1000 USDC seed (→ 0.43) in **one transaction on the market's very
first trade**. Larger buys revert against the `require(fromSeed <= seedReserve)` liquidity guard — so the drain
is *bounded per round-trip by `seedReserve`*, but there is nothing market-specific about it: **every market a
creator opens is drainable of ~87 % of its seed on trade #1**, and any real trader who later sells finds the
pool already empty.

Run it (no dependencies):

```bash
python3 pulso-market-poc/poc_sim.py
```

A Foundry test that exercises the **team's own unmodified contracts** (`PulsoDrain.t.sol`, drop it into the
repo's `test/` and `forge test`) is included for reproduction in-repo, where OZ + the sources already resolve.

**Both proofs confirmed (2026-08-26), identical result:** the pure-integer sim and the Foundry test against the
unmodified `PulsoFactory`/`PulsoMarket`/`MockUSDC` (solc 0.8.22, `viaIR`, OZ 5.0.2) both report the attacker
netting **+872.708247 USDC** on a single `buyShares(YES, 3757e6) → sellShares(YES, all)` round trip, with
`totalUsdcPool → 0` and `seedReserve → 0.433582 USDC` (≈99.96 % of the creator's 1000 USDC seed gone). PoC 1/1.

---

## Why the project's own verification missed it

The README advertises a fuzz-invariant suite proving `balance >= pool + fees + seed` (solvency) plus
Slither-clean + 48/48 tests. **This bug class is invisible to all of them:**

* The solvency invariant **still holds** during the attack — the drain is capped by
  `require(fromSeed <= seedReserve)`, so the contract reverts at exhaustion rather than going negative. The
  identity `balance = pool + fees + seed` is never violated; the value simply moves from `seed`/`pool` to the
  attacker as a *legitimate* payout. Accounting-invariant fuzzing is not no-arbitrage / cost-curve verification.
* Slither / static regex (and this lab's own T0 detectors, `recon.py`) do not model AMM cost curves — this is
  a **reasoning-tier** finding, not a pattern-match. (Confirmed: `recon.py` returned only low-signal hygiene
  hits on this repo.)

The missing property is: **`cost_to_buy(q→q+s) == payout_to_sell(q+s→q)` for the same `s`** (round-trip
value-neutral, minus fees). The code satisfies neither side with an integral.

---

## Fix

Price **both** legs by the cost-curve difference, not `spot × quantity`:

* Adopt a proper cost function `C(q)` (LMSR `C = b·ln Σ e^{q_i/b}`, or the constant-product/CPMM invariant this
  contract's virtual-liquidity design is closer to) and compute:
  * **buy:** shares such that `C(after) − C(before) == net` (solve, don't divide by spot),
  * **sell:** `payout = C(before) − C(after)` for the burned shares (the reverse integral).
* Then a buy immediately followed by a sell of the same size returns exactly the net paid minus the two fees —
  no risk-free profit, and `seedReserve` / other traders are never drained.
* Until the rewrite lands, `DisputeMarket.sol` (which the README says shares "the same AMM mechanics" via its
  own `buyShares`/`sellShares`, `DisputeMarket.sol:221,267`) is almost certainly **identically vulnerable** —
  fix both, and re-run the invariant suite with a **no-arbitrage round-trip** invariant added
  (`assert buyThenSell(x) <= x` for all `x`).

---

## Secondary (lower severity, worth fixing in the same pass)

* `DisputeMarket.sol:403` — `payout = totalCollateral * userShares / totalShares` with no dead-shares /
  zero-supply guard: classic share-rounding shape as `totalShares → 0` near a claim-lifecycle corner
  (ThetaNuts class). Not deep-verified; flagged for awareness.
* `PulsoFactory.sol:105` — `usdc.transferFrom(...)` return value used but not `SafeERC20`; fine for canonical
  USDC (reverts), a hygiene issue only if a non-reverting ERC20 is ever substituted.

## Threat assessment (post-finding)

**PRE-LAUNCH / DORMANT — $0 at risk today.** Testnet-only (Amoy, MockUSDC has no value); repo last pushed
2026-04-16. **Disclosure urgency is HIGH regardless of the zero balance**: the team explicitly intends to ship
*this exact snapshot* to mainnet after a Hacken audit, and their own verification method structurally cannot
see this class. A private pre-mainnet disclosure prevents a LuXMarket-style production drain from ever
happening — the ideal white-hat outcome. **Action: egor sends this privately to the Littania/pulso-market
team before mainnet.**
