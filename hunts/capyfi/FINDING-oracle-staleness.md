# CapyFi — price-oracle staleness + hardcoded-price collateral (Low-Medium)

**Status:** LIVE + in-scope, Gate-0 PASSED. Severity: **Low-Medium** (latent, not forensically exploited).
**Program:** CapyFi (Immunefi, max $1M). **Chain:** Ethereum mainnet. **the researcher discloses.**
**Date:** 2026-06-30. Full-cycle hunt: source -> reach -> recon -> L4 on the fork-drift -> on-chain forensics.

---

## TL;DR
CapyFi (a Compound-V2 fork) reads prices through a `ChainlinkPriceOracle` that **never checks freshness**
(`updatedAt` + `answeredInRound` are commented out). The markets are priced by a mix of (a) custom
single-operator push feeds for LATAM currencies and (b) **permanently hardcoded prices** for the ecosystem
tokens. The missing check is a real best-practice violation, but on-chain forensics show it has **not been
exploited** (the operator has kept feeds fresh during active trading), and the hardcoded-price collateral is
**not cleanly externally exploitable** (the tokens are illiquid and team-controlled). Net: a legitimate
Low-Medium oracle-hygiene finding in a heavily centralized, closed ecosystem.

## Target (on-chain, verified)
- Comptroller: `0x0b9af1fd73885aD52680A1aeAa7A3f17AC702afA`
- Wired oracle (`Comptroller.oracle()`): **`0xfba2712d3bbcf32c6e0178a21955b61fe1ff424a`** = `ChainlinkPriceOracle`
  (verified). Re-confirmed wired live at disclosure time.
- 12 markets, several with non-zero `totalSupply` + active borrows.

## Bug 1 — missing staleness / round-completeness check (the core finding)
`ChainlinkPriceOracle.getUnderlyingPrice(cToken)`:
```solidity
(
    /* uint80 roundID */,
    int256 answer,
    /*uint256 startedAt*/,
    /*uint256 updatedAt*/,      // <-- COMMENTED OUT, never read
    /*uint80 answeredInRound*/  // <-- COMMENTED OUT, never read
) = priceFeed.latestRoundData();
if (answer <= 0) return 0;     // price>0 guard present; NO freshness check anywhere
```
A stale price is accepted as current -> mispriced collateral -> wrongful liquidation / under-collateralized
borrow. Recommended fix: `require(block.timestamp - updatedAt <= heartbeat && answeredInRound >= roundId)`.

## On-chain forensics — did staleness ever bite? (the honest part)
The feeds **can** go stale: the custom wARS/USD feed (single operator `0x6c15e4bc...`, ~4h median cadence)
had a historical **gap of 11 days**; wCOP had ~2 days. BUT aligning the wARS market's **972 borrow/mint/
liquidate actions** against **2010 feed updates** in the same era:

| market actions on a price older than | count |
|---|---|
| > 12h | 3 |
| > 1 day | **0** |
| > 2 days | **0** |

The multi-day gaps happened **early, before the market was funded/active**. Once trading was live, the
operator kept the feed fresh, so **no market action priced off a >1-day-stale price**. => real latent bug,
**no evidence of realized exploitation**. This is why severity stays Low-Medium (a missing seatbelt, no crash
yet), not Medium+.

## Bug 2 — hardcoded prices on illiquid collateral (secondary, centralization-flavored)
Three markets bypass the feed entirely with a `fixedPrice` that can never move:

| token | hardcoded | collateralFactor | market size (@hardcoded) | real market |
|---|---|---|---|---|
| UXD (Criptodolar) | $1.00 | 0.00 (not collateral) | ~$4.5k | V3/USDC pool |
| **LAC** (LaCoin) | $0.01162 | **0.60** | ~$1.4M | **no Uniswap pool at all** |
| **RPC** (Ripio Coin) | $0.01105 | **0.50** | **~$45M** | $34 of V2 liquidity; CoinGecko $0 mcap |

Hardcoded collateral prices cannot track the market and no operator diligence can fix them. HOWEVER: RPC's
hardcoded $0.01105 is within ~8% of its (dust-pool) ~$0.01026, so it is **not wildly mispriced today**, and
the tokens are so illiquid an attacker **cannot source them at scale** to deposit inflated collateral and
drain. So this is a structural/centralization risk, not a clean external exploit.

## Context — what CapyFi actually is
A closed, centralized **LATAM lending ecosystem** (RPC=Ripio Coin, LAC=LaCoin, UXD=Criptodolar, w-currencies
= wARS/wBRL/wMXN/wCOP). The same team controls the **tokens, the hardcoded prices, AND the single-operator
price feeds**. The oracle weaknesses are therefore primarily **centralization risk to the protocol's own
users**, not an external-attacker drain.

## Honest verdict
- **Defensible finding to disclose:** Bug 1 (missing staleness/round check) — a real, live, in-scope
  best-practice violation. **Low-Medium**, latent, not forensically exploited.
- **Worth mentioning as context:** Bug 2 (hardcoded illiquid collateral) + single-operator feeds = oracle
  centralization. Not independently exploitable from outside today.
- **Not a critical.** No external drain path was demonstrated; two leads (staleness forensics, fixed-price
  arbitrage) were chased and both resolved to "real issue, not cleanly exploitable."

## Pre-disclosure checklist (the operator)
1. Check CapyFi's Immunefi **known-issues / out-of-scope** — missing-staleness is a common, often-excluded class.
2. Frame honestly as Low-Med oracle hygiene + centralization context; don't overclaim impact.
3. Fix to cite: read `updatedAt`/`answeredInRound` with a per-feed heartbeat; reconsider hardcoded collateral.

## Engine note
This hunt fixed a det_oracle false-negative (a commented `/*updatedAt*/` satisfied the old substring guard;
now staleness must be ACTUALLY used — commit f710201). Self-improvement loop closing on a live target.
