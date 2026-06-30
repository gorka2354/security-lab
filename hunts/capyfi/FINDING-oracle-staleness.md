# CapyFi — ChainlinkPriceOracle missing staleness check (Low-Medium)

**Status:** LIVE + in-scope, Gate-0 PASSED. Severity: **Low-Medium** (conditional impact). egor discloses.
**Program:** CapyFi (Immunefi, max $1M). **Chain:** Ethereum mainnet.
**Date:** 2026-06-30. Found by the full-cycle hunt (source -> reach -> recon -> L4 on the fork-drift).

## Target (on-chain, verified)
- Comptroller: `0x0b9af1fd73885aD52680A1aeAa7A3f17AC702afA`
- Wired price oracle (Comptroller.oracle()): **`0xfba2712d3bbcf32c6e0178a21955b61fe1ff424a`** =
  `ChainlinkPriceOracle` (verified source on Etherscan).
- Multiple cTokens with non-zero totalSupply (active markets, real value).
- CapyFi is a Compound-V2 fork; the bug is in the protocol's CUSTOM drift (the oracle stack), not the
  audited Compound base.

## The issue
`ChainlinkPriceOracle.getUnderlyingPrice(cToken)` consumes the price feed but **ignores freshness**:
```solidity
(
    /* uint80 roundID */,
    int256 answer,
    /*uint256 startedAt*/,
    /*uint256 updatedAt*/,      // <-- COMMENTED OUT: never read
    /*uint80 answeredInRound*/  // <-- COMMENTED OUT: never read
) = priceFeed.latestRoundData();
if (answer <= 0) return 0;     // price>0 guard IS present
// ... decimal scaling ...      // no staleness / round-completeness check anywhere
```
So a **stale price** is accepted as current. The feeds include a CUSTOM PUSH oracle
(`CapyfiAggregatorV3`, deployed for UXD/LAC) whose `updateAnswer(int256)` is operator-pushed and has no
bounds by default — if the operator stops/lags updating (or a real Chainlink feed lapses past its
heartbeat), the protocol keeps using the old price.

## Impact (conditional)
Mispriced collateral in the Comptroller:
- stale-HIGH collateral price -> borrow more than backed -> under-collateralized debt (bad debt);
- stale-LOW collateral price -> wrongful liquidations of healthy positions.
Real economic loss for a lending market, BUT it requires a stale-price condition (Chainlink heartbeat lapse
or push-operator negligence) — **not attacker-triggerable on demand**. Hence Low-Medium, not High.

## Honest caveats (check BEFORE submitting)
1. **Known-issue / scope:** missing-staleness is one of the most common Compound-fork findings; many programs
   classify it Informational/Low or list it as a known/accepted risk. Check CapyFi's known-issues +
   out-of-scope on Immunefi first — it may be excluded.
2. **Push-oracle framing:** for the UXD/LAC push oracle, staleness is partly operator-trust (centralization),
   which some programs treat as out-of-scope. The cleaner case is any market wired to a REAL Chainlink feed
   (heartbeat staleness is a genuine, non-centralization bug).
3. Recommended fix to cite: read `updatedAt` + `answeredInRound` and
   `require(block.timestamp - updatedAt <= heartbeat && answeredInRound >= roundId)`.

## Engine note
This hunt also fixed a det_oracle false-negative: the staleness guard matched the bare word `updatedAt`,
which a COMMENTED `/*updatedAt*/` satisfied -> the detector stayed silent. Now staleness must be ACTUALLY
used (commit f710201). The self-improvement loop closing on a live target.
