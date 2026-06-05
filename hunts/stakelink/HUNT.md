# HUNT: stakelink (stakedotlink/contracts) — liquid staking for Chainlink (stLINK)

Open-source, non-contest. Scanned via the volume engine; clone lives in the
gitignored `hunts/_volume/stakelink` (this notes file is the persistent record).

## Triage log

| Lead | Detector | Verdict | Why |
|---|---|---|---|
| `RewardsPoolController.sol:98` `distributeTokens` | sibling/access | **FP** | public-good poke: pushes own reward balance to fixed `tokenPools`, anyone triggers (like harvest) |
| `RewardsPoolController.sol:108` `distributeToken` | sibling/access | **FP** | own balance -> fixed pool, token must be supported |
| `WithdrawalPool.sol:424` `updateWithdrawalBatchIdCutoff` | sibling/access | **FP** | public-good bookkeeping poke, no fund movement / no user-controlled destination |
| `CommunityVCS.sol:161` `claimRewards` | sibling/access | **FP** | claims Chainlink rewards to `address(this)` (receiver hardcoded); `_minRewards` is a slippage guard |
| **`WLSTUSDCChainlinkPriceAdapter.sol`** | oracle | **TODO (real pattern)** | see below |
| `WLSTUnderlyingChainlinkPriceAdapter.sol:37` | oracle | TODO | same family; same `price>0`/staleness shape (verify) |

FP pattern across stakelink's access-control leads: they are all intentional
**public-good pokes** (reward distribution/claiming with fixed destinations).
The dangerous ungated ones would have a **user-controlled destination** or change
critical config — none did. (Recorded as a reusable filter in the vault.)

## Lead worth following: WLSTUSDCChainlinkPriceAdapter (oracle misuse, FRESH + deployed)

Surfaced by `diffscan.py` as freshly-changed code. A Chainlink-compatible price
adapter that returns `wrappedLST` priced in USDC, combining two Chainlink feeds
(underlying/USD, USDC/USD) with the wrapped->underlying ratio.

Two real oracle-safety gaps (heuristic #2 — Chainlink misuse):

1. **No `price > 0` validation.** `uint256(underlyingUSDPrice)` and
   `uint256(usdcUSDPrice)` are cast from `int256` without a `> 0` check. A feed
   returning 0 or a negative answer becomes a huge `uint256` -> grossly wrong price.
   (Realistically major USD feeds rarely return <= 0, so this alone is low-likelihood.)

2. **Staleness is MASKED, not just missing (sharper).** Lines 55/58 discard the
   upstream `updatedAt` of BOTH feeds, and line 72 sets the adapter's own
   `updatedAt = block.timestamp`. So a downstream consumer doing the standard
   `require(block.timestamp - updatedAt < heartbeat)` ALWAYS passes — even if both
   Chainlink feeds froze days ago. The adapter actively blinds the consumer's
   staleness guard and serves the last (stale) price as fresh.

### Status: production, but impact UNVERIFIED
- **Deployed on mainnet**: referenced in `deployments/mainnet.json` and the prod
  deploy script `scripts/prod/linkStaking/1.0.5-chainlink-price-adapters/`.
- The consumer of `latestRoundData()` is almost certainly **external** (the
  `EACAggregatorProxy` interface = "expose wrappedLST as a Chainlink-style feed"
  so a money-market can list it). That consumer is NOT in this repo.
- Caveat: stamping `block.timestamp` on a *derived/computed* feed is a COMMON
  adapter pattern and is sometimes an accepted design (freshness is delegated to
  the consumer checking the inputs). So this may be known/accepted.

### To confirm or drop (next session)
1. Identify the actual consumer of this adapter on mainnet (etherscan: who reads
   this address as a price feed?). Lending market? Index valuation?
2. Does that consumer rely on `updatedAt` for staleness AND/OR on `answer` for
   collateral valuation? If yes -> stale/zero feed -> mispricing -> real impact.
3. Is it already known? (stakelink audits / the adapter's own tests asserting intent.)
4. If real + in-scope somewhere: write up as oracle-staleness (Medium-ish), like
   the YO finding — but only if NOT already known.

Disposition per standing rule: not confirmed-critical from here -> recorded, not
reported. Ledger marks it `todo` so it stays visible (not suppressed) next run.
