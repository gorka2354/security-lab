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

### Investigation (RESOLVED 2026-06-05) — verdict: REAL but LOW, not reportable

**Addresses (mainnet, deployments/mainnet.json):**
- USDC adapter (the masking one): `0xBA2A4765934Ad29f27631fcF3117360FE28217a5`
- underlying adapter: `0xf534813F0e94De9718c75c6FE3bbd6583c46BB0A`
- inputs: LINK/USD `0x2c1d072e956AFFC0D435Cb7AC38EF18d24d9127c`, USDC/USD
  `0x8fFfFfd4AfB6115b954Bd326cbe7B4BA576818f6`, wstLINK ratio (`getUnderlyingByWrapped`).

**Consumers (web, not in this repo):** wstLINK is collateral on
- **Morpho** — `wstLINK-LINK` market. Prices wstLINK in LINK, so it uses the
  *underlying* adapter (`0xf534`) = a pure on-chain ratio, **NO Chainlink feed, NO
  staleness at all**. And Morpho Blue oracles **don't check staleness by design**.
- **Folks Finance** — wstLINK -> stablecoin/LINK, cross-chain. The USDC adapter
  (`0xBA2A`, the masking one) is the stablecoin-leg feed.

**Why severity collapses to Low/informational:** the masking bites only if BOTH
(1) the consumer actually checks `updatedAt` AND (2) a *major* feed (LINK/USD or
USDC/USD) freezes. The largest consumer (Morpho wstLINK-LINK) is unaffected (uses
the ratio adapter; doesn't check staleness anyway). `price <= 0` is unreachable for
these majors. No concrete fund-loss path -> not a demonstrable-impact finding.

**Scope:** stake.link HAS a live Immunefi bounty ($100k max, PoC + KYC). But
Immunefi pays for demonstrable impact; this is informational (no exploit path) ->
would triage as Low / won't-pay. (Couldn't fetch the exact asset list — page 404'd
via fetch — but the disposition doesn't depend on it.)

**Disposition:** real pattern, investigated to ground, **closed as Low / defensive-
hardening only** (the fix: propagate `min(upstream updatedAt)` instead of stamping
`block.timestamp`; add `require(price > 0)`). Not reporting. Ledger -> `wontfix`
(silenced) so it won't resurface. Good demonstration that diffscan surfaces real
fresh patterns; discipline correctly sized this one down.
