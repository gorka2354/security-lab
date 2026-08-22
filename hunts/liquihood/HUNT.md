# HUNT — Liquihood (fresh lending fork, Robinhood Chain) — HIGH: stranded supplier yield

**Repo:** `Liquihood-dev/liquihood-contracts` (GitHub, created 2026-07-11, 1 star, un-audited). Sourced via a
fresh-lending-fork GitHub sweep (`gh search repos --language=Solidity --created=">2026-06-01" "lending protocol"`)
— explicitly documents itself as "deployed and verified on Robinhood Chain (Chain ID 4663)". Frontend at
`liquihood.xyz`. PoC: `liquihood-poc/` (forge 1/1 PASS against the real cloned `src/`).

**Deployment (LIVE-FIRST):** `LendingPool` at `0xD26F926CEBdd169D87c5a615C18A3A8AddbBdF6E` on Robinhood Chain
mainnet (chain 4663, `https://rpc.mainnet.chain.robinhood.com`) — confirmed live via direct RPC (`eth_getCode`
non-trivial, `eth_chainId`=0x1237, block head timestamp matches real wall-clock). 24 reserves configured
(`getReserveList()`), owner == deployer == `0x12b502D89f3aF07633a1A8D34C122C87e58a5eb3`.

`threat.py --rpc https://rpc.mainnet.chain.robinhood.com --chain 4663 --token <7 reserve addrs>` →
value-bearing (501,000 USDG / 200 WETH / 5,000 AAPL-T / 5,000 TSLA-T / 10,000 HOOD-T / 5,000,000 DOGE /
500,000 MEME-1 — round numbers, reads as deployer-seeded bootstrap liquidity, not organic third-party deposits).
threat.py's txlist-recency check is chain-unaware here (Robinhood Chain has no Etherscan-v2/explorer-API
integration) — recency was confirmed by hand instead: 3 small duplicate-symbol test reserves (`USDG`, `WETH`,
`USDe`) show real organic borrow+accrual activity (`totalDebt` already exceeds the static `totalLiquidity`,
proving interest has genuinely compounded past what suppliers can claim), with `lastUpdateTimestamp` ≈
1784043392–1784398898 vs a chain head of ≈1787429709 → **last real interaction ~35-39 days ago**. Verdict:
**DORMANT / pre-public-launch**, funded with non-trivial (if likely deployer-seeded, not yet organically
attracted) value. Same posture as the Krystal Community Vault case: real code bug, product not yet actively
used by third parties → current disclosure urgency moderate, not urgent, but must land before real depositors
show up (the bug fires on ordinary use, no attacker needed).

## FINDING (High, PoC-proven) — supplier accounting split-brain: 100% of collected interest is permanently stranded

Full writeup: `liquihood-poc/FINDING.md`. One-line root cause: `LendingPool.withdraw()` and the health-factor /
borrow-capacity math (`_buildPositionArrays()`) are gated on `userCollateral` — a linear ledger that only ever
moves by the raw `supply()`/`withdraw()` amount — while the actual interest-bearing receipt (`LHToken`, whose
`liquidityIndex` genuinely grows via `_accrueInterest()`) is never consulted by anything financial. Borrowers
really do pay compounded interest in full on `repay()` (pulled into the pool's real ERC-20 balance), but there
is no code path — not `withdraw()`, not `InsuranceFund.depositReserves()` (never called), not any owner-sweep
(none exists) — that ever lets that value leave the contract again. Every supplier earns the advertised
non-zero supply APY on paper and exactly 0% in practice; the surplus is destroyed/frozen forever, not stolen by
anyone.

PoC (`liquihood-poc/test/StrandedYield.t.sol`, 1/1 PASS): LP supplies 100,000 USDG, borrower borrows 80,000 USDG
against 100 WETH, 365 days pass, borrower repays 80,520 USDG in full (real interest paid). Pool physically holds
100,520 USDG; LP's true index-based entitlement is 100,468 USDG; LP's actual withdrawable balance never moved
past 100,000 (`userCollateral` flat) — LP withdraws only their 100,000 principal and is left holding an orphaned,
permanently unredeemable 465.8 scaled `lhToken` (≈468 USDG of real value, gone for good). `InsuranceFund` balance
stayed 0 throughout, confirming the documented bad-debt/reserve-factor waterfall is dead code.

Live-chain corroboration (not just the PoC): the small "USDG" test reserve
`0x1FaD69eaf1f4E9d9470787f51D458A93464833F6` already shows `totalDebt` (2.000000000161673484e18) exceeding
`totalLiquidity` (2.000000000000000000e18) on-chain — the split is already manifesting for real, on real
(if tiny) activity.

## Also considered, ruled out (the disciplined negatives)

- **Isolated-market ceiling bypass** (DOGE/MEME-1 $500k/$100k debt ceilings, `IsolatedMarketController`): traced
  the `_getIsolatedCollateral()` → `validateBorrow`/`increaseDebt` wiring for a "dilute the ceiling with non-
  isolated collateral" or "borrow first, add isolated collateral after" bypass. Neither creates bad debt beyond
  what the isolated asset alone would allow — the HF check (backed by ALL collateral, isolated or not) always
  governs actual solvency; the ceiling only ever makes borrowing *more* restrictive when isolated collateral is
  present, never less. Not exploitable, just an over-conservative (not unsafe) simplification.
- **Bad-debt liquidation "theft"**: `_computeBadDebt()` is computed but only ever logged (`recordLiquidation`
  emits an event; state is never touched by it). Traced whether this lets a liquidator profit or externalize
  loss onto other suppliers — it doesn't: the liquidator must pay the *full* `repayAmount` they choose
  regardless of collateral shortfall, so a rational liquidator would never voluntarily liquidate a deeply
  underwater position (they'd lose money). Net effect is a liveness gap (bad debt positions become
  un-liquidatable "zombies") rather than a drain — a real but lower-severity design gap, folded into the "fix"
  note above rather than filed separately.
- **Oracle manipulation**: `OracleRouter` — Chainlink path has a proper staleness+positivity guard; the KEEPER
  path (used for tokenized-equity prices) is a single trusted EOA with a 10%-per-push deviation cap — a
  centralization/trust assumption, documented as such, not a code bug reachable by an external attacker.
- **Reentrancy**: every state-changing `LendingPool` entrypoint is `nonReentrant` (shared OZ guard, correctly
  single-instance); reserve tokens are only addable by the owner (`addReserve`), so a malicious-ERC20 reentrancy
  vector isn't attacker-reachable.
- **DebtToken repay rounding dust**: `burn()`'s scaled-amount rounding can leave sub-wei dust in
  `_scaledBalances` after a "full" repay — real but economically negligible (sub-wei per repay), not filed as a
  separate finding.

## Ledger

`ledger.py add liquihood real "0xD26F926CEBdd169D87c5a615C18A3A8AddbBdF6E:LendingPool.withdraw/_buildPositionArrays vs LHToken split-brain -> 100% supplier interest stranded, PoC-proven, dormant/pre-launch"`
