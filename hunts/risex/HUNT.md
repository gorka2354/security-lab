# RISEx — fully on-chain perps CLOB (RISE Chain 4153) — HUNT LOG

**Status:** REACHED (via decompile) → READ → CLEAN on the readable+trace-verified surface;
one role-gated residual named. Live + active + funded ~$16.4M USDC.e. Un-audited, no bounty, closed-source.

## Reach (the methodological win — closed a wall the whole industry sees as closed-source)
- RISE Chain: id 4153 (0x1039), RPC https://rpc.risechain.com, Blockscout https://explorer.risechain.com —
  NO Etherscan-v2 coverage → fetch_source.py / reach_bytecode.py don't run. Impls UNVERIFIED on Blockscout +
  not on Sourcify + not open-sourced on GitHub.
- Recipe (see memory heimdall-wsl-path-and-unverified-evm-reach): resolve each EIP-1967 impl via direct RPC
  eth_getStorageAt → eth_getCode → `/root/heimdall decompile <hex> --include-sol` in WSL Ubuntu-24.04.
- 7 impls decompiled: PerpsManager (0xb4784436), OrdersManager (0xfa36e52d), CollateralManager (0x5b8ac126),
  FundingRate (0x414ec151), RISExOracle (0x02ed481a), SpotManager (0x38a323cf), Router (0x9bbae49f).

## Read (5 Opus agents by subsystem + Opus skeptic synthesis) — CLEAN on the readable surface
- **Reachability (eth_call-proven on live RPC):** EVERY value-moving entrypoint reverts AccessManagedUnauthorized
  (0x068ca9d8) to an unprivileged caller — liquidate 0xff508b4a, crossTakeover 0x8aa1c60c, isolatedTakeover
  0x05f30511, executeADL 0x62d0ee3e, executeVaultOtc 0x3ada349a, forceCancelOrders 0xbb08aff3. No open value path.
  The only direct actor is a role holder (keeper/XLP). setImpactPriceCache is internal-only (0x7cb45f65).
- **Order-margin math verified correct** against GTE ground truth (RISEx forks GTE-perps margin math):
  notional = size*price/1e18 booking matches CLOBLib.placeOrder / ClearingHouse._getCollateral. Not a bug.
- **2 LOW hardening advisories (defense-in-depth, NOT unprivileged-exploitable — goodwill only):**
  1. RISExOracle wrapper has NO active on-chain circuit breaker: deviationThresholdBps()=0, no fallback source
     set, no block.timestamp staleness revert in getMarkPrice/getIndexPrice (staleness fully delegated to Stork's
     signed pull feed). Docs promise a 1h max-age block the code omits. Setters are role-gated (user can't disable).
  2. The premium-index / funding keeper surface is permissionless (isAllowed==true for everyone: snapshotPremiumIndex,
     syncMarkPriceEMA, settleFundingRate). Bounded 3 ways in the decompile: 5s sample-contiguity gate, once-per-hour
     funding gate, ±4% clamp. A bounded cross-subsystem nudge primitive, not a self-contained drain.

## Live-trace grounding (my own, read-only — reinforces CLEAN)
- liquidate is the HOT path: 278 calls in a ~400-tx window, 235 success / 43 revert (**15% revert rate**).
  The reverts PROVE a real on-chain liquidatability health-check exists — liquidate does NOT blindly trust the
  role caller (answered synthesis open-question #2). debug_traceTransaction IS supported on the RPC.
- Liquidation settles via an INTERNAL ledger, not ERC20 transfers (USDC.e stays in CollateralManager; balances
  move in storage). Full mark-price pipeline seen in the call tree: liquidate → CollateralManager.af9fa7b6 →
  RISExOracle.d02641a0 → RISExStork → Stork impl 0x610a45e5fd (mark from Stork) + impact price from the book.
- Decoded a real successful liquidation (tx 0xbe84436d, market 19): event accounting CROSS-RECONCILES —
  PerpsManager event fee words (0.009123e18, 0.304e18) exactly equal the FeeManager credit events; victim PnL
  present (-1.31e18); liquidation payment routed to XLP/insurance 0xa51c3d367e895988232750d297d8904cd712ab91.
  The engine is healthy and its accounting balances on real executions.

## Residual (NOT closed) — the zero-price takeover FORMULA honesty
- heimdall could NOT recover the zero-price / (mark±adjustment) takeover arithmetic: in BOTH PerpsManager and
  CollateralManager the operands flow through cross-contract staticcalls (68501aee/af9fa7b6/f52b6528) whose
  unverified return types heimdall filled with 0/1 → the math (getWithdrawableUSDC/getAccountEquity/
  creditLiquidationFee) is decompiled as `* 0` / `/ 0x01` garbage. Static analysis is DEAD on this slice.
- It IS recoverable from live event data (schemas decoded above) + historical oracle state, but the residual is
  **role-gated**: only a keeper/XLP triggers liquidation, so a formula mis-rounding would be a bounded
  "malicious/mispricing keeper extracts slightly more / shorts the insurance fund" centralization-adjacent issue —
  NOT an unprivileged-attacker drain of the $16.4M. Skeptic synthesis (Opus): "No confirmed critical/high, nothing
  justifies disclosing a fund-loss exploit against the live $16.4M."
- To fully close it would take one dedicated agent: decode the liquidation event schemas precisely, pull the
  pre-liq oracle mark + position at that block (RPC archival?), re-derive expected zero-price = mark*(1±adj) with
  bankrupt flip + ≤1% fee retention, and check insurance-fund/counterparty conservation across N liquidations.

## Verdict
Reached + read + trace-grounded. **CLEAN for an unprivileged attacker.** 2 low goodwill-hardening advisories
(oracle circuit-breaker inert; permissionless funding keepers). Residual = role-gated liquidation-formula honesty,
sub-High by the attacker model, closeable only by event-grounding — deferred pending a decision to fund it.
