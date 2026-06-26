# Fan-out triage: defillama-immunefi-wave  (chain multi)  2026-06-26

7 targets triaged. **TRIAGE-LEVEL** -- `top_leads` are HYPOTHESES from a shallow skim, NOT verified findings; deep L4 happens later on the DIG queue.

| target | type | chain | gate | fork/audit | rec | top leads (hypotheses) |
|---|---|---|---|---|---|---|
| Twyne (twyne-contracts-v1) | lending / credit-delegation (Euler EVC/EVK layer) | multi | LIVE + in-scope. 1 | greenfield-custom (built | **DIG** | Custom liquidation eligibility _canLiquidate uses ; liquidate() transfers vault ownership to liquidato; rebalance() and canRebalance() are permissionless  |
| Vena Finance (native money market of Fluent L2) | lending,credit | multi | LIVE. Fluent chain | fork-of-Aave-V3 (aave-v3 | **PARK** | PythAggregatorAdapter.latestAnswer() has NO price>; divide-before-multiply precision loss on high-expo; AaveOracle base-currency unit vs adapter decimals  |
| GAIB (AID synthetic dollar / sAID staked vault) | rwa,lending,yield (AI-infra GPU-backed RWA; AID synthetic dollar + sAID ERC-4626 staking vault) | multi | LIVE + funded. sAI | greenfield-custom — sAID | **PARK** | Deposit-vs-exit valuation asymmetry on unrealizedL; Unbacked liquidity drain accounting: deploy() lowe; FIFO queue partial-fill / head-advance accounting |
| Dango Bridge (left-curve / dango.exchange) | bridge,deposit | multi | DEPLOYED + active. | fork-of-X (base = Hyperl | **SKIP** | Custom Hyperlane Warp-Route message handler on the |
| SoDEX Bridge / SoSoValue SSI Protocol | bridge,dex,index | multi | Live + active: TVL | greenfield-custom — SSI  | **SKIP** | - |
| Antarctic Exchange (Antarctic / AX) — perp DEX on Arbitrum | perp,dex | multi | UNKNOWN on-chain c | greenfield-custom — prop | **SKIP** | - |
| Citrea Bridge (chainwayxyz/token-bridge) — LayerZero v2 OFT mint-and-burn bridge, BTC<->Ethereum | bridge | multi | DEPLOYED + active: | fork-of-USDT0 (LayerZero | **SKIP** | - |

## Deep-dive queue (DIG / DIG-CAREFUL) -- verify these by hand

### Twyne (twyne-contracts-v1)  (DIG)
- Reachable (live verified source + public repo), live + in-scope on a NEW $50k Immunefi program, greenfield custom credit-delegation math (no audited base, no public v1 audit found), perfect zone fit (lending), and a dense novel attack surface: custom dual-source liquidation/health math with explicit read-only-reentrancy warnings, regime-bracketed liquidation-incentive rounding, permissionless rebalance moving credit between vaults, and EulerRouter oracle-quoted collateral feeding solvency. This is exactly the under-reviewed-fresh + custom-economic profile that beats hardened deploys.
  - lead: Custom liquidation eligibility _canLiquidate uses Euler accountLiquidity + exter  [hunts/_volume/twyne/src/twyne/EulerCollateralVault.sol:139 (_canLiquidate), :129] (?)
  - lead: liquidate() transfers vault ownership to liquidator (borrower=liquidator) and co  [hunts/_volume/twyne/src/twyne/CollateralVaultBase.sol:529-549 + collateralForBor] (?)
  - lead: rebalance() and canRebalance() are permissionless (anyone can call) and move cre  [hunts/_volume/twyne/src/twyne/CollateralVaultBase.sol:601-608 (rebalance), :241-] (?)
  - lead: BridgeHookTarget blocks Euler-native borrow/liquidate via fallback revert, gatin  [hunts/_volume/twyne/src/TwyneFactory/BridgeHookTarget.sol:31-38] (?)
  - lead: claimRewards() is fully permissionless and does a raw low-level call to INCENTIV  [hunts/_volume/twyne/src/twyne/AaveV3CollateralVault.sol:375-379] (?)
