# HUNT: Native Credit Pool -- /hunt SKILL TEST (end-to-end dogfood, 2026-06-10)

First real run THROUGH the `/hunt` skill. DefiLlama Lending, audits=0, ~$31M, Ethereum. CreditVault (RFQ/
off-chain-settled credit lending) + NativeLPToken + transient-storage libs. forkdrift: original code, NO
audit -> greenfield. Reached via DefiLlama-Adapter CORE addr (0xe3D4...) + Etherscan key.

## Skill flow validated (the point of this run)
Phase 0 SOURCE (reachability-first correctly SKIPPED Templar=Rust) -> 1 REACH (fetch_source+Etherscan, 26
files) -> 2 TRIAGE (forkdrift: greenfield) -> 3 DETECT (recon: 311 sibling[!], 250/445 liquidation[!],
round-trips) -> 4 L4-READ + 5 VERIFY:
- `CreditVault.sol:311` addCollateral -> **FP** (NatSpec-documented PERMISSIONLESS deposit; gate C + FP#10).
- `CreditVault.sol:250` liquidate -> **operator-trust** (onlyLiquidator + off-chain _verifyLiquidationSignature;
  recon 4-check N/A on-chain) -> not an on-chain finding as-is.
The kill-gates correctly killed both top recon leads -> no false alarm. SKILL WORKS END-TO-END.

## Parked (real deep surface, if pursued -- this was a skill test, not a full hunt)
- `_verifyLiquidationSignature`: replay / nonce / expiry / chainid (signed liquidation requests = classic bug source).
- Round-trips: addCollateral<->removeCollateral, deposit<->withdrawReserve rounding/fee leak.
- rebalance-cap accounting (`_updateRebalanceCap`) across liquidate's collateral+position legs.

## Status -- /hunt skill TEST PASSED. No finding this run (top leads by-design/operator-trust); Native is a
## genuine greenfield lending target with a parked signature/round-trip surface. Ledger: 311 fp, 250 todo.
