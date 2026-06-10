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

## DEEP-DIVE (the parked surface, 2026-06-10) -- RESULT: no finding, competently built
- **Signature scheme** (`_verifySettle/RemoveCollateral/LiquidationSignature` 542-607): textbook -- OZ EIP-712
  (`_hashTypedDataV4` -> chainid in the domain), a DISTINCT type-hash per request (SETTLEMENT_/REMOVE_COLLATERAL_/
  LIQUIDATION_REQUEST_SIGNATURE_HASH) so a shared `nonces[]` mapping can't cross-type-replay, `_updateNonce`
  (replay) + `deadline` (expiry), OZ `ECDSA.recover` (malleability/address(0)), and the hash COVERS every
  economic field (nonce/deadline/trader/positionUpdates/claimCollaterals + the recipient). No replay/nonce/
  expiry/chainid/missing-field bug.
- **NativeLPToken share-vault** (custom, not OZ-4626): `totalUnderlying` is BOOKKEPT (deposit/distributeYield
  increment it) -> a direct donation can't move the share price (donation-inflation defeated, Lagoon-style);
  `distributeYield` is `onlyCreditVault` -> an attacker can't inflate for a first-depositor attack; conversions
  round DOWN (protocol-safe); `minDeposit` bounds dust. No first-depositor/donation/rounding finding.
- `addCollateral`:311 = documented permissionless deposit (FP). `liquidate`:250 = onlyLiquidator + signed (operator-trust).

**Conclusion:** Native Credit Pool is a competently-built greenfield credit vault. The whole economic state is
OFF-CHAIN-SIGNED by a single trusted `signer` (operator-trust = gate E) -> the on-chain attack surface is thin
and the deep-read of its two high-EV areas (signature scheme + LP share math) found no demonstrable bug. CLEAN.
This was also the first REAL deep run of /hunt -- the L4-READ + VERIFY discipline arrived at an honest, evidenced
"no finding / well-built / operator-trust" verdict (exactly its job). Ledger: 311 fp, signature/LP known, 250 (liq) known.
