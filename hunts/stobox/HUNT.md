# HUNT: Stobox STV3 (StoboxTechnologies/Stobox_STV3_Protocol) -- scout v2 + REACHABILITY-FIX first catch

Surfaced by `scout.py --source defillama` (RWA tokenization, audits=0, ~$15.1M, Arbitrum/BSC/Polygon).
**First target reached via the reachability fix:** DefiLlama listed only the STBX gov token
(0xa642...50ed), but scout's new core-repo resolver followed DefiLlama's `github` field to the actual
CORE repo `StoboxTechnologies/Stobox_STV3_Protocol` (Solidity) -> cloned the MECHANISM, not the token.
forkdrift: ORIGINAL code (no fork base), NO audit evidence -> greenfield / high-EV. PARTIAL pass.

## What it is -- a Diamond (EIP-2535) RWA security-token
`StoboxProtocolSTV3` + facets: `CCTFacet` (Chainlink Cross-Chain Token burn/mint), `DefaultValidationFacet`
(transfer-restriction / compliance), DiamondCut/Loupe. Libs: `LibCCT`, `LibERC20`, `LibDiamond`. ERC677
(`transferAndCall`). The novel/custom surface for an RWA security token = the COMPLIANCE / transfer-validation
layer (who may hold/transfer), not the ERC20 plumbing.

## Triaged
- `CCTFacet.mint/burn/burnFrom` (32-42) + `LibCCT` -> **by-design (standard Chainlink CCT)**: mint is
  `onlyOperator` (operators added by `onlyOwner`), `LibCCT.mint` bounds by `maxSupply` + OZ `_mint` (no
  address(0)). This is the CCIP burn-mint-token pattern (the bridge pool is the operator) = operator-trust,
  NOT attacker-mint-from-nothing. Not a finding.
- `LibCCT.transferAndCall:76-83` (recon: unchecked-transfer :77 + ERC677 callback) -> **FP/by-design**:
  `LibERC20.transfer` is the token's OWN internal transfer (reverts on failure; not an external ERC20 whose
  bool you'd drop), and the `onTokenTransfer` callback fires AFTER the balance update (CEI-correct ERC677).
- `StoboxProtocolSTV3.sol:40` DISABLED-signal -> FP (a fragment of a NatSpec comment, not a disabled check).
- `LibDiamond.sol:158` initialize -> standard OZ/diamond LibDiamond (known/by-design).

## Threads parked (deep pass -- the genuinely-custom RWA surface)
- **`DefaultValidationFacet` / `ITransferValidation`** -- the compliance/transfer-restriction logic. THE place
  an RWA-tokenizer bug lives: can a restricted/blacklisted holder be bypassed? is validation enforced on ALL
  paths (transfer, transferFrom, transferAndCall, CCT mint-to)? is there a hook that skips it? (e.g. CCT
  `mint(account,...)` mints to `account` -- is `account` compliance-checked, or can the bridge mint to a
  non-whitelisted address?). Cross-check whitelist enforcement across every balance-changing entry.
- L2/AA footguns x2 (recon) -- if deployed on zkSync, the `to.code.length > 0` ERC677 check + any
  isContract-style gate; verify per deployed chain (it's on BSC/Arb/Polygon -> likely N/A, but confirm).

## Status -- PARTIAL (greenfield triage; CCT layer clean; compliance layer parked)
Reachability fix VALIDATED end-to-end: scout(github) -> CORE repo -> forkdrift(original/unaudited) -> recon.
CCT/ERC20 plumbing is standard-and-clean; the EV is in the compliance/transfer-validation facets (parked).
LIVE-FIRST: STV3 is deployed (~$15.1M across Arb/BSC/Polygon) -- confirm the exact deployed facet addresses
+ an in-scope bounty before treating any compliance-bypass as a finding. Ledger: CCT by-design (known),
compliance todo.
