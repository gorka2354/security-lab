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

## Deep-dive result -- the REPO is CLEAN; the compliance bug-surface is OFF-REPO
Read the full chokepoint + admin model:
- **Validation is correctly centralized:** `LibERC20._update` (the single path for transfer/transferFrom/
  mint/burn) calls `ITransferValidation(address(this)).beforeUpdateValidation` (pre) + `afterUpdateValidation`
  (post) on EVERY balance change -- incl. CCT mint (from==0) and burn (to==0). Right design (no path skips it).
- **...but the shipped validator is a NO-OP:** `DefaultValidationFacet.{before,after}UpdateValidation` are
  empty. So this repo's default token has NO transfer restrictions -- the real compliance facet (whitelist/
  blacklist/holder-caps) is cut in per-deployment via `diamondCut` and is **NOT in this repo**. The genuinely-
  custom RWA bug-surface (restriction bypass) therefore cannot be hunted from source here.
- **Admin model is coherent:** `DiamondCutFacet.diamondCut` -> `enforceIsDeployer` (deployer = super-admin:
  add/replace facets + arbitrary `_init` delegatecall); `transferOwnership`/`setDeployer` -> `onlyDeployer`;
  CCT operator mgmt -> `onlyOwner`. `initializeDiamondCut` (recon :158) reachable only via the deployer-gated
  cut/constructor -> FP. No unprotected init / re-init.
- ERC20/Diamond/CCT all standard. No first-depositor/oracle/reentrancy/supply issue. **No finding in-repo.**

## Status -- CLEAN (repo); deeper surface UNREACHABLE (DefiLlama gave the token, not a deployed diamond)
Reachability fix VALIDATED end-to-end (scout github -> CORE repo -> forkdrift original/unaudited -> recon ->
read). The repo is a clean, minimal Diamond CCT-ERC20 with an extensible no-op validator -- no in-repo finding.
On-chain probe to reach the real validation facet: `facetAddresses()` (DiamondLoupe) on the DefiLlama address
0xa642...50ed -> it has code ONLY on Ethereum and is NOT a diamond (returns nothing); no code on BSC/Arb/
Polygon. => 0xa642 is the **STBX token**, not a deployed STV3 diamond. The actual per-asset STV3 diamonds
(carrying the real compliance facet) are at addresses DefiLlama does not list -> the compliance bug-surface is
**not reachable** without those addresses (the gov-token trap, again -- even the github-CORE-repo route can't
recover a per-deployment facet that isn't in the repo). VERDICT: clean triage, closed. To revisit, one would
need a concrete deployed STV3-diamond address (Stobox app/docs/an issuer's token) -> DiamondLoupe -> fetch the
cut-in validator -> hunt restriction-bypass. Ledger: repo + CCT clean (known); compliance facet = unreachable.
