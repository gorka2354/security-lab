# HUNT: Mellow Flexible Vaults (sherlock-audit/2025-07-mellow-flexible-vaults)

New fresh target (Sherlock contest, concluded 2025-07). A modular ERC4626-style vault kit:
Vault/Subvault, ShareManager (Basic/Tokenized), async Deposit/Redeem queues (FenwickTree
accounting + Checkpoints prices), Oracle, FeeManager/RiskManager, Lido/redirect hooks,
EigenLayer/Symbiotic verifiers, consensus/bitmask permissions. 39 prod .sol, normal Solidity
(good engine fit, unlike assembly-heavy Fluid which we skipped). Clone gitignored in
`hunts/_volume/mellow`. Recon: `mellow-recon.md`; hypotheses: `mellow-hypo.md`.

## The upgraded hypothesizer's best output yet
The controllability+bridge ranking produced **15 shared-state roots touching a recon-flagged fn**
(vs 0-4 on prior targets) and a sharp **EMERGENT+RECON+OPEN** list aiming straight at the async
queue accounting: `claim`/`deposit` (attacker-callable, reentrancy-flagged) sharing `$.allocatedShares`
/ `$.pendingBalance` / `$.vaultState` / `$._totalSupply` with `acceptReport`/`handleBatches`/
`cancelDepositRequest`. That is exactly where async-vault bugs live -> it aimed me right.

## Deep-dive + triage (verify-before-claiming; two self-caught false alarms)
- **DepositQueue async accounting -> SOUND.** One pending request per user (claim-or-revert on
  re-deposit); FenwickTree sums a batch; `_handleReport` allocates `assets*reducedPrice` shares to the
  pool; per-user `_claim` floor-divides (dust stays in the pool -> no over-claim). `claim` mints the
  vault's OWN share token (no external callback) so the missing `nonReentrant` on it is harmless;
  `cancelDepositRequest` only before the price is set. **Self-caught false alarm:** I first suspected
  `_claim`'s `prices.lowerLookup(request._key)` looked up the WRONG direction -> re-checked OZ
  Checkpoints: `lowerLookup` = "first checkpoint with key >= search" = the first report at/after the
  deposit = correct pricing. Not a bug.
- **`ShareManager.mintAllocatedShares:212` (recon: PUBLIC mint [!]) -> FP -> fix#31.** It has no
  modifier and drains the shared `$.allocatedShares` pool minting to an arbitrary `account` -- looked
  like a critical "front-run the claims, steal the allocated pool" bug (allocateShares is `onlyQueue`
  but this wasn't!). **Verified safe:** it calls the sibling `mint()` (line 223) which is
  `onlyVaultOrQueue`; msg.sender is preserved across the internal call, so an attacker EOA reverts
  inside `mint()`. Transitively gated -> not exploitable.

## Outcome -- no finding (partial pass), system hardened: fix#31
- **fix#31 det_mint:** a mint/burn wrapper that delegates to a bare gated sibling `mint(`/`burn(`
  (not the `_mint` primitive) is now recognized as a thin delegator (`[.]`), not "PUBLIC mint" (`[!]`).
  Extends fix#25 (which only caught `mintX(`-with-capital). Verified on Mellow `mintAllocatedShares`;
  a real ungated mint calling `_mint(...)` still stays `[!]`. Regression tests +1 (129).
- **Not exhausted (a longer audit could pull):** RedeemQueue symmetry; the consensus/bitmask Verifier
  + EigenLayer/Symbiotic verifier access model; SignatureDeposit/RedeemQueue (EIP-712 binding/replay);
  Oracle report acceptance + FeeManager math; the Subvault `callHook` external-call surface.

**Lesson:** the engines aimed PERFECTLY (det_mint + the controllability-ranked hypothesizer both
converged on `mintAllocatedShares`/`allocatedShares`), and the value was the disciplined verification:
two plausible "criticals" dissolved on a careful read (lowerLookup direction; transitive `mint()` gate),
and the second became fix#31. Verify before claiming -- always.
