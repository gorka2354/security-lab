# Hunt: Crypto Unicorns (Laguna Games) — comprehensively CLEARED

**Target:** Crypto Unicorns — breeding/farming GameFi, EIP-2535 Diamonds on Xai (660279) + Arbitrum (42161).
Self-hosted bounty up to **$200k**, disclosure **bounty@laguna.games** (NO platform KYC → no-KYC-friendly).
Source = public `Laguna-Games` GitHub `cu-osc-*` repos (= deployed verified code). White-hat, user discloses.

## Verdict: WELL-BUILT across all modules. No exploitable finding.
Deep-triaged (recon + L3/L4 hypothesizer + multi-module facet→Lib trace). Diamond facets are thin + gated
(`LibDiamond.enforceIsContractOwner` / `enforceIsController` / SSS signatures); logic is in `Lib*`.

| Module (repo) | What was checked | Verdict |
|---|---|---|
| Shadowforge staking (`cu-osc-shadowforge`) | stake/unstake/harvest/forceUnstake | LibStaking everywhere `require(staker==msg.sender)` — clean |
| Shadowforge rewards | claimRewards / global+player queue | **no double-claim**: claim window `[cWC-6..cWC-1]` + `getDequeueCount` removes all-but-current → claimed waves can't be re-claimed; `calculateRewardsByWaveId = waveUNIM*pQty/gQty`, Σowed ≤ waveUNIM (rounds down); no underflow/cross-player corruption in `deductClaimedRewards` |
| Marketplace (`cu-osc-marketplace`, thirdweb V3 fork) | buyFromListing / buyFromMultipleListings / acceptOffer | CEI (effects before payout/NFT), price-match anti-frontrun, currency-validated (`getTargetTotalPrice`), bulk-buy aggregates+checks `msg.value`; `_payout` verbatim thirdweb — clean |
| Game Bank (`cu-osc-game-bank`) | UNIM/DarkMarks mint/burn, stash/unstash, withdraw | mint/burn `enforceIsController` (owner-managed allowlist); stash requires gameServer-SSS sig + replay-guard + deadline, funds→signature-bound owner; withdraw owner-only — clean |
| SatBank (`cu-osc-satbank`) | DropperFacet claim, SatBankFacet claim, ProductFacet buy | replay-ledger `DropRequestClaimed[dropId][reqId]` + sig-bound-to-claimant + signer-holds-auth-pool + nonReentrant; separate replay namespaces per payout path — clean |

## Non-bounty hygiene notes (optional goodwill disclosure → reputation)
- `SatBankFacet.claim` with `amount==0`: deducts 0 from app balance but `super._claim` pays the default → app-balance drift. **Server-trust** (needs valid app-server sig), not external-exploitable.
- `LibCurrencyTransfer` imports forge-std `console` in a production library (debug leftover).
- `buyFromMultipleListings` length check omits `listingIds.length == currencies.length` (OOB-reverts or ignores extras → not exploitable).
- `enforceValidAppOwner` only asserts the app exists (misleading name); `removeRitualTemplateFromPool` is a `revert("not implemented")` stub.

## Method value (the real takeaway)
- L3/L4 hypothesizer dig worked: derived a precise double-claim invariant → traced 4 fns → refuted rigorously.
  An independent agent **re-derived the same dequeue guard** → cross-validated the reasoning.
- Toolkit hardened from CU: **fix#18** (Diamond `enforce*`-auth), **fix#19** (thin-facet-delegator softener).
  Recurring FP confirmed: facet→Lib leaf-call gating (backlog: full transitive-gating call-graph; `*Fragment.sol` stubs).
- Re-check trigger: CU Diamonds are upgradeable — if a facet is replaced post-review, `livecheck` the diamond + diff.
