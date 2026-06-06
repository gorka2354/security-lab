# HUNT: Aavegotchi (aavegotchi/aavegotchi-contracts) — on-chain game (diamond)

User's edge (gaming). Surfaced by `hypothesize.py` after the universal-accessor fix
(diamond `s.`). Bounty: self-run/verify (analysis of public code is legal; report only
if in-scope). Clone in gitignored `hunts/_volume/agotchi`.

## Hypothesizer seeds (game logic)
- `decreaseAndDestroy` <-> `increaseStake` (destroy gotchi to reclaim collateral) — round-trip.
- raffle `enterTickets` <-> `exitTokens` + Chainlink VRF — RNG/economic.
- **marketplace `s.nextERC1155ListingId` <- 6 fns** (executeERC1155Listing / batchExecute /
  setListing*) — emergent listing-accounting candidate (Treasure-class). **<- triaged below.**
- No invariant harness found (games rarely fuzz -> more room).

## Triage: ERC1155 marketplace execute (the emergent seed) — verdict SOUND
`ERC1155MarketplaceFacet.handleExecuteERC1155Listing` is the single funnel for all execute
paths (single / toRecipient / batch). Read end-to-end:
- **CEI-compliant** — all state effects happen BEFORE the external callback: `quantity -=`
  (L270), GHST `transferSales` (L280), item `removeFromOwner`/`addToOwner` (L322-323),
  `sold=true` (L316). The only external callback is `onERC1155Received(_recipient)` (L325) /
  `safeTransferFrom` (L328), and **after it there are ONLY emits** (L330-345). No state-after-
  interaction -> **no reentrancy**.
- Proper checks: not-found / sold / cancelled / price-matches / address / id / `seller!=buyer`
  / whitelist / `quantity>0` / `quantity<=listing.quantity`. Price can't be manipulated (must
  equal `listing.priceInWei`).
- `batchExecuteERC1155Listing` (<=10) funnels through the SAME `handleExecute` -> no batch-bypass.

**Verdict: SOUND.** No reentrancy, no double-execute, no batch-bypass. Mature/audited code.

### Noted nuance (possible Low, by-design?)
Whitelist is checked on `buyer = msgSender()` (L266), but `executeERC1155ListingToRecipient`
delivers to an arbitrary `_recipient` (NOT whitelist-checked). So a whitelisted buyer can
proxy-deliver a whitelist-gated item to a NON-whitelisted recipient. Real IF the whitelist's
intent is to gate the final OWNER (not just the executor); needs Aavegotchi's whitelist
semantics to confirm. Severity Low (needs a willing whitelisted accomplice; no fund loss).

## HEAD-TO-TOE sweep of ERC1155MarketplaceFacet (scope.py-driven) — 14/14 = 100%
Demonstrating the COVERAGE-driven method (not lead-driven): every entry point reviewed,
auth followed into the lib. Verdict: SOUND, with 2 minor by-design items the sweep found.

| # | entry point | access | verdict |
|---|---|---|---|
| 1 | setListingFee | onlyDaoOrOwner | FP (admin) |
| 2 | setERC1155Categories | onlyItemManager | FP (admin) |
| 3-5 | setERC1155Listing / WithSplit / WithWhitelist | UNGATED -> createERC1155Listing | SOUND (checks balanceOf>=qty, isApprovedForAll, cost>=1e15, split=10000) |
| 6 | cancelERC1155Listing | UNGATED -> lib | SOUND (lib: `require(listing.seller==_owner)`) |
| 7-9 | execute / executeToRecipient / batchExecute | UNGATED -> handleExecute | SOUND (CEI; full checks; batch funnels same path) |
| 10-11 | updateERC1155Listing / Batch | UNGATED | SOUND (permissionless re-sync poke vs owner's real balance; public-good) |
| 12 | cancelERC1155Listings | onlyOwner | FP (admin moderation) |
| 13-14 | updateERC1155ListingPriceAndQuantity / Batch | UNGATED -> lib | **LOW** (see below) |

**Findings (both minor / by-design):**
1. **whitelist-recipient** (execute path): whitelist gates `buyer=msgSender`, not the `_recipient`
   of `executeToRecipient` -> whitelisted proxy can deliver to a non-whitelisted holder. Low.
2. **no-op fee** (`updateERC1155ListingPriceAndQuantity`, lib L124): the price/quantity writes
   are **commented out** (`// listing.priceInWei=...` "until subgraph is synced"), yet the facet
   still **charges the listing fee** (L389-391). Seller pays for a no-op update; a buyer acting on
   the emitted "new price" would revert (execute checks the unchanged on-chain price -> no fund
   loss). Low / by-design-temporary. **The full sweep found this; a lead-scan would have missed it.**

**Why this matters:** the coverage sweep covered the admin fns, the lib auth, AND the commented-out
logic - the whole surface - and surfaced the no-op-fee oddity that targeted triage skipped. This is
the head-to-toe method working on a real component. Same method x scale = whole project (263 fns),
resumable via the coverage counter + ledger.

## L3 fuzzer: PROVEN LIVE (the other missing piece)
`forge test` on `invariant-lab` (forge 1.7.1): `invariant_solvency()` **caught the planted insolvency**
in the buggy staking and **shrank it to a 7-call sequence** (notify->stake->warp...); the safe version
passed. So the math/invariant layer works end-to-end - the only gap is building a REAL target's deps.

## Method note
hypothesizer (emergent seed) -> me (verifier) -> verdict; THEN coverage sweep to 100%. A refutation
is a valid output. Untouched seeds for a next pass: raffle RNG/VRF, staking `decreaseAndDestroy`.
