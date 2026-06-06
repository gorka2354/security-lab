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

## Method note
hypothesizer (emergent seed) -> me (verifier, read the funnel) -> verdict SOUND + one Low nuance.
A refutation is a valid output. Untouched seeds for a next pass: raffle RNG/VRF, staking
`decreaseAndDestroy` round-trip.
