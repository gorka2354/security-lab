# dealers-sh (Dealers.sh / "Drug Wars") — Abstract Chain (2741)

Sourced: GitHub fresh-Solidity sweep (`language:Solidity abstract chain pushed:>2026-07-15`) ->
`Dealers-sh/dealers-contracts` (public repo, created 2025-10-28, pushed 2026-08-20, `AUDIT.md`
soliciting third-party review — pre-audit at time of this hunt). On-chain PvE/PvP mafia strategy
game on Abstract Chain (zkSync-based L2, chain id 2741). ~12k SLOC across 19 contracts.

## Reach

- Source: full repo clone (`hunts/_volume/dealers-contracts`, gitignored), not just Etherscan —
  repo ships `script/data/deployments/mainnet.json` with the live address book.
- Deployed + LIVE + ACTIVE + FUNDED (confirmed via Etherscan-v2 multichain API, chainid=2741, and
  direct `eth_call`/`eth_getLogs` against `https://api.mainnet.abs.xyz`):
  - `DealersHeists 0x4B7A7E9dD2254c7848Def422cEB517AC6310C90e` — 0.1536 ETH, nonce 76803 (heavy
    usage), last tx ~1.5h before this hunt.
  - `DealersPaymentHandler 0x798E0f15A34F491eF4A69E9CC626A625bb80A504` — 0.1062 ETH.
  - `DealersBankHeist 0x987779Fd28E24D9cBeB7c22Eb1AFE1B7771ED5e1` — 0.3956 ETH.
  - `DealersNFT 0x610CcEe1AE4aFF961d043faB379491C2997383F7` — 0.0690 ETH; `totalMinted()=502` /
    `MAX_SUPPLY=10000` (5% sold, mint actively ongoing at 0.01 ETH/dealer).
  - `threat.py --chain abstract 0x610CcEe1AE4aFF961d043faB379491C2997383F7` -> **LIVE + ACTIVE +
    FUNDED, first-seen ~65d ago, 20 recent txns, last tx 0.0d ago -> HIGH urgency.**
- `AUDIT.md`'s own scope table marks `DealersNFT`/`DealerRendererSVG`/`DealerRendererHTML` "in
  scope" (checkmarked) alongside the ETH-custody game modules.

## Pattern catalog swept (all in scope of AUDIT.md's "session-key priority" list)

Read in full: `DealersRandomness.sol`, `DealersHeists.sol`, `DealersBankHeist.sol`, `DealersPVP.sol`,
`DealersActions.sol`, `DealersPaymentHandler.sol`, `DealersBoosts.sol`, `DealersClaims.sol`, plus
`DealersCore.sol`'s `onlyAuthorized` gating.

**HONEST NEGATIVE for all of the above** — the commit-reveal RNG (`DealersRandomness`, blockhash-
based, `reveal()` is a public view with no per-consumer secrecy) is consistently defended by paying
the stake/attempt cost **at commit time, not reveal time**, and by making every `resolve*` function
permissionless ("anyone may call"). Verified concretely for each consumer that a losing/expired
outcome costs the same as a normal loss (`DealersHeists._bust` vs `resolveStage`'s expiry branch;
`DealersPVP._applyExpiryAsLoss` vs a normal loss's `repDelta`/heat; `DealersActions.commitBreakout`/
`commitWantedPoster` spend the attempt unconditionally at commit) — so the classic "peek the
blockhash then selectively withhold reveal" grind has no positive-EV branch. `DealersBankHeist`'s
`reservedETH` liability bookkeeping was traced through every writer (`enter`/`settle`/`claim`/
`claimRefund`/`sweepExpired`) and is internally consistent; CEI + `nonReentrant` hold throughout.
Reentrancy guards are per-contract (OZ shared `_status`), so cross-module reentrancy via a
malicious NFT-owner's `receive()` was checked at every ETH-transfer site (`claimJackpot`,
`BankHeist.claim/claimRefund`) — no exploitable cross-contract state race found (CEI is followed
before every external call). `DealersBoosts`'s missing owner-check on `purchaseBoost*` is
intentional "gift a boost to any tokenId" behavior, consistent with `DealersActions.purchaseCash`/
`purchaseAttemptReset` — caller always pays for value that only helps the target, not a
vulnerability.

## THE FINDING — HIGH: NFT reveal is deterministic + attacker-orderable -> one-of-one sniping

**`src/nft/DealersNFT.sol`** (mint 502/10000 done, minting still open at 0.01 ETH):

- `_revealOrReanchor` (lines 320-335): `poolIndex = _drawPool(keccak256(blockhash(rb), tokenId))`.
  The seed has **no secret / per-caller component** — comment at line 318 even says so explicitly
  ("Seed deliberately excludes msg.sender so the result is caller-independent"), a design chosen to
  keep a permissionless keeper honest, but which also means **anyone can compute the exact seed for
  any token off-chain the moment `blockhash(rb)` exists** (no need to even call the view fn).
- `_drawPool` (lines 341-359): a lazy Fisher-Yates draw over shared, mutable `poolRemaining`
  (`public`) / `poolCache` (`private`, but ordinary storage — readable via `eth_getStorageAt` like
  any other on-chain value, or fully reconstructable by replaying public `DealerRevealed` events).
  `i = seed % poolRemaining` — so for a **fixed seed**, the resulting `poolIndex` is a function of
  `poolRemaining` **at the moment of the call**.
- `resolve`/`resolveMany` (lines 288-314): fully permissionless, **no restriction on which tokenId
  is revealed in what order** — `resolveMany` reveals a caller-supplied array strictly in the given
  order, atomically.

Chain: a player who mints a batch (up to `MAX_PER_WALLET=10` in one `mint()` call, so all share one
`revealBlock = block.number + REVEAL_DELAY(2)`) can, once `blockhash(rb)` exists, off-chain compute
every one of their tokens' fixed seeds and simulate `_drawPool` under every candidate reveal
*ordering* of their own batch (trivial integer swap simulation) to find an order that lands one of
their tokens on a specific, already-known-valuable `poolIndex` — then submit that exact order via
`resolveMany` in one atomic tx. No special access, no extra cost beyond normal mint price + gas; a
losing simulation costs nothing (don't submit, or mint another batch with a fresh blockhash and
retry).

**"Already-known-valuable" is not hypothetical — confirmed live on-chain right now:**

- `DealerRendererSVG.oneOfOnes(poolIndex)` is a `public` mapping; the owner populates it via
  `setOneOfOne`/`setOneOfOnesBatch` **well ahead of the pool being exhausted** — confirmed by
  sampling `isTraitStored(poolIndex)` on the live renderer (`0x8c99b0c3...ede31A`): **`true` at
  poolIndex 9000/9999/10000** while only 477/10000 pool slots have been drawn so far
  (`poolRemaining()=9523`).
- Pulled every `OneOfOneSet` event from the live renderer (`eth_getLogs`, topic
  `0xb6be79e8...80e9fc`): **44 one-of-one poolIndex values are publicly logged**
  (e.g. 200, 202, 204, 357, 400, 401, 403, 404, 409, 500, 502, 503, 504, 714, 1071, 1429, 1786, ...,
  9643 — evenly spread across the full 1..10000 range).
- Cross-referenced against every `DealerRevealed` event on the NFT contract (477 draws so far):
  **only 3 of the 44 one-of-ones have been claimed** (201, 205, 599) — **41 remain unclaimed and
  exactly identified**, sitting in a pool that is still 95% undrawn.

Any technically capable minter can read those same public events today, mint a batch, and
deterministically snipe one or more of the 41 remaining one-of-ones — the game's rarest, most
valuable tier — defeating the collection's fairness guarantee for every other legitimate minter.
This is a live, ongoing exposure (mint is 5% sold, still open) with real secondary-market value at
stake (one-of-ones are the entire premium-rarity draw for this collection).

No PoC transaction was sent (white-hat: static/code analysis + read-only `eth_call`/`eth_getLogs`
against public mainnet state only; no mint/reveal txs submitted, no funds or live state touched).

## Threat assessment

`threat.py` on `DealersNFT`: **LIVE + ACTIVE + FUNDED** (65d old, 20 recent txns, last tx same-day)
-> HIGH urgency, disclose promptly. Mint is actively ongoing (502/10000, 9498 remaining at 0.01 ETH
each = up to ~95 ETH more in primary-sale exposure before the pool exhausts), on top of the
already-confirmed one-of-one rarity-sniping exposure.

## Disclosure

No public bounty program found for this project (not in `programs.py` open-scope list). The repo's
own `AUDIT.md` is soliciting third-party review and lists a real contact surface (GitHub org
`Dealers-sh`, `README.md` "Audit: scope, trust model, and build commands for reviewers"). Recommend
private disclosure to the team via the repo (issue/security contact) — the researcher discloses,
not the tool.
