# Dealers.sh — NFT trait reveal is deterministic and caller-orderable → the rarest tier is grindable at zero cost (High)

**Severity:** High (permissionless, no funds-at-risk directly but breaks the mint's core fairness guarantee for
every honest minter; the rarest "one-of-one" tier is worth a large multiple of mint price, and ~95% of the pool is
still undrawn with 41/44 one-of-ones unclaimed). Confirmed exploitable on the **live** contract; PoC below.

**Status:** **Live + active + funded** on Abstract Chain (chain 2741, zkSync EraVM). Mint actively ongoing
(502/10000 sold at 0.01 ETH → up to ~95 ETH more primary-sale exposure). Repo pushed to `main` 2 days before this
review; `AUDIT.md` written for an *upcoming* third-party audit → **pre-audit**, ideal window for a private
disclosure. Self-verified from source; PoC (`poc_sim.py`) reproduces the ordering attack with a real keccak256.

**Contract:** `DealersNFT` — `0x610CcEe1AE4aFF961d043faB379491C2997383F7` (Abstract, chain 2741).
Renderer `DealerRendererSVG` `0x8c99b0c302E774CF50ba6B4763dcB15d84ede31A` (holds the public `oneOfOnes` mapping).
**Repo:** `github.com/Dealers-sh/dealers-contracts` @ current `main`. `src/nft/DealersNFT.sol`.

**Class:** predictable/orderable pseudo-randomness — a public, mutable draw pool whose seed excludes the caller and
whose consumption order is caller-controlled, so the outcome is fully pre-computable and selectable off-chain.

**Disclosure intent:** private, goodwill, pre-audit. White-hat, read-only: analysis is source-read + exact off-chain
simulation of the deployed integer math + read-only on-chain queries (no transactions sent). **The researcher discloses.**

---

## The bug

`DealersNFT` reveals each token's traits by drawing a slot from a shared lazy Fisher-Yates pool. The draw seed
**deliberately excludes `msg.sender`** (`DealersNFT.sol:318-320`, the contract's own comment says so), and
`resolveMany` processes the caller's `tokenId[]` **in the caller's order** over the *mutable, public* pool:

```solidity
// DealersNFT.sol:302-314  — reveals the caller's array strictly in the given order
function resolveMany(uint256[] calldata tokenIds) external {
    for (uint256 i; i < tokenIds.length;) {
        uint256 tokenId = tokenIds[i];
        if (_exists(tokenId) && tokenToPool[tokenId] == 0) {
            uint64 rb = revealBlockOf[tokenId];
            if (block.number > rb) _revealOrReanchor(tokenId, rb);   // mutates the shared pool, in order
        }
        unchecked { ++i; }
    }
}
// DealersNFT.sol:320-335 — seed has NO msg.sender; pool draw is a pure fn of (blockhash, tokenId, pool state)
uint32 poolIndex = _drawPool(uint256(keccak256(abi.encodePacked(bh, tokenId))));
```

Every input is public **before** the attacker must act:
* `bh = blockhash(revealBlock)` becomes public 2 blocks after mint (`REVEAL_DELAY = 2`);
* `tokenId`s are the attacker's own;
* the pool state (`poolRemaining` public, `poolCache` plain storage / replayable from `DealerRevealed` events);
* the valuable slots are **pre-known**: `DealerRendererSVG.oneOfOnes(poolIndex)` is populated by the team long
  before those slots are drawn (verified live: `isTraitStored` true at poolIndex 9000/9999/10000 while only
  ~477/10000 slots were drawn).

So a minter who buys a batch (up to `MAX_PER_WALLET = 10`, all sharing one `revealBlock`) can, **off-chain and at
zero cost**, simulate `_drawPool` for every ordering of their own `tokenId` array and submit — via `resolveMany` —
the exact order that lands one of their tokens on a known-valuable slot. A losing simulation is simply never
submitted; the only cost is normal mint price + gas, which the attacker would pay anyway.

## Live confirmation (read-only, no txs sent)

Pulled all 44 `OneOfOneSet` events from the live renderer and all 477 `DealerRevealed` events from the live NFT:
**only 3 of 44 one-of-ones are claimed (poolIndex 201, 205, 599); 41 remain unclaimed and exactly identified**, in a
pool that is ~95% undrawn (`poolRemaining()` ≈ 9523), with the mint still open. The fairness of the rarest tier is
grindable *right now*, for every honest minter.

## PoC

`poc_sim.py` (this folder) ports `_drawPool` exactly and uses a **real keccak256** (`eth_hash`/`pycryptodome`):

```
order A (as-is)   : {5001: 5, 5002: 16, 5003: 17, 5004: 6, 5005: 15}
order B (reversed): {5005: 3, 5004: 8, 5003: 17, 5002: 5, 5001: 13}   <- same tokens, DIFFERENT slots
EXPLOIT: submit resolveMany([5001, 5002, 5004, 5005, 5003])
  -> lands token 5005 on RARE slot 20 (a known one-of-one) -- risk-free, chosen before committing
```

Run: `python3 dealers-poc/poc_sim.py` (no chain access needed; deterministic).

## Fix

Bind the reveal to entropy the caller cannot both know and reorder at reveal time:
* **Include a per-reveal secret in the seed** — at minimum `msg.sender` AND a value the minter committed *at mint
  time* (a commit-reveal per token), so the outcome is not pre-computable from public data; and/or
* **Remove caller-controlled ordering** — fix the resolution order (e.g. ascending `tokenId`, or draw by
  `tokenId` rather than array position) so `resolveMany` cannot be used to steer which slot a token lands on; and/or
* use a real VRF (e.g. the pattern the project already applies elsewhere) for the pool draw. Any one of these
  breaks the "simulate-all-orderings, submit-the-winner" strategy.

Note the seed excluding `msg.sender` is only safe when neither the ordering nor the slot values are attacker-known
in advance — here both are, which is what makes it exploitable.

## Honest negatives found in the same review (the rest of the RNG surface is sound)

* `DealersRandomness` commit-reveal (blockhash-based, public `reveal()`) is correctly defended **everywhere it's
  consumed** by charging the stake/attempt cost **at commit time**, so a post-reveal selective-abort has no
  positive EV (verified in `DealersHeists.resolveStage`, `DealersPVP.resolveAttack`, `DealersActions.commit*`).
* `DealersBankHeist` `reservedETH` liability bookkeeping is internally consistent (no under-reservation / double-spend).
* Cross-module reentrancy at every ETH-transfer site reachable by a malicious NFT-owner contract — CEI holds +
  per-contract `nonReentrant`; no exploitable race.

## Threat assessment (post-finding)

**LIVE / ACTIVE / HIGH urgency.** `threat.py`: DealersNFT first-seen ~65d, last tx same-day; `DealersHeists`
nonce ~76.8k (heavy usage), last tx ~1.5h before review. Mint 5% sold, ~95 ETH primary-sale + rarest-tier value
still on the table. **Pre-audit** → disclose privately to the Dealers.sh team now, before the audit and before more
one-of-ones are drawn. (Abstract = zkSync EraVM, so no live-EVM fork-fuzz — moot: the exploit is a deterministic
off-chain simulation, already shown above.)
