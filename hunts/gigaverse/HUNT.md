# HUNT — Gigaverse (active on-chain RPG, Abstract chain 2741, Proof-of-Play GameRegistry arch)

Sourced from the Abstract Discover ecosystem (egor's GameFi edge). 8 gameplay systems triaged via an 8-agent
fan-out (`hunts/_fanout/2026-06-15-gigaverse-systems.md`); RandomSystem/PetRacing/ItemMarket/Account/Vendor = PARK
(RNG is a solid Proof-of-Play off-chain VRF, economics conserved). Two live signature-binding leads survived; this
deep-dive proves the sharpest.

## 🎯 FINDING (PoC-proven) — ImportExportSystem `abi.encodePacked` signature collision → item over-mint

**Contract:** `ImportExportSystem` `0xE1De5aD14cE61ab97C5eD1dd9DDe45F303deee9c` (Abstract, live: 133KB, 20+ recent txns).
**Class:** abi.encodePacked hash-collision on adjacent dynamic arrays (a known T0/T1 class) on a permissionless, payable entrypoint.

### Mechanism
`exportItemsFromGame(player, itemIds[], itemAmounts[], nonce, sig)` mints on-chain items per an OFF-CHAIN backend
signature. The signed digest (`ImportExportSystem.sol:100`):
```solidity
keccak256(abi.encodePacked(player, itemIds, itemAmounts, nonce))
```
`itemIds` and `itemAmounts` are **two adjacent unbounded `uint256[]`** packed with NO length prefix / separator.
The middle blob `ids‖amts` can be **re-partitioned at a different boundary** into `(ids', amts')` that yields the
**SAME digest → the SAME valid signature**. And `_exportItemsFromGame` does **NOT** enforce
`itemIds.length == itemAmounts.length` — it loops `for i < itemIds.length { gameItems.mint(player, itemIds[i], itemAmounts[i]); }`
(only needs `amts.length >= ids.length`). So a player holding a backend signature for one split mints a different,
attacker-chosen split.

### Impact (the math)
Backend signs an intended export `itemIds=[100, 717], itemAmounts=[5, 3]` (give 5 of item #100 and 3 of #717).
The attacker submits the re-split `itemIds=[100], itemAmounts=[717, 5, 3]` with the **same signature** → the loop
runs once → `mint(player, 100, 717)` → **717 units of item #100** (vs the intended 5 — a 143x over-mint; in general
the SECOND item's id becomes the amount of the FIRST item). The no-on-chain-`minted<=burned` design (the matching
burn is off-chain) means this is a direct item-inflation primitive.

### Proof (`gigaverse-poc/`)
Faithful verbatim reimplementation of the digest + the no-equal-length mint loop. `forge test` 2/2:
- `test_EncodePackedCollision_OverMint`: the two splits hash to the SAME digest (`assertEq` passes); the backend
  signs only the legit split; the attacker's re-split verifies with that signature and mints **717 of item #100**, **0 of #717**.
- `test_LegitSplit_MintsIntended` (control): the legit split mints exactly 5 of #100, 3 of #717.

### Exploitability gate — CONFIRMED on-chain + HONEST bounded severity
Decoded 3 real `exportItemsFromGame` (selector `0x59b43fc6`) txs from the live signer (Etherscan-v2 txlist + raw
`eth_getTransactionByHash`):
- tx `0x842f79…`: **itemIds=[4,21,76,83,7], itemAmounts=[72,19,18,3,33]** — a real **len-5 batch** ✓
- tx `0xe36b48…`: `[616],[700]` · tx `0x686fdf…`: `[615],[2000]` (len-1)
So the **gate is CONFIRMED**: the signer signs len>=2 batches → the collision is exploitable on the live contract.

**Honest impact bound:** the attacker can only RE-SHUFFLE the SIGNED words (cannot conjure a new large value) — they
re-partition to concentrate the batch's largest word as the amount of a chosen item. For the real len-5 batch, the
attack `ids=[4,21,76,83], amts=[7,72,19,18,3,33]` mints **72 of item #21 (vs the intended 19, +279%)** and drops #7.
Max amount on any one item == the largest word in that signed batch (here 83; single-item exports showed 700 / 2000,
so a multi-item batch pairing a large amount with a rare item could mint up to that of the rare item). So this is a
**confirmed Medium** — item mis-assignment / bounded over-mint of a live, tradeable item economy (Gigaverse Items /
ROMS / Giglings have OpenSea markets) — NOT a catastrophic unbounded mint (the illustrative 717x needs a large word
in the batch). Second lead: the digest also omits `chainid`/`address(this)` → cross-deployment replay (Medium).

## Secondary (on-chain CONFIRMED, Medium) — RedeemSystem unbound-dealId reward inflation
`RedeemSystem` `0xE855...`: the backend sig binds `(player,itemId,amount,nonce)` but NOT `dealId`. On-chain deals 2
and 3 are the same `itemId=717` but pay `0.80` vs `0.95` USDC.e — a player picks the richest deal for their signed
item (+18.75% on a live ~15k USDC pool). Bounded by nonce-one-shot + caps. Same root cause: under-bound signature.

## Engine feedback (debt)
recon's `det_signature` MISSED both: it keys on raw `ecrecover` and did not flag `SignatureChecker.isValidSignatureNow`,
nor the **`keccak256(abi.encodePacked(...))` with >=2 adjacent dynamic arrays** hash-collision pattern. Both are
clean T0/T1 extensions worth harvesting (unlike split-brain, this IS regex-catchable).

## Verdict / disposition (steps 1-2 done)
A real, PoC-proven (3/3), **gate-CONFIRMED** (live len-5 export batches signed) item mis-assignment / bounded
over-mint on a LIVE, ACTIVE, a16z/Proof-of-Play-backed game — the strongest GameFi find of the session. Honest
severity: **Medium** (impact bounded by the signed batch's word magnitudes; tradeable item economy). **Scope: NO
public bug-bounty** (no Immunefi listing, no SECURITY.md on proofofplay/gigaverse-games/GLHFers, no disclosure page
in docs) → no reward; the white-hat move is a **goodwill responsible disclosure** to the team (egor sends via their
Discord/contact) with the PoC + the honest bounded-severity framing. Recommended fix: bind the signature to a
hashed-struct (EIP-712 with explicit field types incl. array lengths) or `abi.encode` (length-prefixed) instead of
`abi.encodePacked`, and add `require(itemIds.length == itemAmounts.length)` + chainid/address(this) in the digest.

## Engine win (step 3) — DONE
Sharpened `det_encodepacked`: it used to flag ALL `keccak256(abi.encodePacked(2+ args))` at low `[.]` ("verify the
types"), so this real collision was buried as generic noise. Now it parses the encodePacked args, looks up each in
the enclosing function's params, and **bumps to `[!]` HIGH when >=2 ADJACENT args are dynamic PARAMS (array/bytes/
string)** — the actual collision primitive — while all-fixed (permit-shape) stays `[.]`. A BARE-identifier gate
(`arr[i]`/`a.b`/`f(x)`/literals are not the whole array) kills the Merkle-element FP (`encodePacked(leaves[0],
leaves[1])`). **TP-grounded on this exact live Gigaverse code** (`ImportExportSystem.sol:100` -> `[!]`); **0 FP** on
7 signature-heavy clones (stakewise/notional/reserve/euler/dreusd/cap/magicswap). golden 351->353. The detector
would now surface this exact bug class at high signal on the next target.
