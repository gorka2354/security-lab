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

### Exploitability gate (honest)
Conditional on the **backend signer ever signing a multi-item (len>=2) export** — natural for an inventory game,
but to be CONFIRMED by decoding a real `exportItemsFromGame` tx from the live signer. A len-1 export can only
re-split to an empty array (no mint) → inert. Also: the signed digest omits `chainid`/`address(this)` (a second,
Medium cross-deployment-replay lead). Severity: **High if the signer signs len>=2 batches** (item over-mint on a live game).

## Secondary (on-chain CONFIRMED, Medium) — RedeemSystem unbound-dealId reward inflation
`RedeemSystem` `0xE855...`: the backend sig binds `(player,itemId,amount,nonce)` but NOT `dealId`. On-chain deals 2
and 3 are the same `itemId=717` but pay `0.80` vs `0.95` USDC.e — a player picks the richest deal for their signed
item (+18.75% on a live ~15k USDC pool). Bounded by nonce-one-shot + caps. Same root cause: under-bound signature.

## Engine feedback (debt)
recon's `det_signature` MISSED both: it keys on raw `ecrecover` and did not flag `SignatureChecker.isValidSignatureNow`,
nor the **`keccak256(abi.encodePacked(...))` with >=2 adjacent dynamic arrays** hash-collision pattern. Both are
clean T0/T1 extensions worth harvesting (unlike split-brain, this IS regex-catchable).

## Verdict / disposition
A real, PoC-proven, code-level item-over-mint on a LIVE, ACTIVE, a16z/Proof-of-Play-backed game — the strongest
GameFi find of the session. Disposition: confirm the len>=2 signer behavior on-chain, then (Gigaverse/Proof of Play
likely run a bug-bounty — CHECK scope) draft a responsible disclosure with the PoC. egor sends. White-hat, read-only.
