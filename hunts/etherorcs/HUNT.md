# HUNT: EtherOrcs (EtherOrcsOfficial/etherOrcs-contracts)

Semi-dead on-chain RPG (2021-22), ETH mainnet + Polygon. Orcs farm ZUG, raid for
BoneShards, cross-chain via FxPortal. Pure skill-practice target (no live bounty):
read public code, triage, harden detectors. Clone in gitignored `hunts/_volume/etherorcs`.

**Pass goal:** first GameFi run of the upgraded pipeline; theme = weak-randomness
(the canonical on-chain-game bug class). Recon: `hunts/_volume/etherorcs-recon.md`
(50 .sol, 141 leads, 1 [!] high-signal cluster after dedupe).

## What recon surfaced + triage (verify-before-claiming)

| Lead | Detector | Verdict | Why |
|---|---|---|---|
| `Raids._rand`/`_getReward` (mainnet) | manual (weak-RNG, not in recon) | **refuted (LOW)** | predictable keccak RNG, but `noCheaters` (EOA-only) blocks the atomic predict-and-revert grind |
| `MainlandPortal.replayCall:77` | det_arbitrary `[!]` | **FP** | `require(msg.sender==admin)` on next line; detector missed inline admin-gate -> fix#24 |
| `mintRogues:70` (Allies) | det_mint `[!]` | **FP** | gate lives in delegated `mintRogue()` (openForMint||auth + burn 60 BS); thin-delegator-for-mint -> fix#25 |
| `Raids.unstake:117` | det_reentrancy `[!]` | **FP** | plain ERC721 `transfer` (no `onERC721Received` callback); reward zeroed in `_claim` before mint |
| `Portal.replayCall` / `forceProcess*` | dangerous-primitive | refuted | all admin-gated; `receiveMessage` validates FxPortal Merkle-Patricia proof + child-tunnel emitter |
| `delegatecall`/`tx.origin`/`extcodesize` (26+9) | dangerous / L2-footgun | by-design | proxy pattern + `noCheaters` anti-bot; not zkSync-deployed |

## The weak-RNG lead in detail (the teaching core)

`Raids._rand()` (Raids.sol:322):
```
keccak256(msg.sender, block.timestamp, block.basefee, block.timestamp, entropySauce)
entropySauce = keccak256(tx.origin, block.coinbase)   // _updateEntropy
```
Raid reward tier (reg/great/superb BoneShards) = `_randomize(_rand(),salt,orcId) % 10000`
in `_getReward`, fixed at `sendToRaid` time. Every input is on-chain-predictable -> the
textbook GameFi RNG bug: a contract predicts the outcome and reverts on a bad roll to
grind only superb rewards.

**Why it's REFUTED as a practical exploit:** `sendToRaid` is `noCheaters`:
```
require(auth[msg.sender] || (msg.sender == tx.origin && size == 0), "you're trying to cheat!");
```
`msg.sender == tx.origin` => EOA-only. A contract (even mid-constructor, since
msg.sender != tx.origin) cannot call -> the atomic predict-and-revert grind is blocked.
A vanilla EOA can't pre-set block.timestamp/basefee/coinbase, so it can't predict its
own tx outcome. Residual risk: a block proposer/builder controls timestamp+coinbase and
could bias outcomes -> known low-severity, by-design tradeoff for a 2022 game.

**Sibling-inconsistency (color, not a bug):** Polygon uses `GamingOraclePoly` =
Chainlink VRF; mainnet `Raids` kept the naive keccak. They knew the RNG was weak (added
VRF on L2) but left the mainnet `noCheaters` gate as the mitigation. The EOA-gate, not
VRF, is the mainnet defense.

## Outcome — no finding (expected for a much-forked 2022 game); system learned

2 detector precision-fix candidates + 1 reusable mitigation pattern + 1 detector to forge:
- **fix#24 `det_arbitrary`:** recognize an inline `require(msg.sender == admin/owner/...)`
  as the FIRST statement as a gate -> `replayCall` (admin-gated arbitrary call) no longer `[!]`.
- **fix#25 `det_mint`:** thin-delegator-for-mint -> a mint wrapper whose body only loops a
  gated sibling (`mintRogue()`) should downgrade (same family as fix#19 thin-facet-delegator).
- **Vault pattern:** `noCheaters` (`msg.sender==tx.origin && extcodesize==0`) is the canonical
  weak-RNG mitigation in on-chain games -> a future `det_weak_randomness` must check for an
  EOA-gate / VRF before flagging, else it FPs on every game that mitigated this way.
- **Backlog detector `det_weak_randomness`:** surface `keccak(block.*/now/blockhash/...)` used
  in a reward/outcome path; suppress when guarded by EOA-gate or Chainlink VRF.

**Lesson (reinforced):** the discipline is checking the *mitigation* (`noCheaters`) before
claiming the textbook bug. The RNG is genuinely weak; the EOA-gate blocks *atomic* grinding.

## CORRECTION (after the Wolf Game pass) — EOA-gate is a speed bump, not a wall

Initial verdict said `noCheaters` makes the RNG "not grindable". Wolf Game (same class,
same `tx.origin==msg.sender` gate) was ACTUALLY exploited via **simulation + selective
submission**: an EOA `eth_call`s the pending block, predicts the seed, and only broadcasts
when favorable. The EOA-gate stops a *contract* revert-grind but NOT this. So for Raids the
honest residual is: an EOA can selectively submit `sendToRaid` only on a predicted superb
roll. Severity stays LOW here for OTHER reasons (coinbase/basefee aren't perfectly
predictable for the landing block, unlike Wolf Game's exact `blockhash(n-1)`; reward is
small BoneShards locked 192h) -- NOT because `noCheaters` blocks it. Precision matters:
the right reason, not a convenient one.
