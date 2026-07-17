# HUNT: Wolf Game / Woolf (swooshcrypto/Wolf_Game mirror)

Famous 2021 NFT staking game (sheep/wolves, $WOOL, 10% steal-on-mint). Semi-dead.
Skill-practice target with DOCUMENTED exploits (B. Mueller "Herdsman's Report",
Alcibiades) = built-in feedback loop. Clone in gitignored `hunts/_volume/wolfgame`
(5 .sol, 778 lines). Recon: `hunts/_volume/wolfgame-recon.md` (9 leads, 2 [!]).

## Triage

| Lead | Detector | Verdict | Why |
|---|---|---|---|
| `Woolf.random()` mint RNG | manual (weak-RNG, not in recon) | **known (real class)** | `keccak(tx.origin, blockhash(n-1), block.timestamp, seed)`, same-tx reveal of sheep/wolf + 10% steal -> predictable; documented & later patched (VRF) |
| `Barn.rescue:222` | det_reentrancy `[!]` | **FP / low** | CEI violation (safeTransferFrom before delete) but re-entry reverts: token already left the barn so inner `safeTransferFrom(this,..)` fails; `rescueEnabled` is emergency-only |
| `Barn:84` unchecked ERC20 | det_unchecked `[!]` | **FP** | `WOOL` is their own token (returns true); hardening note only (SafeERC20) |
| supply-integrity (3), dangerous (3) | det_mint / primitives | by-design | WOOL mint gated to controller; standard ERC721 |

## The weak-RNG core (same class as EtherOrcs)

`Woolf.mint` gates with `require(tx.origin == _msgSender(), "Only EOA")` then derives the
whole outcome (species, traits, whether a staked wolf steals the mint) from `random()`:
```
keccak256(tx.origin, blockhash(block.number - 1), block.timestamp, seed)
```
All inputs are known/predictable, and the result is revealed in the SAME tx (no
commit-reveal / VRF). `blockhash(n-1)` is EXACT once block n-1 exists.

**Cross-target lesson (the valuable bit):** Wolf Game was ACTUALLY exploited despite the
`tx.origin == msg.sender` EOA-gate. The gate blocks an atomic contract-based
predict-and-revert grind, but NOT **simulation + selective submission**: an EOA runs
`eth_call` against the pending block, predicts the seed, and only broadcasts the real tx
when the outcome is favorable (mint a wolf / avoid theft). => An EOA-gate is a SPEED BUMP,
not a wall, for same-block-reveal RNG. This corrects the EtherOrcs verdict (see that HUNT).

## Outcome

No fresh finding (the RNG flaw is public & patched). But two GameFi targets in a row
confirm the system's biggest GameFi blind spot: **no weak-randomness detector.** recon's 17
detectors caught only the (mitigated) reentrancy + unchecked-transfer here and missed the
actual, historically-exploited bug entirely. Strongest possible case to forge
`det_weak_randomness` (the GameFi/gambling focus + closes a real coverage gap).
