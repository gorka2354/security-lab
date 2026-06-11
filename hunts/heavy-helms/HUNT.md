# HUNT: Heavy Helms  (warlock-forge/heavy-helms-contracts)

- **Date:** 2026-06-11
- **Source:** GameFi GitHub sweep (egor's edge) -> fresh, deployed, under-reviewed on-chain auto-battler RPG.
- **Repo:** https://github.com/warlock-forge/heavy-helms-contracts  (Solidity, GPL-3.0, 10 stars, v0.8)
- **Deployed:** Base Mainnet (8453) + Base Sepolia (per `.claude/skills/hh-deploy/networks.md`), Chainlink VRF infra.
- **Audit:** NO professional audit (their `.claude/rules/hh-audit-context.md` is a DIY AI-assistant context file,
  not a firm report -> forkdrift false-flagged it AUDITED; fixed, see self-improvement).
- **Triage:** forkdrift = greenfield (no known base) -> hunt the WHOLE surface. `deepdive.py` seeded the
  workspace (`model/`) -> Tier-1 = PlayerTickets / Player / TournamentGame / GauntletGame; 44 leads, all routed
  to the bespoke-invariant form (game logic = state/auth, no financial formulas).

## FINDING (candidate, Medium) -- RNG outcome grinding defeats the commit-reveal

**Where:** `src/game/modes/TournamentGame.sol:1338` and `src/game/modes/GauntletGame.sol:1560`
(shared anti-pattern `_getEnhancedRandomness`).

**The bug.** The tournament/gauntlet seed is a commit-reveal over a committed future block, but the reveal
mixes in REVEAL-TRANSACTION-controlled entropy:
```solidity
function _getEnhancedRandomness(uint256 futureBlock) private view returns (uint256) {
    uint256 baseHash = uint256(blockhash(futureBlock));
    if (baseHash == 0) revert InvalidBlockhash();                 // 256-block staleness IS guarded
    // aderyn-fp-next-line(weak-randomness)                       // <- suppressed analyzer (masking flag)
    return uint256(keccak256(abi.encodePacked(
        baseHash, block.timestamp, block.number, gasleft(), tx.origin)));  // <- reveal-tx entropy
}
```
The point of committing to `futureBlock` is that the seed is FIXED by `blockhash(futureBlock)` (unknowable at
commit, fixed once mined). Mixing in `block.timestamp / block.number / gasleft() / tx.origin` of the reveal tx
**re-introduces grindability** -- 4 of the 5 entropy sources are controlled by whoever sends the reveal.

**Reachability.** The reveal is triggered by the PERMISSIONLESS `tryStartTournament()`
(`TournamentGame.sol:419`, `external whenGameEnabled nonReentrant`) / `tryStartGauntlet()`
(`GauntletGame.sol:527`). Reveal is allowed at ANY block in `[selectionBlock, selectionBlock+256]`
(`SelectionBlockNotReached` is a `>=` gate), so the caller also picks which block.

**Seed -> outcome.** `randomness` drives `_shuffleParticipants(participants, randomness)` (bracket) and
`_runTournamentRounds(..., randomness, ...)` where `fightSeedBase = keccak256(randomness, tournamentId)`
decides every fight. So grinding the seed grinds participant selection AND who wins.

**Attack (WHO / WHAT / HOW MUCH).**
1. WHO: any queued participant (no special role).
2. WHAT: when a tournament/gauntlet is at its reveal phase, the attacker calls `tryStartTournament()`
   THEMSELVES (so `tx.origin` = attacker). They `eth_call`-simulate the result off-chain (free); if the seed
   yields a favorable outcome (their player selected / wins the bracket) they submit; otherwise they wait a
   block (new `block.timestamp/number`) or change gas (`gasleft()`) and re-simulate -- unlimited cheap re-rolls,
   pay gas only for the winning call.
3. HOW MUCH: biases the winner/runner-up/3rd-4th reward distribution (NFT-ticket rewards set via
   `setWinnerRewards` etc.) toward the grinder, and biases Phase-2 selection so a low-priority player gets in.
   Repeatable every tournament -> a steady, unfair edge in a competitive prize game.

**Why it's not "acknowledged".** Their audit-context says blockhash randomness is "intentional commit-reveal,
acceptable". They acknowledge *using* blockhash; they do NOT acknowledge that mixing reveal-tx entropy DEFEATS
the commit-reveal they rely on. Their stated mitigation is broken by their own implementation. (Gate C does not
kill it.)

**Severity:** Medium. Permissionless + repeatable + defeats the core fairness guarantee, but bounded by needing
to be a participant, racing other callers, and the value of the NFT-ticket rewards. Medium-High if rewards are
valuable or selection-grinding lets one address monopolize tournaments.

**Fix.** Do not mix reveal-tx-controlled entropy into a commit-reveal seed. Use PURELY `blockhash(futureBlock)`
(remove `block.timestamp/number/gasleft/tx.origin`), or -- since they already run Chainlink VRF infra -- seed
from VRF. Pure future-blockhash still carries the L2-sequencer trust + the 256-block liveness window, but it is
not participant-grindable.

**Status:** GPL repo, NO formal bounty program visible -> responsible disclosure direct to warlock-forge; egor
confirms the deployed mainnet version matches HEAD + sends. White-hat: read-only, no funds touched.

## CURRENT CRITICALITY (on-chain, Base mainnet, checked 2026-06-11) -- LOW / DORMANT
The vulnerable code is LIVE but the LIVE-FIRST test re-calibrates the impact HARD:
- **The vulnerable path has NEVER executed.** All 3 deployed GauntletGame brackets read `nextGauntletId == 0`
  (L1-4 `0x005744..`, L5-9 `0x4D31cA..`, L10 `0x2Ff94A..`) -> not a single gauntlet has ever completed on
  mainnet. `isGameEnabled == true`, but only **6 players queued** total (one bracket), below the start
  threshold. So nothing has been (or can yet be) grinded.
- **No funds at stake.** `queueForGauntlet` is FREE (not payable, no entry fee, no prize pool). The "prize" is
  utility PlayerTickets NFTs (ATTRIBUTE_SWAP / NAME_CHANGE / PLAYER_SLOT / DUEL_TICKET ... -- game consumables),
  not money. The bug cannot STEAL anything; at most it lets a player win utility tickets unfairly + bias bracket
  / season standings. Grinding is rate-limited (`dailyGauntletLimit = 10`/player).
- **TournamentGame is NOT deployed on mainnet v2** (absent from the README deploy table) -> that half is moot.
- The traction that exists ("54k fights, 450 players") was the EARLIER Heavy Helms Origins on Shape Network
  (GameEngine v28, different code) -- not this Base-v2 deployment.

**Verdict on "can it damage anything right now?": essentially NO.** It is a REAL latent fairness flaw, but
current real-world impact is negligible -- deployed + enabled != active + valuable. It only starts to matter
IF/WHEN gauntlets run at real volume with rewards that carry value (or season standings get tied to money /
airdrops). Honest severity: abstract Medium (integrity); **current live impact Low.**

**Disclosure framing:** low-priority, pre-traction heads-up. The team is at the BEST moment to fix (no live
exploitation possible yet, trivial fix: drop the reveal-tx entropy from the seed or use their existing Chainlink
VRF). Not urgent, not a fund-loss bug. egor decides whether it's worth the contact.

## Verify trail (kill-gates passed)
- grindable: yes (4/5 entropy sources caller-controlled; keccak avalanche -> any change = new seed).
- benefit: yes (seed drives selection + bracket + per-fight winners; attacker is a participant).
- permissionless: yes (`tryStartTournament`/`tryStartGauntlet` external, only `whenGameEnabled`).
- intentional: no (their commit-reveal mitigation is the thing being defeated).
- both modes: TournamentGame + GauntletGame share `_getEnhancedRandomness`.

## Scratch (FPs cleared)
- `TournamentGame.sol:470` recon weak-randomness lead = `(block.timestamp/1 hours)%24` hour-of-day SCHEDULING,
  explicitly commented non-security. FP (a det_weak_random precision note: modulo for time-bucketing != RNG).

## Self-improvement (the loop)
- forkdrift FALSE-AUDITED: a `.claude/rules/*audit*.md` AI-context file was counted as an audit report ->
  fixed `detect_audit_evidence` to exclude `.claude/` paths (same class as the Ledgity slither-report guard).
