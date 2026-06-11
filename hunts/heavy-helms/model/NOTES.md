# Deep dive: heavy-helms

Target src: `hunts/_volume/heavy-helms/src`  |  recon leads: 44 (<= [.] prio)  |  fill the worklog as you go.

> Two-speed reminder: recon/hypothesize AIMED you here; the FIND comes from a tool built for THIS
> protocol. Pick a form below, build the smallest thing that can be RED, make it red, then fix-diff.

## Tier-1 files (most high-signal leads -> read these first)
- `nft/PlayerTickets.sol`  (10 high-signal leads)
- `fighters/Player.sol`  (6 high-signal leads)
- `game/modes/TournamentGame.sol`  (4 high-signal leads)
- `game/modes/GauntletGame.sol`  (3 high-signal leads)
- `fighters/registries/skins/PlayerSkinRegistry.sol`  (2 high-signal leads)

## Route A -- DIFFERENTIAL MODEL  (math/formula leads; the Ledgity method)
Reimplement the suspect formula cleanly (Python `model.py` OR Solidity `Differential.t.sol`) and
diff it against the contract over fuzzed inputs. Catches rounding / precision / off-by-one / wrong
operator that generic invariants miss. Best when the bug is "the math is subtly wrong".
  (none surfaced by recon -- read the core by hand; recon AIMS, it doesn't FIND)

## Route B -- BESPOKE INVARIANT  (state/auth leads; chimera fuzz)
A property meaningful only for THIS protocol, dropped into a chimera harness and fuzzed under
Foundry+Echidna+Medusa. Best when the bug is "a reachable state breaks an accounting/auth rule".
Generate the harness:
    python toolkit/scaffold.py hunts/_volume/heavy-helms/src/<Core>.sol <Core> --engine chimera --out hunts/_volume/heavy-helms/recon
Then write the protocol-specific `property_*` (e.g. `sum(local) == global` across EVERY path).
- [!] `fighters/Player.sol:717` -- UNGATED, but siblings here use [onlyOwner, onlyPlayerOwner] -> inconsistent?  _( ACCESS-CONTROL sibling inconsistency (regression technique) )_
- [!] `fighters/Player.sol:717` -- external/public + privileged name, NO only* / inline auth  _( ACCESS CONTROL leads (privileged fn, no modifier) )_
- [!] `fighters/Player.sol:987` -- UNGATED, but siblings here use [onlyOwner, onlyPlayerOwner] -> inconsistent?  _( ACCESS-CONTROL sibling inconsistency (regression technique) )_
- [!] `fighters/Player.sol:987` -- external/public + privileged name, NO only* / inline auth  _( ACCESS CONTROL leads (privileged fn, no modifier) )_
- [!] `fighters/Player.sol:1018` -- UNGATED, but siblings here use [onlyOwner, onlyPlayerOwner] -> inconsistent?  _( ACCESS-CONTROL sibling inconsistency (regression technique) )_
- [!] `fighters/Player.sol:1018` -- external/public + privileged name, NO only* / inline auth  _( ACCESS CONTROL leads (privileged fn, no modifier) )_
- [!] `fighters/registries/skins/PlayerSkinRegistry.sol:143` -- strict == / != on a balance (this.balance / balanceOf) -> force-feed (selfdestruct / direct transfer) breaks the exact match (DoS / bad accounting); use >= or <= and deltas  _( STRICT balance equality (force-feed DoS) )_
- [!] `fighters/registries/skins/PlayerSkinRegistry.sol:185` -- external call THEN state write, no nonReentrant -> reentrancy (CEI)?  _( REENTRANCY (external call then state write) )_
- [!] `game/engine/GameEngine.sol:638` -- initialize without initializer/onlyX -> front-run / re-init?  _( DANGEROUS primitives )_
- [!] `game/modes/BaseGame.sol:78` -- external/public + privileged name, NO only* / inline auth  _( ACCESS CONTROL leads (privileged fn, no modifier) )_
- [!] `game/modes/GauntletGame.sol:954` -- UNGATED, but siblings here use [onlyOwner, onlyPlayerOwner] -> inconsistent?  _( ACCESS-CONTROL sibling inconsistency (regression technique) )_
- [!] `game/modes/GauntletGame.sol:954` -- external/public + privileged name, NO only* / inline auth  _( ACCESS CONTROL leads (privileged fn, no modifier) )_
- [!] `game/modes/GauntletGame.sol:1565` -- predictable on-chain RNG: keccak256 over block entropy (timestamp/blockhash/difficulty/coinbase) drives an outcome -> grindable (predict-and-revert; use commit-reveal or Chainlink VRF)  _( WEAK randomness (predictable on-chain RNG in an outcome path) )_
- [!] `game/modes/PracticeGame.sol:302` -- predictable on-chain RNG: keccak256 over block entropy (timestamp/blockhash/difficulty/coinbase) drives an outcome -> grindable (predict-and-revert; use commit-reveal or Chainlink VRF)  _( WEAK randomness (predictable on-chain RNG in an outcome path) )_
- [!] `game/modes/TournamentGame.sol:470` -- DIRECT modulo of block entropy (no keccak) drives an outcome -> predictable RNG; grindable (predict-and-revert / revert-to-reroll). Use commit-reveal or Chainlink VRF  _( WEAK randomness (predictable on-chain RNG in an outcome path) )_
- [!] `game/modes/TournamentGame.sol:792` -- UNGATED, but siblings here use [onlyOwner] -> inconsistent?  _( ACCESS-CONTROL sibling inconsistency (regression technique) )_
- [!] `game/modes/TournamentGame.sol:792` -- external/public + privileged name, NO only* / inline auth  _( ACCESS CONTROL leads (privileged fn, no modifier) )_
- [!] `game/modes/TournamentGame.sol:1343` -- predictable on-chain RNG: keccak256 over block entropy (timestamp/blockhash/difficulty/coinbase) drives an outcome -> grindable (predict-and-revert; use commit-reveal or Chainlink VRF)  _( WEAK randomness (predictable on-chain RNG in an outcome path) )_
  ... and 26 more

## Bespoke-invariant starters (curate for this target; full menu: `hypothesize.py hunts/_volume/heavy-helms/src`)
- conservation: SUM(per-user accounting) == the global aggregate, at ALL times, across EVERY path
  (mint/burn/redeem/liquidate/redistribute) -- the #1 fork-CDP / vault break.
- round-trip: do(x) then undo() never leaves the caller richer (rounding must favor the protocol).
- accrual-before-change: any setRate/setFee/addPrincipal accrues/settles the OLD state FIRST.
- price-source parity: liquidation and settlement read the SAME price; no cheaper bypass path.
- monotonic-where-promised: an index/share-price only moves in the direction the design promises.

## Route C -- STATE-MACHINE MODEL  (when the bug is an illegal transition)
Encode the intended states + legal transitions; fuzz the real contract; flag any reachable state
the model calls impossible. Heavier -- reach for it when A/B don't fit (e.g. multi-phase auctions,
queue/epoch lifecycles). Sketch the states here before coding.

## Worklog
- [ ] picked form: ___  (file/formula: ___)
- [ ] smallest RED check written  -> reproduces? ___
- [ ] verified vs VERIFY kill-gates (FP? known? severity honest?)
- [ ] -> HUNT.md verdict + ledger
