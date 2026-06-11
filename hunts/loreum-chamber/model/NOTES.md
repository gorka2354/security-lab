# Deep dive: loreum-chamber

Target src: `hunts/_volume/loreum-chamber/contracts/src`  |  recon leads: 22 (<= [.] prio)  |  fill the worklog as you go.

> Two-speed reminder: recon/hypothesize AIMED you here; the FIND comes from a tool built for THIS
> protocol. Pick a form below, build the smallest thing that can be RED, make it red, then fix-diff.

## Tier-1 files (most high-signal leads -> read these first)
- `Chamber.sol`  (4 high-signal leads)

## Route A -- DIFFERENTIAL MODEL  (math/formula leads; the Ledgity method)
Reimplement the suspect formula cleanly (Python `model.py` OR Solidity `Differential.t.sol`) and
diff it against the contract over fuzzed inputs. Catches rounding / precision / off-by-one / wrong
operator that generic invariants miss. Best when the bug is "the math is subtly wrong".
  (none surfaced by recon -- read the core by hand; recon AIMS, it doesn't FIND)

## Route B -- BESPOKE INVARIANT  (state/auth leads; chimera fuzz)
A property meaningful only for THIS protocol, dropped into a chimera harness and fuzzed under
Foundry+Echidna+Medusa. Best when the bug is "a reachable state breaks an accounting/auth rule".
Generate the harness:
    python toolkit/scaffold.py hunts/_volume/loreum-chamber/contracts/src/<Core>.sol <Core> --engine chimera --out hunts/_volume/loreum-chamber/contracts/recon
Then write the protocol-specific `property_*` (e.g. `sum(local) == global` across EVERY path).
- [!] `Chamber.sol:321` -- UNGATED, but siblings here use [initializer] -> inconsistent?  _( ACCESS-CONTROL sibling inconsistency (regression technique) )_
- [!] `Chamber.sol:321` -- external/public + privileged name, NO only* / inline auth  _( ACCESS CONTROL leads (privileged fn, no modifier) )_
- [!] `Chamber.sol:425` -- UNGATED, but siblings here use [initializer] -> inconsistent?  _( ACCESS-CONTROL sibling inconsistency (regression technique) )_
- [!] `Chamber.sol:425` -- external/public + privileged name, NO only* / inline auth  _( ACCESS CONTROL leads (privileged fn, no modifier) )_
- [.] `Board.sol:277` -- unchecked{} opts OUT of 0.8 overflow checks -> verify the arithmetic inside can't wrap  _( OVERFLOW / underflow (pre-0.8 pragma or opt-out math block) )_
- [.] `Board.sol:305` -- unchecked{} opts OUT of 0.8 overflow checks -> verify the arithmetic inside can't wrap  _( OVERFLOW / underflow (pre-0.8 pragma or opt-out math block) )_
- [.] `Board.sol:361` -- unchecked{} opts OUT of 0.8 overflow checks -> verify the arithmetic inside can't wrap  _( OVERFLOW / underflow (pre-0.8 pragma or opt-out math block) )_
- [.] `Board.sol:451` -- unchecked{} opts OUT of 0.8 overflow checks -> verify the arithmetic inside can't wrap  _( OVERFLOW / underflow (pre-0.8 pragma or opt-out math block) )_
- [.] `Board.sol:482` -- unchecked{} opts OUT of 0.8 overflow checks -> verify the arithmetic inside can't wrap  _( OVERFLOW / underflow (pre-0.8 pragma or opt-out math block) )_
- [.] `Board.sol:493` -- unchecked{} opts OUT of 0.8 overflow checks -> verify the arithmetic inside can't wrap  _( OVERFLOW / underflow (pre-0.8 pragma or opt-out math block) )_
- [.] `Chamber.sol:231` -- unchecked{} opts OUT of 0.8 overflow checks -> verify the arithmetic inside can't wrap  _( OVERFLOW / underflow (pre-0.8 pragma or opt-out math block) )_
- [.] `Chamber.sol:266` -- unchecked{} opts OUT of 0.8 overflow checks -> verify the arithmetic inside can't wrap  _( OVERFLOW / underflow (pre-0.8 pragma or opt-out math block) )_
- [.] `Chamber.sol:279` -- unchecked{} opts OUT of 0.8 overflow checks -> verify the arithmetic inside can't wrap  _( OVERFLOW / underflow (pre-0.8 pragma or opt-out math block) )_
- [.] `Chamber.sol:475` -- unchecked{} opts OUT of 0.8 overflow checks -> verify the arithmetic inside can't wrap  _( OVERFLOW / underflow (pre-0.8 pragma or opt-out math block) )_
- [.] `Chamber.sol:497` -- unchecked{} opts OUT of 0.8 overflow checks -> verify the arithmetic inside can't wrap  _( OVERFLOW / underflow (pre-0.8 pragma or opt-out math block) )_
- [.] `Chamber.sol:544` -- unchecked{} opts OUT of 0.8 overflow checks -> verify the arithmetic inside can't wrap  _( OVERFLOW / underflow (pre-0.8 pragma or opt-out math block) )_
- [.] `Chamber.sol:582` -- unchecked{} opts OUT of 0.8 overflow checks -> verify the arithmetic inside can't wrap  _( OVERFLOW / underflow (pre-0.8 pragma or opt-out math block) )_
- [.] `Chamber.sol:624` -- address.code.length as an EOA/contract check -> unreliable on AA chains (zkSync)  _( L2 / AA footguns (zkSync: extcodesize EOA-check, isContract sig branch) )_
  ... and 4 more

## Bespoke-invariant starters (curate for this target; full menu: `hypothesize.py hunts/_volume/loreum-chamber/contracts/src`)
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
