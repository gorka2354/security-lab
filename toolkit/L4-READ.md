# L4-READ — the structured deep read (what I run on each flagged function)

recon (21 regex detectors) + hypothesize (shared-state seeds) tell me WHERE to look. This is HOW I read it —
a repeatable protocol so the L4 pass is thorough, not vibes. Run it on each Tier-1 function / flagged lead;
findings that survive go to `VERIFY.md` (kill-gates). (Multi-mindset × lens + Feynman + missing-sweep structure
borrowed from Krait — ZealynxSecurity/krait, MIT.)

## STEP 1 — 4 MINDSETS (read the function 4 times, one question each)
| Mindset | The question |
|---------|--------------|
| **Attacker** | "How do I exploit this to drain funds or escalate privilege? What sequence?" |
| **Accountant** | "Trace every wei. Do the numbers add up across ALL paths (deposit/withdraw/mint/burn/liquidate/redeem)? round-trip <= start?" |
| **Spec Auditor** | "Does the code do what the docs / comments / NatSpec / the EIP say? Where do they DIVERGE?" (stale comment vs code = a real lead — Stobox `setWhitelist`) |
| **Edge-Case Hunter** | "What breaks at 0 / max / empty / single-user / last-user / self-referential / reentrant / same-block?" |

A lead seen by 2+ mindsets = consensus boost (prioritize). A single-mindset lead = extra scrutiny in VERIFY.

## STEP 2 — 4 LENSES (sweep the area through each)
- **A — Access & state integrity:** who SHOULD call this vs who CAN? governance/role invariants. siblings gated but this one isn't?
- **B — Value flow & economics:** fee consistency (deposit vs withdraw vs liquidate), rounding DIRECTION, accrual model (linear vs compound — Ledgity), first/last-mover, no-free-value.
- **C — External interactions:** CEI (state before external call?), cross-function & read-only reentrancy, what runs in the callback / between this call and the next line, cross-tx windows.
- **D — Edge / math / standards:** unsafe casts (uint256->uint128 silent truncation), div-before-mul, decimal/precision mismatch, EIP/ERC compliance (ERC-712 typehash char-by-char, ERC-4626 share math).

## STEP 3 — FEYNMAN INTERROGATION (7 questions per function)
1. **PURPOSE** — what invariant does this protect? what breaks if removed?
2. **ORDERING** — can I reorder ops to leave an inconsistent state?
3. **CONSISTENCY** — why does fn A have this guard but fn B doesn't? (the sibling-gap = recon heuristic 3)
4. **ASSUMPTIONS** — what's implicitly trusted (oracle, share price, msg.sender, a balance)? what if it's violated/manipulated?
5. **BOUNDARIES** — first call, last call, double-call, empty state, max values, zero amount?
6. **RETURN/REVERT** — what state persists on revert? can a failed external call leave dirty state?
7. **EXTERNAL CALLS** — what can the callee do before returning? can it reenter / move a price / change a balance the next line reads?

## STEP 4 — "WHAT'S MISSING" SWEEP (7 mechanical checks, after the creative read)
1. **Missing inverse op** — set w/o unset, lock w/o unlock, pause w/o unpause, add w/o remove.
2. **Missing access control** — a state-writing fn with no modifier / inline auth (and not a gated callee).
3. **Missing reward/accrual checkpoint** — reward/index state not updated BEFORE a balance change (double-claim).
4. **Missing restriction coverage** — some paths gated, a PARALLEL path (transferAndCall, CCT mint-to, batch, emergency) not.
5. **Missing paired-op validation** — deposit validates X but withdraw/redeem doesn't (asymmetry).
6. **Parameter-transition safety** — changing a param (rate, cap, collateralization) retroactively breaks EXISTING positions.
7. **DoS on a core fn** — unbounded loop, an external call that can revert, dust/force-feed griefing, strict `==` balance.

## STEP 5 — COUPLED-STATE (when 2+ functions touch shared state; hypothesize seeds this)
- Map each state var to its coupled dependency (totalSupply <-> Σbalances, rewardDebt <-> staked, $.totalAssets <-> Σcollateral).
- When StateA updates, does ALL dependent StateB update in the SAME tx? interleave the writers (esp. 2+ attacker-reachable, cross-contract).
- **Masking-code flag:** a ternary clamp / try-catch / min-max cap / `if (x > bal) x = bal` that HIDES a broken invariant instead of fixing it -> read what it's papering over (often the real bug, or proof it's protocol-safe-by-design).

## OUTPUT
For each surviving lead: a concrete **WHO / WHAT / HOW MUCH** (else it's gate-D speculative). Then -> `VERIFY.md`
(8 kill-gates + 10 FP-patterns) -> verdict -> ledger. Prove TP with a PoC or a verbatim-formula reimplementation,
never by reading alone.
