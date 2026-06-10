# VERIFY — kill-gates + FP-patterns before ANY finding is claimed

Run this on EVERY candidate before it leaves the lab. This is our verify-before-claiming discipline made
explicit. (Borrows the kill-gate / FP-pattern structure from Krait — ZealynxSecurity/krait, MIT — whose
0-FP/contest record across 50 blind audits comes from exactly this aggressiveness. Adapted to our white-hat +
severity-calibration + ledger flow.) **Rule: FPs are worse than misses.** A claimed-but-wrong finding burns
credibility (egor discloses, not me). When unsure -> downgrade to IE (insufficient evidence), not "report it".

## A finding must SURVIVE ALL 8 KILL GATES
| Gate | KILL it if... | Note |
|------|---------------|------|
| **A — generic best practice** | it's "use SafeERC20 / add events / two-step ownership / nonReentrant just in case" with no concrete exploit | hygiene != finding |
| **B — theoretical / not exploitable** | the trigger needs token/chain behavior NOT present in this deployment (e.g. a fee-on-transfer/ERC-777 path on a plain-ERC20 asset) | check the ACTUAL asset list |
| **C — intentional design** | it matches the docs, code comments, the reference impl, or the fork origin (forkdrift: verbatim canonical) | by-design (RockSolid/Lagoon, Alchemix self-liq) |
| **D — speculative** | you cannot state a concrete **WHO / WHAT / HOW MUCH** (attacker, action, loss) | "could be an issue if…" = not yet a finding |
| **E — admin trust** | it requires a trusted admin/role to act maliciously | EXCEPTION: missing timelock on an *irreversible/destructive* op IS a finding |
| **F — dust** | loss < ~$1/tx, bounded truncation, or precision loss < gas cost; or a protocol-favorable rounding (SUM(local)<=global) | calibrate magnitude (the Ledgity 0.47%/yr was NOT dust) |
| **G — out of context** | token behavior for an unlisted token, or a chain issue on an unsupported chain | scope discipline |
| **H — publicly known** | already in the README "Known Issues", a prior audit, or a public finding (Solodit / the protocol's audit/ dir) | LIVE-FIRST + ledger + forkdrift audit-router; query Solodit when in doubt |

**DoS exception:** a DoS that bricks a CORE lifecycle function + cheap to trigger + persistent = Medium
minimum, and it survives gates A/B/D/F (the Ledgity last-unwrapper-bricked tail qualified).

## Then check the 10 FALSE-POSITIVE PATTERNS (the lead is an FP if any holds)
1. **Auth handled elsewhere** — the gate is in the calling fn / a modifier / router / factory (recon FPs: ward `auth`, OZ `restricted`, library-internal called by a gated facet).
2. **Validation in the callee** — the guard is in an internal/external function this one calls, or a library.
3. **OZ / Solmate standard protection** — a battle-tested library already provides the guard (virtual shares, AccessManager, SafeERC20).
4. **Rounding cleaned downstream** — dust threshold / reconciliation / the rounding direction is protocol-safe (round user-debits UP, credits DOWN -> SUM(local) <= global).
5. **Bounded loops / economic constraint** — iterations bounded, or griefing costs more than it gains.
6. **Severity inflation** — a real issue but the actual impact is lower than first claimed (downgrade, don't drop).
7. **Solidity 0.8+ math safety** — checked arithmetic is built in (EXCEPTION: an explicit `uintX(...)` cast still truncates silently).
8. **View/pure confusion** — a `view`/`pure` function can't change state; not an access-control bug.
9. **Test / script / interface / mock** — not production code (the Alchemix AlEth "infinite mint" was a test mock).
10. **Documented design decision** — an intentional trade-off acknowledged in code/docs.

## VERDICT (assign one; only TP/LT reach a report)
- **TP** (true positive) — verified exploitable; attach the proof trace (PoC or a verbatim-formula reimplementation like the Ledgity one).
- **LT** (likely true) — mechanism confirmed, edge-case dependent; state the precondition.
- **DOWNGRADE** — real but lower severity than claimed.
- **FP** — disproven; **write WHY to the ledger** (so it never resurfaces; + fix the detector if a pattern FP).
- **IE** (insufficient evidence) — can't prove or disprove with the available source/state -> park, don't claim.

## After the verdict
- Every verdict -> `ledger.py add` (fp/known/wontfix/real/todo). FP-by-pattern -> also a recon precision fix.
- TP/LT -> calibrate severity HONESTLY (the Ledgity Medium-leaning-Low calibration), write the disclosure,
  confirm in-scope + a real bounty, and remember: **egor discloses, never me.**
