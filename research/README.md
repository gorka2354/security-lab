# Bug-Pattern Library — the research engine behind the toolkit

Deep, example-rich studies of vulnerability classes — **especially the ones static recon CANNOT catch**.
Each pattern feeds three outputs: a **detector** (if static-catchable), a **hypothesis/invariant** (if it needs
reasoning), and a **writeup** (skill + reputation). Study the pattern + its real examples first; build the tool second.

## Why this exists (the detection gap — proven by data)
- **OWASP SC02:2026 top classes = Business-Logic Vulnerabilities + Price-Oracle Manipulation.** Price manipulation
  alone = **17.3% of major exploits Jan-2023…May-2025, >$165.8M**.
- Business-logic flaws = *the rules themselves are unsafe* — the code "does what it says", but what it says permits an
  exploitable outcome. **No runtime error, no access-control trip, no static signature.**
- The gap, in numbers: **frontier LLMs detect business-logic bugs ~31% of the time vs ~78% for senior human auditors.**
  Fuzzers (Echidna/Medusa) help on invariants — **but generating the RIGHT invariant still needs a human's model of
  what the protocol enforces.** → That human-derived-invariant + adversarial-reasoning layer is exactly our edge
  (`hypothesize.py` "their invariants as data" + L3 invariant fuzzing + Claude-as-verifier).

## Detectability tiers (where each pattern lands → which tool)
| Tier | What | Tool that catches it |
|---|---|---|
| **T0** regex signature | missing modifier, raw `ecrecover`, unchecked ERC20 return, `tx.origin` | `recon.py` detectors ✅ |
| **T1** AST / dataflow | some reentrancy, transitive gating, lib-auth | Slither + `analyze.py`; recon fix#15-19 |
| **T2** cross-component / state-invariant | shared-state breaks an invariant (supply≤backing, sharePrice unmanipulable) | `hypothesize.py` + `scaffold.py` L3 fuzz |
| **T3** economic / business-logic | the incentive/rule itself is exploitable; needs adversarial sequence | **human/Claude reasoning + adversarial sim** (the frontier) |

recon lives at T0/T1 (and floods FPs above that — the whole session proved it). **The money + the skill-growth are at
T2/T3.** This library's job: turn T2/T3 patterns into (a) the few extra T1 detectors that ARE catchable, and (b)
sharp, reusable HYPOTHESES + INVARIANTS for the T2/T3 reasoning layer.

## Method per pattern (the template)
1. **Mechanism** — how the rule breaks, precisely.
2. **Real examples** — post-mortems + our own first-hand session finds (we read the code).
3. **The "tell"** — what to grep / read / ask to spot it.
4. **Detector idea (static, T0/T1)** — a concrete regex/AST rule, or "not statically catchable → T2/T3".
5. **Hypothesis / invariant (T2/T3)** — the property to assert + how to fuzz/reason it.
6. **Mitigations to RECOGNIZE** — so we don't FP on safe code (the session's #1 lesson: most flags are mitigated).

## Index
- [x] **[erc4626-inflation.md](erc4626-inflation.md)** — vault share-price / exchange-rate manipulation (donation/first-depositor; vault-as-oracle). *Densest class; bit dStake, Venus, Inertia.*
- [ ] oracle-manipulation — spot-vs-TWAP, AMM-reserve, read-only-reentrancy price, cross-decimal/stale. *(Likwid truncatedReserves = the mitigation to study.)*
- [ ] reward-accounting — wave/queue/contribution double-claim, dust, timing windows. *(CU LibRewards = the correct design to study.)*
- [ ] liquidation-math — bad-debt socialization, self-liquidation, half-liquidation threshold, rounding direction.
- [ ] index/rate-manipulation — Aave-fork liquidityIndex inflation on empty markets. *(dTRINITY $257k.)*
- [ ] cross-chain / AA — mutable-chainId domain-separator replay (zkMarkets); extcodesize/EIP-1271 on zkSync (`det_l2_footgun`).
- [ ] interest/fee rounding — mulDivUp vs mulDivDown asymmetry over manipulable totals (Monolith soft-spot).
- [ ] init / upgrade / storage — front-run init, uninitialized impl, storage-collision, transitive proxy.

> Sync the transferable lessons into the Obsidian "Крипто безопасность" vault (heuristics + pattern notes) — that's the public/study face; this dir is the toolkit-feeding face.
