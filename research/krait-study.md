# Krait study — what to borrow (ZealynxSecurity/krait, MIT, examined 2026-06-10)

**What it is:** a Solidity-audit system shipped BOTH as Claude Code skills (`/krait`, no API) AND a TS CLI
(Anthropic SDK, for batch/shadow). Claimed: ~90% precision, **0.0 FP/contest in v7-v8 across 50 blind
Code4rena shadow audits**, "100% precision across 50 contests" bar. Self-improving (heuristics each mined
from a real missed finding). MIT -> we can adapt with attribution.

## Their pipeline (vs ours)
`preflight -> recon(AST+Slither+risk-score+tiers+primer) -> detector(3-pass: 4 mindsets x 4 lenses + Feynman
+ 101 heuristics + 26 modules + 7 primers) -> state-auditor(coupled-state 8-step) -> critic(8 kill-gates +
10 FP patterns) -> reviewer(2nd opinion) -> reporter`. CLI mirrors it as a multi-agent pipeline
(Detector->Reasoner->Critic->Ranker). MCP: **solodit** (search past C4/Sherlock findings) + **forge** (PoC).

**Honest comparison — they're COMPLEMENTARY, not competitors:**
- **Krait is stronger on the per-target AUDIT METHODOLOGY** (the L4 reasoning): structured multi-mindset
  prompting, explicit kill-gates, 101 heuristics, 26 modules, Solodit cross-ref, shadow-audit benchmarking.
- **WE are stronger on SOURCING + REACHABILITY + TRIAGE** (Krait is *given* a target; it does NOT source):
  scout v2/v3 (DefiLlama/Immunefi), DefiLlama-Adapters address resolution, fetch_source, forkdrift
  (fork+drift+audit-router), contest_monitor (timing edge), ledger. Krait has none of this.
- Ideal: OUR funnel (find -> reach -> triage -> is-it-novel/unaudited) FEEDS a Krait-style deep audit on the
  survivors. Our recon (21 regex detectors) is the cheap pre-filter; their multi-mindset read is the L4 depth.

## TOP BORROWS (prioritized -- cheap, high-impact, MIT-adaptable)
1. **Kill-gates + FP-patterns as an EXPLICIT checklist (do first).** We do verify-before-claiming implicitly;
   codify it. The 8 gates: A generic-best-practice, B theoretical/not-exploitable, C intentional-design
   (matches docs/fork-origin), D speculative (no concrete WHO/WHAT/HOW-MUCH), E admin-trust (except missing
   timelock on irreversible), F dust (<$1/tx), G out-of-context (unlisted token/chain), H publicly-known
   (README known-issues / prior audit). + 10 FP patterns (auth-elsewhere, validation-in-callee, OZ/Solmate
   protection, rounding-cleaned-downstream, bounded-loops, severity-inflation, 0.8-math-safety, view-fn,
   test/interface-only, documented-design). -> ADD as `toolkit/` doc or a `/verify` checklist; this is the
   discipline that gives them 0 FP/contest.
2. **L4 deep-read protocol = 4 MINDSETS x 4 LENSES + Feynman + "what's-missing" sweep.** Our hypothesize gives
   shared-state seeds; this is the structured READ on a flagged function. The 4 mindsets (Attacker / Accountant
   "trace every wei" / Spec-Auditor "code vs docs/EIP" / Edge-Case "zero/max/empty/reentrant") + Feynman 7-cat
   interrogation (purpose/ordering/consistency/assumptions/boundaries/return-values/external-calls) + the
   7-check missing-sweep (missing inverse-op / access / reward-checkpoint / restriction-coverage / paired-op
   validation / param-transition / DoS). -> ADOPT as my L4 checklist (biggest reasoning upgrade).
3. **Solodit cross-reference (kill gate H + enrichment).** They query Solodit (the global C4/Sherlock/audit
   findings aggregator) via an MCP: `search_similar_findings` / `validate_hypothesis`. We have ledger (OUR
   verdicts) + forkdrift (audit detection) but NOT a query vs the GLOBAL findings DB -> we could report a bug
   that's publicly known. -> add a Solodit lookup (their MCP, or a lighter `solodit.py` query) before reporting.
4. **Mine their 26 modules / 7 primers / 101 heuristics for detector+hypothesis ideas.** Directly fills our
   GameFi gaps: module **Q** "NFT attribute & randomness integrity", module **S** "cross-contract state on
   transfer" (= our asset-locking-bypass gap), module **K** "multi-tx attack sequences", module **V** economic
   design (circular collateral / liquidation profitability / first-last-mover). Their GameFi/NFT primer =
   randomness/attribute-collision/mint-griefing/royalty-bypass. -> recon/hypothesize detector backlog.
5. **Shadow-audit benchmarking.** They clone solved C4 contests, run the pipeline, diff vs official findings ->
   precision/recall dashboard, and treat FPs as worse than misses. WE HAVE NEVER BENCHMARKED our engine this
   way. -> build a tiny shadow-runner: clone a past contest we have the report for, run recon+hypothesize+my
   read, diff vs the known findings -> objective recall/precision on OUR pipeline (validates + guides fixes).

## Also noted
- Pattern YAML schema (`patterns/schema.yaml`) is richer than our markdown: id/category/severity + detection
  {strategy,regex,ast_pattern,indicators} + real_examples{source,project,finding_id,impact,amount_lost,
  code_vulnerable,code_fixed} + false_positive_notes + confidence. Could upgrade `research/patterns/`.
- `improvements-backlog.md` (17KB) = their roadmap; worth skimming for more ideas.
- Their FPs-worse-than-misses stance matches our verify-before-claiming + ledger discipline exactly.

## Recommendation
Borrow #1 (kill-gates checklist) and #2 (4x4+Feynman L4 protocol) FIRST -- pure prompt/doc, zero code, and
they're the core of Krait's 0-FP record. Then #5 (shadow-benchmark) to measure the gain objectively. #3
(Solodit) and #4 (module mining) next. Net: keep OUR sourcing/reachability moat, bolt on THEIR L4 rigor.
