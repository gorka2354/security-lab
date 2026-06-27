# Tooling research — findings (20-agent sweep, 2026-06-27)

> Goal: accelerate FINDINGS + maximize COVERAGE. Verdicts: STEAL=integrate/fork, LEARN-FROM, PAID-REF, SKIP.
> Roadmap synthesis in ROADMAP.md.

## static-analyzers (Solidity static analysis beyond Slither, as an L2 lane in analyze.py)

**State of the art.** The post-Slither static landscape splits into three buckets for our purposes. (1) Slither-add-on detector packs (Slitherin) that bolt straight onto the Slither we already run and add genuinely NEW economic/logic detections we lack — read-only reentrancy, price-manipulation-via-arbitrary-call, Uniswap/AAVE integration bugs, double-entry tokens. (2) Independent AST analyzers (Aderyn-Rust, Wake-Python) with their own detector sets and clean JSON/SARIF output — easy to wire as parallel lanes, but their open-source detectors overlap heavily with our T0 + Slither and skew low/info-tier. (3) Exploit-derived pattern rulesets (Decurity semgrep) where each rule is tied to a real DeFi hack — same philosophy as our DeFiHackLabs mining, importable as patterns. None of these breaks the freshness wall (our actual #1 bottleneck); they widen COVERAGE on already-reachable verified code. solhint/4naly3er are lint/gas/QA-tier and redundant with our recon.py T0.

**Tools:**
- **[STEAL] Slitherin (pessimistic-io)** — https://github.com/pessimistic-io/slitherin  ()
  25+ custom Slither detectors: read-only reentrancy (general + Balancer), price-manipulation via arbitrary call, UniswapV2 integration bugs, AAVE flashloan-callback, double-entry token, unprotected setters/initializers, inconsistent nonReentrant, dubious typecasts, falsy-EOA modifier. pip install slitherin; run `slitherin-cli --pess` (Slitherin-only) or --separated. AGPL-3.0, 376 stars, active (Jun 2026).
- **[STEAL] Aderyn (Cyfrin)** — https://github.com/Cyfrin/aderyn  ()
  Rust single-binary AST static analyzer, ~100 high/low detectors, native Markdown/JSON/SARIF output, custom-detector framework in Rust, runs sub-second. GPL-3.0, 782 stars, very active. Detector set skews low/info but the clean machine-readable JSON+SARIF makes it the cheapest extra lane to parse into ledger/analyze.
- **[LEARN-FROM] Decurity/semgrep-smart-contracts** — https://github.com/Decurity/semgrep-smart-contracts  ()
  Semgrep rules where each rule is backed by the ACTUAL exploited source from a real DeFi hack (proxy-storage-collision, exact-balance-check, etc.). Free with semgrep OSS; intra-procedural taint needs --pro (paid). 713 stars. Same exploit-pattern philosophy as our shadow.py corpus — minable into recon.py regex patterns even without running semgrep.
- **[LEARN-FROM] Wake (Ackee-Blockchain)** — https://github.com/Ackee-Blockchain/wake  ()
  Python Solidity dev+fuzz framework with built-in detectors (strong cross-function reentrancy detector, ownable, etc.) + detector/printer API. ISC license, 368 stars, active. OSS detectors overlap Slither but its reentrancy printer/IR API is good. Heavier to integrate than a binary.
- **[PAID-REF] Wake Arena (Ackee)** — https://ackee.xyz/wake/arena  ()
  Hosted multi-agent AI audit: 108 detectors (87 private) feeding LLM graph-reasoning; claims 63/94 crit/high on historical contests, beating Zellic V12 and GPT-5.2. This is the reasoning-tier (T2/T3) automation we lack — but it's a paid managed service, not self-hostable.
- **[SKIP] 4naly3er (Picodes)** — https://github.com/Picodes/4naly3er  ()
  TypeScript analyzer producing the gas/QA 'automated findings' report used in Code4rena/audit contests. GPL-3.0, 552 stars. Mostly gas-optimization + QA-tier, near-zero novel security detection for us.
- **[SKIP] solhint security rules (protofire)** — https://github.com/protofire/solhint  ()
  MIT linter; security rules = reentrancy(state-after-transfer), avoid-low-level-calls, not-rely-on-time, etc. 1126 stars. Pure lint-tier, fully redundant with our recon.py T0 detectors.
- **[LEARN-FROM] tintinweb/semgrep-rules** — https://github.com/tintinweb/semgrep-rules  ()
  Small low-noise semgrep security ruleset (22 stars, no license). Minor supplement to Decurity's set.

**Techniques:**
- Slither-detector-pack stacking: since analyze.py already invokes Slither, `pip install slitherin` exposes the --pess suite in the SAME process — read-only reentrancy + price-manip detectors come online with near-zero new plumbing
- SARIF as the lane interchange format: Aderyn and Slither both emit SARIF; normalize all L2 analyzers to SARIF and dedupe by (detector, file, line) so each new analyzer is just another SARIF producer feeding ledger.py
- Exploit-anchored rule mining: Decurity ships the real victim source next to each rule — diff their rule's taint pattern against our recon.py coverage to find missing patterns, then port as regex/heuristic detectors (no semgrep runtime dependency)
- Cross-tool consensus scoring: run Slither+Slitherin+Aderyn over the same target and rank findings by how many independent engines flag a line — high-consensus = triage-first, single-engine = likely FP, which directly feeds our FP-tuning discipline
- Custom-detector authoring in two frameworks (Aderyn Rust API, Wake Python API) for any high-value pattern we mine but can't express as a regex in recon.py

**Applicability:** Concrete wiring: (1) NEW L2 sub-lane in analyze.py — add `slitherin` to the existing Slither call path (`slitherin-cli --pess --json`), map its read-only-reentrancy / price-manipulation / arbitrary-call detectors into the same finding schema recon.py emits, route verdicts to ledger.py. This is the single highest-ROI integration because Slither is already integrated. (2) Second analyzer lane in analyze.py — Aderyn as a self-contained Rust binary (`aderyn --output report.sarif`), parsed via SARIF, run in parallel during fan-out per-target so each agent gets Slither+Slitherin+Aderyn consensus. (3) Feed Decurity's exploit-anchored rules into the recon.py/shadow.py loop: treat their rule corpus like the DeFiHackLabs corpus — mine missing patterns into new recon detectors and validate recall with shadow.py. (4) Wake/Wake-Arena: backlog reference for the T2 reasoning gap, not a near-term lane.

**Impact:** Coverage, modest-to-meaningful magnitude. Slitherin is the real win: read-only-reentrancy and price-manipulation-via-arbitrary-call are exactly the T2-adjacent economic classes our recon.py misses, and they arrive for ~zero integration cost. Aderyn adds breadth + a clean SARIF lane but mostly low/info overlap. Decurity adds exploit-pattern breadth. Honest ceiling: this widens detection on already-reachable VERIFIED code — it does NOT touch the freshness wall (the documented zero-live-findings bottleneck) or the unverified/non-EVM blind spots. More detectors on the same hardened/audited reachable surface yields diminishing returns; expect better recall on the next fresh target, not a step-change in find rate.

**Implementability:** Slitherin: LOW effort — `pip install slitherin`, one new subprocess call in analyze.py, JSON parse; we already own the Slither dependency. v1 = run --pess, surface read-only-reentrancy + price-manip findings to ledger. A day. Aderyn: LOW-MED — install Rust binary (brew/cargo, works offline on Mac per MAC-LANE.md), `aderyn --sarif`, write a SARIF→finding adapter; dedupe against Slither. 1-2 days. Decurity semgrep: MED — semgrep Solidity is experimental and good taint needs paid Pro, so prefer mining their rules into recon.py patterns over running the engine; rule-porting is incremental. Wake: MED-HIGH — full framework, heavier; defer. Key dep/caveat: Slitherin is AGPL-3.0 and Aderyn GPL-3.0 — fine for our private self-hosted tooling (no distribution), but note it if any output is ever published.

**Recommendation:** BUILD-NOW Slitherin as a sub-lane on the existing Slither call (lowest effort, directly fills the read-only-reentrancy + price-manipulation T2 gap). PROTOTYPE Aderyn as a second SARIF lane for cross-tool consensus and mine Decurity's exploit-anchored rules into recon.py via the shadow.py loop. BACKLOG Wake; PAID-REF Wake Arena as the only credible self-serve T2/T3-reasoning automation if budget ever opens. SKIP 4naly3er and solhint — gas/QA/lint-tier, redundant with our T0.

---

## fuzzing

**State of the art.** The EVM fuzzing stack splits into two modes that map directly onto OUR two biggest gaps. (1) Harness-based property fuzzers — Echidna (Haskell, mature), Medusa (Go, parallel, coverage-guided, Foundry-cheatcode compatible) and Foundry's built-in invariant runner — find economic/invariant bugs FAST but need a written target wrapper + stated properties; this is exactly the reasoning-tier (T2/T3) automation OUR scaffold.py half-solves. (2) Bytecode/on-chain fuzzers — ItyFuzz (Rust, snapshot + concolic hybrid) point straight at a live address in fork mode, pull/decompile ABI when source is missing, and auto-generate exploits for >80% of historical hacks with ZERO human-written properties. ItyFuzz is the single highest-leverage item here: it attacks BOTH the unverified-contract blind spot AND reasoning-tier automation, with near-zero setup (address + block + chain). The harness side is dominated by Recon's create-chimera-app, which is a one-repo scaffold that drives Echidna+Medusa+Halmos+Foundry off a single target — i.e. a better scaffold.py.

**Tools:**
- **[STEAL] ItyFuzz** — https://github.com/fuzzland/ityfuzz  (yes (MIT, cargo build on Mac))
  Rust bytecode-level hybrid (fuzzing+concolic) fuzzer. Fork mode: give it a target address + block + chain, it pulls ABI from Etherscan (decompiles if unverified), and auto-finds precision-loss, overflow, fund-stealing, Uniswap-pair-misuse, reentrancy, flashloan exploits with NO human-written properties. Paper claims auto-exploit for >80% of past hacks. MIT, 1.1k stars, active (pushed Dec 2025).
- **[STEAL] Medusa** — https://github.com/crytic/medusa  (yes (AGPL-3.0))
  Go, parallelized coverage-guided mutational Solidity fuzzer on go-ethereum. Foundry-cheatcode compatible, faster multi-core throughput than Echidna, same property/assertion model. Active (pushed May 2026).
- **[STEAL] Recon create-chimera-app** — https://github.com/Recon-Fuzz/create-chimera-app  (yes (MIT-style template))
  Scaffold repo: write ONE target wrapper, run Echidna + Medusa + Halmos + Foundry invariant tests off it. Standardizes the harness boilerplate scaffold.py generates. Plus Recon-Fuzz/setup-helpers for actor/asset setup. Active (Apr 2026).
- **[STEAL] crytic/properties** — https://github.com/crytic/properties  (yes (AGPL-3.0))
  Pre-built, audited security properties for ERC20/ERC4626/ERC1155 and common ops. Drop-in invariants — directly seeds reasoning-tier coverage without hand-authoring each property. 370 stars, active (Mar 2026).
- **[LEARN-FROM] Echidna** — https://github.com/crytic/echidna  (yes (AGPL-3.0))
  The mature Haskell property fuzzer; coverage-guided, optimization-mode (maximize a value), Slither-informed. Already a scaffold.py engine option. Most battle-tested, slowest to set up vs Medusa. Active (Jun 2026).
- **[LEARN-FROM] Halmos** — https://github.com/a16z/halmos  (yes (AGPL-3.0))
  Symbolic (bounded model checking) tester, Foundry-test-compatible. Complements fuzzing: proves small properties exhaustively where fuzzing only samples. Already wired in scaffold.py. Pushed Aug 2025.
- **[LEARN-FROM] Trident** — https://github.com/Ackee-Blockchain/trident  (yes (Rust))
  Rust framework to fuzz Solana programs (Anchor-aware). The answer IF OUR engine ever covers SVM — currently non-EVM is a declared blind spot, so this is the on-ramp, not a now-build. 395 stars, active (May 2026).
- **[PAID-REF] Recon Pro (recon.xyz)** — https://getrecon.xyz  (no (SaaS; core tooling is the free chimera repos))
  Hosted cloud fuzzing + AI-assisted invariant generation + long-running campaigns on top of the open chimera tooling. Useful as a reference for AI-property-generation UX; the open repos give 80% free.

**Techniques:**
- On-chain fork fuzzing (ItyFuzz): point at live in-scope bounty address at a recent block; no source, no harness — auto-search for fund-stealing/precision/oracle-misuse. This is the fastest path from a fresh-deploy alert to a candidate exploit.
- Decompile-to-ABI fallback: ItyFuzz pulls bytecode + decompiles ABI for unverified contracts — turns OUR 'unverified = blind' contracts into fuzzable targets.
- One-target multi-engine harness (chimera): a single wrapper drives Echidna+Medusa+Halmos+Foundry, so a DIG hypothesis becomes 4 independent searches in parallel; Medusa for raw coverage throughput, Halmos to PROVE the narrow property.
- Drop-in property libraries (crytic/properties): attach standard ERC20/ERC4626 invariants automatically based on detected interface — converts recon.py's interface detection into runnable reasoning-tier properties.
- Optimization-mode fuzzing (Echidna/Medusa): instead of boolean invariant, maximize 'attacker balance delta' / 'protocol solvency gap' to surface economic leaks that don't trip a hard assert.
- Corpus reuse / coverage replay: persist fuzz corpus per target in ledger so re-runs after a code change resume from prior coverage (pairs with radar.py impl-upgrade diffs).

**Applicability:** Three concrete integrations: (1) NEW auto-PoC step after a DIG and after a freshdeploy/radar hit — wrap ItyFuzz fork mode as a lane callable from the hunt pipeline: input = (address, chain, block), output = candidate exploit trace or 'no bug found in N runs'. This is the only tool here that needs NO harness and works on UNVERIFIED code, so it slots between fetch_source.py (when source exists) and the dead-end (when it doesn't). (2) REWRITE/UPGRADE scaffold.py around create-chimera-app's structure so one generated target wrapper fans out to Echidna+Medusa+Halmos+Foundry instead of bespoke per-engine harnesses; add Medusa as the default fast engine (parallel, Foundry-cheatcode compatible). (3) Wire crytic/properties into scaffold.py keyed off recon.py interface detection (ERC20/4626/1155) to auto-attach reasoning-tier invariants — closes part of the T2/T3 automation gap without hand-writing properties.

**Impact:** both — and the largest single lever in this batch. ItyFuzz: COVERAGE (unblinds unverified contracts) + SPEED (zero-setup auto-exploit, minutes not hours) — realistically the only item that can convert a fresh-deploy alert into a finding without human harness work. chimera+Medusa+properties: ~2-4x faster harness turnaround and broader invariant coverage per DIG, but still gated on a stated hypothesis, so it amplifies OUR existing reasoning rather than replacing it. Net: meaningfully attacks the freshness wall (auto-fuzz every fresh deploy) AND the reasoning-tier automation gap.

**Implementability:** ItyFuzz: MED effort. Rust build on Mac via cargo (the MAC-LANE CDN-block note applies — build from source, may need an Etherscan key it already supports). Risk: fork-mode tuning (block selection, flashloan assumptions) produces noise; treat output as a candidate trace that VERIFY.md kill-gates, NOT a confirmed finding. v1 = a thin Python wrapper (ityfuzz_lane.py) that shells ityfuzz evm -t <addr> --onchain <chain> -f and parses the exploit report. chimera/Medusa: LOW-MED — Medusa is a single Go binary (brew/go install), chimera is a template to fork; scaffold.py refactor is the real cost. crytic/properties: LOW — git submodule + interface-keyed include. Trident: HIGH (whole new SVM lane) — defer. Main honest caveat: fuzzers find SHALLOW economic bugs fast but still struggle with deep multi-tx protocol invariants without a good harness, so this complements, not replaces, OUR L4 read.

**Recommendation:** BUILD-NOW: ItyFuzz fork-mode lane (only tool that unblinds unverified code + auto-finds exploits with zero harness — directly hits both top gaps). PROTOTYPE: refactor scaffold.py onto create-chimera-app + add Medusa as default engine + wire crytic/properties via interface detection. BACKLOG: Trident (only when/if SVM coverage is on the roadmap). LEARN-FROM/keep: Echidna+Halmos already integrated.

---

## ai-llm-audit

**State of the art.** The field has split into three reusable layers that map cleanly onto our gaps. (1) LLM-as-reasoner over a code diff with a hard false-positive filter — productionized by anthropics/claude-code-security-review (MIT, 5.4k stars): a Python harness whose findings_filter.py + claude_api_client.py + prompts.py are directly liftable as a new reasoning lane in analyze.py. (2) Static-confirmed LLM detection — GPTScan's ICSE'24 recipe: GPT proposes candidate logic-vuln scenarios, then program analysis confirms data/control flow before reporting, cutting FPs. This is exactly how to bolt a T2/T3 tier on top of recon.py's regex hits instead of letting an LLM free-associate. (3) Agentic Reason-Act-Observe PoC generation against forked state in Foundry — PoCo (MIT) turns an NL vuln report into an executable Foundry PoC, and quimera (AGPL, archived but pip-installable, has a no-API "manual mode") iterates LLM→forge test→trace→refine. Both slot under a DIG to auto-build the PoC our scaffold.py already harnesses. Commercial agents (AuditAgent, Almanax, Octane) report ~30-67% recall and are explicitly "pair auditor, not standalone" — honest ceiling for what an LLM tier buys us. Crucially, EVMBench (Paradigm/OpenAI, free) is now the standard reasoning-tier benchmark (120 high-sev bugs from 40 real audits, detect/patch/exploit harness) — a direct upgrade to shadow.py's recall measurement, which currently leans on the easier DeFiHackLabs/DeFiVulnLabs corpora.

**Tools:**
- **[STEAL] anthropics/claude-code-security-review** — https://github.com/anthropics/claude-code-security-review  (yes (MIT))
  MIT Python harness: diff-scoped Claude security review with a dedicated false-positive filter (findings_filter.py), Claude API client for FP adjudication (claude_api_client.py), prompt templates (prompts.py), robust JSON parsing, and an evals/ harness. General-purpose (web/injection-leaning), NOT solidity-tuned, but the scaffolding is the cleanest open reference for an LLM lane with FP suppression.
- **[LEARN-FROM] GPTScan** — https://github.com/GPTScan/GPTScan  (yes (AGPL-3.0))
  ICSE'24: combines GPT scenario-matching with static program analysis (Slither-based) to confirm candidate logic vulns before reporting — the canonical 'LLM proposes, static analysis confirms' architecture for reasoning-tier bugs with controlled FPs.
- **[STEAL] PoCo (ASSERT-KTH/PoCo-public)** — https://github.com/ASSERT-KTH/PoCo-public  (yes (MIT))
  MIT research artifact (arXiv 2511.02780): agentic Reason-Act-Observe loop that converts an auditor's NL vuln description into an executable Foundry PoC; beat zero-shot/workflow baselines on 23 real reports. Direct blueprint for an auto-PoC step.
- **[LEARN-FROM] quimera** — https://github.com/gustavo-grieco/quimera  (yes (AGPL-3.0))
  Data-driven LLM+Foundry exploit generation: LLM writes a forge test against forked state, runs it, reads traces, refines. Supports GPT-4o/Gemini/Ollama and a no-cost 'manual mode'. Archived (read-only) but pip-installable; great loop design.
- **[STEAL] EVMBench (paradigmxyz/evmbench, openai/frontier-evals)** — https://github.com/paradigmxyz/evmbench  (yes (open-source))
  Free benchmark+harness: 120 high-sev vulns from 40 real audits/contests (Code4rena, Paradigm Tempo) with detect/patch/exploit tasks in containerized, reproducible scoring. The reasoning-tier yardstick our shadow.py lacks.
- **[LEARN-FROM] SolidityGuard (alt-research)** — https://github.com/alt-research/SolidityGuard  (yes (check license/claims))
  Open agentic Solidity auditor: 104 vuln patterns, 8 tools, claims 120/120 on EVMBench + 100% CTF. Worth mining its pattern catalog and tool-orchestration for our fan-out/recon, but verify the self-reported scores skeptically.
- **[LEARN-FROM] calc1f4r/Horus** — https://github.com/calc1f4r/Horus  (yes (Apache-2.0))
  Apache-2.0 portable agentic audit workflow: curated vuln DB + grep-first 'hunt cards' + reusable playbooks for Claude/Codex/Gemini CLI. Maps onto our Claude agent-per-target fan-out; steal the hunt-card format. Tiny/young (0 stars) — treat as reference, not dependency.
- **[PAID-REF] Nethermind AuditAgent** — https://docs.auditagent.nethermind.io/  (no (free dev tier))
  Hosted AI auditor across Solidity/Cairo/Rust(SVM); free Developer tier (500 BLoC, up to 3 scans/day), GitHub Action + REST API. 67% post-validation recall on EVMBench. Covers our non-EVM (Cairo/Move/SVM) blind spot as an external oracle.
- **[PAID-REF] Almanax (ALMX-1) / Octane** — https://almanax.ai/  (no)
  Commercial 'AI security engineer' agents (Almanax: Solidity/Move/Rust/Go, CI integration; Octane: continuous per-commit scanning). Closed models, no self-host. Reference points for the reasoning ceiling and continuous-scan UX, not buildable.
- **[LEARN-FROM] LLMSmartAuditTool (LLM-SmartAudit)** — https://github.com/LLMAudit/LLMSmartAuditTool  (yes)
  OSS multi-agent auditing framework (role-specialized LLM agents emulating an audit firm). Useful design reference for a multi-pass reasoning tier, but multi-agent overhead is likely overkill vs a single confirm-then-reason pass for a solo engine.

**Techniques:**
- Confirm-then-reason (GPTScan pattern): never let the LLM free-scan; feed it ONLY recon.py's regex/heuristic hits + Slither sinks as candidate anchors, ask it to confirm/refute exploitability with a concrete data/control-flow path. Anchoring is what keeps FPs down and tokens cheap.
- Two-stage FP adjudication (claude-code-security-review pattern): a first model pass produces findings, a SECOND independent Claude call with a strict filter prompt kills low-impact/unprovable ones before they reach the ledger. Port findings_filter.py's deny-categories idea (DoS, generic input-validation, no-proven-impact) into our verdict pipeline.
- Diff-scoped review, not whole-repo: run the LLM lane only on forkdrift/diffscan deltas (audited base vs live) — matches our LIVE-FIRST + audit-drift doctrine and caps cost; this is precisely claude-code-security-review's diff-only design.
- Agentic Reason-Act-Observe PoC loop (PoCo/quimera): on a DIG, hand the LLM forge build/test + trace-read tools against forked state and let it iterate test→trace→refine until balance-delta invariant trips — output is a runnable scaffold.py harness, not prose.
- Benchmark-gated tuning: score every prompt/lane change against EVMBench's 120 real high-sev bugs (detect+exploit tasks) the same way our 353 golden tests gate detectors — gives an HONEST reasoning-tier recall number instead of T0-corpus optimism.
- Invariant/scenario seeding from LLM: use the LLM to draft candidate economic invariants (share-price, solvency, minted<=locked) per target, then feed them to Halmos/Medusa via scaffold.py — keeps the unsound LLM out of the verdict and lets the sound tool decide.

**Applicability:** Concrete integrations, in priority order: (1) NEW reasoning lane in analyze.py ('L2.5'): after recon.py + Slither produce candidate hits on the live/diff source, a confirm-then-reason Claude pass (GPTScan-style, anchored to those hits) + a second FP-filter pass (lifted from claude-code-security-review's findings_filter.py/claude_api_client.py) emits structured verdicts straight into ledger.py. This is the direct fix for our WEAK reasoning-tier automation. (2) Auto-PoC step after a DIG in the fan-out/scaffold path: a PoCo/quimera-style Reason-Act-Observe loop takes the DIG's NL hypothesis + fetch_source.py output + a fork RPC and emits a Foundry PoC into the scaffold.py harness — turning a triage hypothesis into a runnable exploit attempt automatically. (3) shadow.py upgrade: add EVMBench as a second corpus to measure reasoning-tier (T2/T3) recall, not just T0 pattern recall — gates prompt/lane changes. (4) Non-EVM blind spot: AuditAgent free dev tier as an external oracle for Cairo/Move/SVM targets surfaced by scout/radar (manual call, not in the auto loop). (5) Fan-out: adopt Horus-style 'hunt cards' as the per-target agent prompt scaffold.

**Impact:** Both — primarily COVERAGE (opens the T2/T3 economic/invariant class that regex structurally cannot reach; this is the biggest single gap in our stack) and secondarily SPEED (auto-PoC compresses DIG→PoC from manual hours to minutes). Magnitude is bounded and must be claimed honestly: commercial agents and AuditAgent land ~30-67% recall on real audits and remain 'pair auditor, not standalone' — so realistically a +1 tier of candidate generation and far faster PoC turnaround, NOT a step-change in live-find rate. Note the hard truth: our all-time-zero-findings wall is FRESHNESS sourcing, and an LLM reasoning tier does not move freshness — it raises ceiling on each fresh target we do reach.

**Implementability:** Med effort, low new deps (we already have the Anthropic SDK + Foundry + Slither + fork RPC). v1 of the analyze.py LLM lane: ~1 file that takes recon/Slither candidate JSON, builds an anchored confirm-then-reason prompt, runs a second FP-filter call, writes ledger verdicts — directly portable from claude-code-security-review's 4 modules (MIT, copy freely). v1 auto-PoC: wrap a forge build/test + cast trace toolset in a Reason-Act-Observe loop following PoCo's MIT reference; budget for iteration cost and a hard step cap. EVMBench wiring is a contained scaffold.py/shadow.py harness job (containerized scoring already provided). Watch-outs: GPTScan and quimera are AGPL (read their code for design, don't vendor into our tree); LLM token cost must be capped by diff-scoping; treat every LLM verdict as a hypothesis that still passes VERIFY.md kill-gates + callability checks before any disclosure — the LLM never gets the final say.

**Recommendation:** PROTOTYPE — Build the analyze.py confirm-then-reason + FP-filter LLM lane now (port claude-code-security-review's MIT filter modules, anchor to recon.py hits GPTScan-style) and the post-DIG auto-PoC loop (PoCo/quimera design); BUILD-NOW the EVMBench harness in shadow.py to measure it honestly. Keep AuditAgent free tier as a manual non-EVM oracle (PAID-REF). It raises per-target coverage/ceiling but will NOT break the freshness wall — sequence it as a force-multiplier on targets we already reach, not as the fix for zero live findings.

---

## onchain-dynamic-exploit

**State of the art.** The state of the art in auto-finding-the-exploit (not flagging patterns) is fork-and-fuzz with economic oracles: spin up a mainnet fork at a live block, mutate transaction sequences with DeFi-aware actions + flashloan/reentrancy, and assert on abnormal fund flow rather than code patterns. ItyFuzz (fuzzland, MIT) is the production-grade open tool — bytecode-level, onchain fork mode, flashloan/reentrancy oracles, claims auto-generation of working exploits for >80% of historical hacks with zero prior knowledge (Nomad in 0.3s). VERITE (FSE'25) supersedes ItyFuzz academically with a profit-centric design (DeFi-action mutators + gradient-descent profit maximization, 134x more extracted profit, found 6 zero-days/$2.5k bounties) but ships only a paper+dataset, not a usable fuzzer. The decisive unlock for OUR stack: these tools run at bytecode level on forked state, so they sidestep BOTH our reasoning-tier gap (economic oracle, not regex) AND our unverified-contract gap (no source needed) — exactly our two weakest seams.

**Tools:**
- **[STEAL] ItyFuzz** — https://github.com/fuzzland/ityfuzz  (yes — MIT)
  Bytecode-level hybrid fuzzer+symbolic-exec with onchain fork mode (--onchain-block-number, any of 60+ chains), built-in economic oracles (fund-stealing, Uniswap-pair misuse, precision-loss, integer overflow), flashloan + reentrancy support. Auto-generates a concrete exploit tx-sequence from live forked state. MIT, 1.1k stars, Rust, last push 2025-12.
- **[LEARN-FROM] VERITE (FSE'25, wtdcode)** — https://github.com/wtdcode/verite  (no — code not released; dataset+paper only)
  Profit-centric fuzzer: DeFi-action mutators, abnormal-fund-flow candidate criteria, gradient-descent profit maximization. Beats ItyFuzz 29-vs-10 on detection and ~134x on extracted profit over 61 real DeFi exploits. CRITICAL CAVEAT: repo currently ships only paper.pdf + dataset.csv (61 profitable-exploit targets) — no fuzzer source released. Mine the design + dataset, can't run it.
- **[STEAL] heimdall-rs** — https://github.com/Jon-Becker/heimdall-rs  (yes — open source)
  EVM toolkit that decompiles UNVERIFIED bytecode to pseudo-Solidity, recovers storage layout, function selectors, CFG, and traces. Directly attacks our 'unverified contracts unreachable' blind spot. Rust, 1.5k stars, actively maintained (push 2026-06).
- **[STEAL] DeFiHackLabs** — https://github.com/SunWeb3Sec/DeFiHackLabs  (yes — MIT)
  700+ Foundry PoC reproductions of real hacks — the canonical auto-PoC template library. We already use it in shadow.py; reuse its harness skeletons as the scaffold target for ItyFuzz-confirmed leads and as ground-truth for the economic-oracle tuning. 6.6k stars, updated daily.
- **[LEARN-FROM] blazo** — https://github.com/fuzzland/blazo  (yes — MIT)
  Official one-command wrapper to run ItyFuzz onchain against an address. Useful as a reference for the CLI invocation/RPC plumbing, but STALE (last push 2024-02, 8 stars) — copy the invocation pattern, don't depend on it.
- **[PAID-REF] BlockSec Phalcon Explorer + Simulation API** — https://docs.blocksec.com/transaction-insights/transaction-simulation-api  (no — hosted, API gated)
  Fork-and-simulate replay with balance-diff/fund-flow traces; good for validating a candidate exploit tx and reading fund-flow without a local fork. Free explorer UI; programmatic Simulation API is gated.
- **[PAID-REF] Tenderly Simulation API** — https://tenderly.co  (no — hosted)
  Hosted tx/bundle simulation across 40+ chains with state-override and asset-change output; handy as a quick second-opinion oracle on a candidate exploit bundle. Free tier exists but throttled; not self-hostable.

**Techniques:**
- Onchain fork-fuzz at a live block: replay live state, mutate tx-sequences, assert on fund-flow — finds economic bugs regex/Slither cannot, on the actual deployed bytecode.
- Economic/profit oracles instead of pattern oracles: flag when attacker balance increases / protocol invariant breaks (VERITE's abnormal-fund-flow criterion + ItyFuzz fund-stealing oracle) — this is the reasoning-tier automation we lack.
- Flashloan-assumption fuzzing: grant the fuzzer infinite capital so it explores capital-gated paths (price manipulation, share-price, liquidation) that bounded fuzzers miss.
- Bytecode-level fuzzing => unverified contracts become targets without source — pairs with heimdall decompile to give L4 a readable view.
- Profit maximization as gradient descent on identified candidates (VERITE) — turn a 'breaks invariant' hit into a quantified, severity-ranked, copy-paste exploit.
- Differential/auto-PoC: once a fuzzer finds a tx-sequence, emit it into a DeFiHackLabs-style Foundry test as the disclosure artifact.

**Applicability:** Concrete integrations, in priority order. (1) NEW DYNAMIC LANE in scaffold.py: add an `ityfuzz onchain` target alongside the existing Foundry/Echidna/Medusa/Halmos harnesses. It needs only what we already have — chain RPC + address + block (from fetch_source.py's Etherscan-v2 keys, 60+ chains) — and runs as the auto-PoC step AFTER a DIG/DIG-queue item from fanout_log.py: feed it the target + suspected attacker-controlled funcs, let its economic oracle confirm/deny exploitability and emit a concrete tx-sequence. This is the missing T2/T3 automation: it attacks live state with a profit oracle, not a pattern. (2) NEW STEP in fetch_source.py: when a contract is UNVERIFIED, call heimdall-rs to decompile bytecode -> pseudo-Solidity + storage layout + selectors, so recon.py heuristics and the L4 read can still operate, and ItyFuzz (bytecode-level) can fuzz it directly — closing the unverified blind spot. (3) shadow.py corpus extension: add VERITE's dataset.csv (61 profitable targets) as a second ground-truth corpus and use ItyFuzz's auto-exploit rate as a recall yardstick for the dynamic lane. (4) hypothesize.py: port VERITE's abnormal-fund-flow oracle as a new economic invariant seed (attacker_balance_delta > 0 under flashloan) for the Echidna/Medusa harnesses we already generate.

**Impact:** Both — and this is the highest-leverage angle for our two named gaps. Coverage: bytecode-level fork-fuzz directly automates the reasoning-tier (economic/invariant) class we explicitly can't do today, and via heimdall it reaches unverified contracts — two blind spots closed at once. Speed/findings: ItyFuzz turns a DIG from hours of manual L4 + hand-written Foundry PoC into a minutes-to-seconds automated confirm-or-kill with a ready exploit sequence (Nomad-class in sub-second). It does NOT fix the #1 freshness-sourcing bottleneck (zero live findings is a sourcing problem, not a tooling one), but it sharply raises conversion of each sourced lead into a confirmed, PoC-backed finding — which is the second-biggest lever.

**Implementability:** ItyFuzz lane: MEDIUM effort. It's a prebuilt Rust binary (cargo/docker), MIT; v1 is a scaffold.py subcommand that shells out `ityfuzz evm -t <addr> -c <chain> --onchain-block-number <n> --flashloan --onchain-etherscan-api-key $KEY` and parses the emitted exploit. Main friction: per-chain RPC archive-node access for fork fuzzing (a public RPC often rate-limits state pulls — budget for a paid archive endpoint or rely on its onchain-fetch cache), and oracle tuning to suppress FPs. heimdall lane: LOW-MEDIUM — single binary, decompile call + parse, cleanly bolts onto fetch_source.py's unverified branch. VERITE: LOW effort to ingest dataset.csv into shadow.py; HIGH/blocked to run the fuzzer (no source). v1 prototype: wire ItyFuzz behind one DIG-queue target on a chain where we hold an archive RPC, measure how many DeFiHackLabs/VERITE-dataset victims it auto-exploits, then promote to a standing post-DIG step.

**Recommendation:** PROTOTYPE — wire ItyFuzz as a dynamic fork-fuzz lane in scaffold.py as the auto-PoC/confirm step after a DIG (MIT, bytecode-level, economic oracle = exactly our reasoning-tier + unverified gaps), and BUILD-NOW the heimdall-rs decompile step in fetch_source.py since it's low-effort and unblocks unverified targets for both recon and the fuzzer. Treat VERITE as LEARN-FROM (port its profit oracle + ingest its 61-target dataset; no runnable code). Phalcon/Tenderly stay BACKLOG/PAID-REF as exploit validators. Caveat: this raises lead->finding conversion, not lead supply — freshness sourcing remains the separate #1 bottleneck.

---

## invariant-libraries

**State of the art.** For standardized contract types (ERC20/721/4626, fixed-point math) the reasoning-tier invariant problem is largely SOLVED by off-the-shelf property libraries — you don't need to hand-derive vault/token invariants. Trail of Bits' crytic/properties ships 25 ERC20 + 19 ERC721 + 37 ERC4626 + 106 ABDKMath64x64 pre-built properties runnable under Echidna/Medusa/Foundry; a16z/erc4626-tests gives a Foundry+Halmos-native 4626 spec suite; Recon's Chimera gives "write-once-run-everywhere" harness plumbing (Foundry/Echidna/Medusa/Halmos/Kontrol from one suite) and giovannidisiena/properties-chimera ports the 4626 props onto it. These bolt directly onto our existing scaffold.py multi-engine generator and are the fastest path to T2 coverage for the exact classes our recon already flags (det_vault_share_math = Thetanuts/4626, det_decimal_scale = wrappers). They cover STANDARD invariants only — bespoke economic logic still needs hand-built properties, so this closes the "standard 4626/ERC20 rounding/solvency" slice of the T2 gap, not arbitrary economic reasoning.

**Tools:**
- **[STEAL] crytic/properties** — https://github.com/crytic/properties  (yes (AGPL-3.0; fine for self-use white-hat, not redistribution))
  Trail of Bits pre-built security properties: 25 ERC20, 19 ERC721, 37 ERC4626, 106 ABDKMath64x64. Runnable as Echidna/Medusa fuzz harnesses or Foundry unit tests. Internal (inherit) or external (wrap) testing modes. `forge install crytic/properties`.
- **[STEAL] a16z/erc4626-tests** — https://github.com/a16z/erc4626-tests  (yes (AGPL-3.0))
  Property tests for the full EIP-4626 spec, Foundry-native and Halmos-compatible. Abstract test contract you inherit/parametrize with the vault under test. 220 stars, maintained 2025.
- **[LEARN-FROM] Recon-Fuzz/chimera** — https://github.com/Recon-Fuzz/chimera  (yes (no explicit license file — treat as source-reference, vendor patterns not code))
  'Write once, run everywhere' property-test framework: one suite runs under Echidna, Medusa, Halmos, Kontrol and debugs in Foundry. Exactly the multi-engine goal scaffold.py hand-rolls today.
- **[LEARN-FROM] Recon-Fuzz/create-chimera-app** — https://github.com/Recon-Fuzz/create-chimera-app  (yes)
  Starter template wiring Foundry tests + Echidna + Medusa + Halmos invariant testing out of the box. Concrete reference for what scaffold.py harness output should look like.
- **[LEARN-FROM] giovannidisiena/properties-chimera** — https://github.com/giovannidisiena/properties-chimera  (yes (AGPL-3.0; 1 star, niche but useful as an adapter blueprint))
  crytic 4626 properties ported onto the Chimera harness format — shows the exact glue to mount ToB properties under a modern multi-engine suite.
- **[LEARN-FROM] lindy-labs/solidity_properties** — https://github.com/lindy-labs/solidity_properties  (yes)
  Symbolic-test (Halmos) reformulation of crytic-style properties for common operations — a SYMBOLIC complement to the fuzz-oriented crytic/properties, for cases where you want proofs not just fuzzing.
- **[PAID-REF] abdk-consulting/abdk-libraries-solidity** — https://github.com/abdk-consulting/abdk-libraries-solidity  (yes (BSD-4-Clause; reference only — last touched 2024))
  The ABDKMath64x64 fixed-point library itself — pair with crytic's 106 ABDKMath properties when a target (options/derivatives/AMM) uses ABDK math, to fuzz for overflow/precision bugs.

**Techniques:**
- Detector-triggered auto-mount: when recon.py flags a target as ERC20/721/4626/ABDK (det_vault_share_math, det_decimal_scale already fingerprint vault/wrapper math), scaffold.py picks the matching property library and generates the harness automatically — no manual property authoring per DIG.
- External-vs-internal harness wiring: for OUR use case (forked live verified source we don't own), use the EXTERNAL testing mode (wrap deployed/forked instance as a target) rather than internal inheritance — crytic/properties documents both; external is the right default for fork-based hunting.
- 'Write once, run everywhere' suite layout (Chimera): structure generated harnesses so one property file runs under fuzz (Echidna/Medusa) AND symbolic (Halmos/Kontrol) — fuzz finds counterexamples fast, symbolic proves absence; reuse the same properties.
- Property-as-oracle on a fork: mount the 4626 spec suite (a16z) against the live forked vault to surface rounding-direction / share-solvency / preview-vs-actual divergences — the exact Thetanuts near-empty share-price class.
- ABDK precision fuzzing: when source imports ABDK 64x64, drop in crytic's 106 math properties to hunt for overflow/round-to-zero in fee/price math.

**Applicability:** Direct upgrade to scaffold.py: add a "property-library auto-mount" step. recon.py classifies the target (already partially done via det_vault_share_math/det_decimal_scale/standard-interface detection); scaffold.py then vendors the matching suite — crytic/properties for ERC20/721/ABDK, a16z/erc4626-tests for vaults — wires it in EXTERNAL mode against the fetch_source.py verified source, and emits an Echidna+Medusa+Halmos harness. This becomes the default "auto-PoC/DIG step" after any vault/token DIG in the /hunt pipeline, replacing hand-written invariants for standard types. Chimera/create-chimera-app are the structural blueprint for how scaffold.py should template multi-engine output (one suite, four engines). ledger.py records which property suite was run per target so the same standard-invariant sweep isn't repeated.

**Impact:** both — but bounded. Coverage: meaningfully closes the T2 slice for STANDARD types (4626 vaults, ERC20/721, ABDK math) which is a large share of DeFi targets and matches classes recon already flags. Speed: turns "hand-derive + write invariants" (hours per target) into a near-instant auto-mount. Magnitude is real but scoped: it does NOT touch bespoke economic/cross-protocol reasoning (still manual) and does NOT help the freshness/sourcing bottleneck at all — it accelerates the DIG once a target exists, not target discovery.

**Implementability:** Low-to-medium effort. crytic/properties + a16z/erc4626-tests are `forge install`-able with documented harness patterns; the work is (1) target-type classification glue in recon.py (mostly exists), (2) an external-mode harness template in scaffold.py, (3) remappings/solc wiring under MAC-LANE (offline solc). v1: hardcode the ERC4626 path — recon flags a vault, scaffold mounts a16z/erc4626-tests + crytic 4626 props in external mode against forked source, run Medusa. Main friction: external-mode wrappers need per-target constructor/asset wiring (semi-manual), and AGPL means self-use only (fine). Chimera adoption is a larger refactor — BACKLOG that; start by stealing crytic/a16z directly.

**Recommendation:** BUILD-NOW — wire crytic/properties + a16z/erc4626-tests into scaffold.py as a recon-triggered auto-mount (external mode) for ERC20/721/4626/ABDK targets; it's the cheapest real T2 coverage gain and lands exactly on the vault/wrapper classes our detectors already surface. PROTOTYPE Chimera multi-engine harness layout as the longer-term scaffold.py template; BACKLOG full Chimera migration.

---

## fresh-target-data — cheapest cross-chain feed of brand-new funded contracts to beat the freshness wall

**State of the art.** The #1 bottleneck (zero live findings = freshness, not detector coverage) is fundamentally a data-sourcing problem, and the cheapest fix is a chain-wide new-contract firehose rather than the current per-deployer Etherscan-v2 polling in freshdeploy.py. Two free, self-hostable primitives dominate: Envio HyperSync can stream ALL `create`-kind traces across EVM chains (every new contract, ~2000x faster than RPC, Python client, free tier with token) — this is a true firehose vs. our watchlist-only model. DefiLlama's `/protocols` carries a `listedAt` timestamp on 6209 protocols, so sorting desc is a free "newly-listed funded protocol" feed that already surfaces egor's sector (Sui Luck Games, flooor.fun, Mezo yield) within hours. Token-launch trackers (GeckoTerminal/DexScreener "latest/new pools", free) add a funded-token radar; Sim by Dune / Dune SQL / Allium / Footprint are enrichment or paid-ref, not the cheap firehose. The strategic shift: stop watching known deployers, start watching the whole chain and filter to funded+verified.

**Tools:**
- **[STEAL] Envio HyperSync (hypersync-client-python)** — https://github.com/enviodev/hypersync-client-python  ()
  Rust-backed Python client to query HyperSync. Trace queries with kind=create return every contract creation (INIT code + created ADDRESS) on a chain, ~2000x faster than JSON-RPC. Trace endpoints e.g. https://eth-traces.hypersync.xyz; supports ETH/Base/Arbitrum/Gnosis/Monad for traces (more chains for logs/tx). MPL-2.0, pip install hypersync. Free tier; API token required since 2025-11-03 (envio.dev/app/api-tokens).
- **[LEARN-FROM] Envio HyperIndex** — https://github.com/enviodev/hyperindex  ()
  Self-hostable multichain indexer (Dockerized, GraphQL out, factory/dynamic-contract support for 1M+ contracts, EVM+Solana+Fuel). Heavier than needed for a firehose but the reference impl for indexing fresh factory children.
- **[STEAL] DefiLlama /protocols API (listedAt)** — https://api-docs.defillama.com/  ()
  Free open API. GET api.llama.fi/protocols returns all protocols incl. a listedAt unix ts (6209/7742 have it). Sort desc = newly-listed funded protocols with chain+category+TVL. Verified live: top entries are hours-old and skew GameFi/gambling/yield (egor's sector). Web mirror: defillama.com/recent.
- **[STEAL] GeckoTerminal API (new_pools)** — https://apiguide.geckoterminal.com/  ()
  Free (beta), 10 calls/min. /networks/new_pools (all chains) and /networks/{net}/new_pools = latest 20 pools = fresh tokens that just got liquidity (= funded launch signal). Good GameFi/gambling token radar across 100+ chains.
- **[STEAL] DexScreener API** — https://docs.dexscreener.com/api/reference  ()
  Free, no key. token-profiles/latest, token-boosts/latest, and pair endpoints surface freshly launched/promoted tokens across chains. Redundant-ish with GeckoTerminal but different coverage; good as a second funded-launch source.
- **[LEARN-FROM] Sim by Dune (Activity/Realtime API)** — https://docs.sim.dune.com/evm/activity  ()
  Realtime per-address activity feed (native/ERC20/NFT/decoded calls), CU-priced (Activity=3 CU/req), free tier exists. Not a cheap chain-wide CREATE firehose, but excellent for ENRICHING a fresh candidate: is it funded? active? who funded it?
- **[PAID-REF] Dune Analytics (SQL + API)** — https://dune.com/pricing  ()
  Write a 'new verified contracts funded > $X in last 24h' query across chains; great for backtests/calibration. Free tier limited, API/CSV export is paid. Not realtime-cheap.
- **[PAID-REF] Allium / Footprint** — https://www.allium.so/  ()
  Enterprise multichain data (realtime streams, decoded). Powerful but priced for teams; overkill for a solo white-hat. Track for reference only.

**Techniques:**
- CREATE-trace firehose: poll HyperSync kind=create per block-range per chain, dump (creator, new_addr, init_code_hash); the whole point is chain-wide coverage vs. our watchlist-only freshdeploy.py
- Fresh+funded+reachable filter: gate firehose output to (has balance OR holds tokens) AND has verified source (Etherscan-v2 getsourcecode) AND age < N hours -> dig-now queue; unverified+funded -> park (matches our no-decompile gap)
- newly-listed lane: nightly sort DefiLlama /protocols by listedAt desc, diff against ledger, auto-fetch_source the protocol's core addresses (DefiLlama-Adapters resolve) -> forkdrift+recon before anyone audits it
- funded-launch radar: GeckoTerminal/DexScreener new_pools -> token addr -> creator/owner contract -> recon; sector-filter to gaming/gambling/lottery names
- init-code dedup: hash creation bytecode to collapse 1000s of factory clones into one pattern; only triage novel init_code_hash (kills clone noise like our 8-clone BY/LPC case)
- enrichment-on-demand: only spend Sim/Dune CUs AFTER the free firehose flags a candidate, never as the primary feed

**Applicability:** Direct, named integrations: (1) NEW data source in freshdeploy.py — add a `hypersync_creates(chain, from_block)` provider beside the existing legacy.deployer_contracts/factory_spawned Etherscan path, flipping it from watchlist-polling to chain-wide CREATE firehose, then reuse its existing is_verified()/funded filter to queue hunts/_radar/FRESH-DEPLOY.md. (2) New 'recently-listed' lane in scout.py (which already pulls DefiLlama) — sort /protocols by listedAt, diff vs ledger.py, emit fresh targets straight into the /hunt SOURCE step. (3) New token-launch source feeding radar.py/freshdeploy via GeckoTerminal+DexScreener new_pools, sector-filtered to GameFi/gambling. (4) Sim/Dune as the funded?/active? enrichment call inside activity.py's Phase-0 LIVE-FIRST gate, not as a feed. Output of all four lands in the existing fanout_log.py DIG-queue.

**Impact:** Both, large on coverage and the #1 lever (freshness). Today freshdeploy.py only sees contracts from deployers we already chose to watch; HyperSync CREATE-traces see EVERY new contract on a chain, so coverage of brand-new code goes from a hand-picked watchlist to chain-complete — this is the difference that could break the all-time zero-live-findings wall. DefiLlama listedAt + new_pools add a near-zero-cost protocol/token freshness signal in egor's exact sector. Speed: hours-fresh queue instead of finding code after it's hardened/audited.

**Implementability:** Med effort, low deps. HyperSync: pip install hypersync (MPL-2.0 Rust-backed Python client, verified to exist, 32 stars, maintained Jun 2026) + free API token; v1 = a ~80-line provider in freshdeploy.py that pages create-traces over a block window on ETH/Base/Arbitrum (trace-enabled chains) and pipes addrs into the existing verified+funded filter. Caveat: trace endpoints cover fewer chains than log endpoints, and token rate/credit limits aren't publicly numeric — must measure against free quota. DefiLlama listedAt lane is trivial (1 request + sort + ledger diff, already verified working, stdlib only). GeckoTerminal/DexScreener lanes are ~30 lines each, free, no key (GeckoTerminal 10 calls/min). All four are stdlib-or-one-pip, no infra to host.

**Recommendation:** BUILD-NOW the DefiLlama-listedAt lane (trivial, free, verified, sector-matched) and PROTOTYPE the HyperSync CREATE-trace provider in freshdeploy.py (highest-leverage coverage jump on our #1 bottleneck; gate on free-tier limits). BACKLOG GeckoTerminal/DexScreener token-launch radar and Sim-by-Dune enrichment; SKIP Allium/Footprint (paid, team-scale).

---

## mempool-realtime (pre-confirmation / real-time monitoring for the timing edge)

**State of the art.** For a SOLO WHITE-HAT (not an MEV trader), the mempool timing edge is mostly a category error against OUR actual goal: bugs in already-deployed contracts have no sub-second dimension — the buggy code sits on-chain for hours/days and our bottleneck after sourcing is L4 analysis, not latency. The real, narrow mempool wins are three, and only one is timing: (1) DEFENSIVE — when we finally find a live exploitable bug, broadcasting a rescue/PoC tx through the public mempool gets generalized-frontrun by sweepers; a private relay (Flashbots Protect, free) is the safe-disclosure primitive we currently lack. (2) SOURCING — live-exploit/anomaly feeds (eigenphi MEVScan, Forta, OZ Monitor) are fresh victim-contract + pattern firehoses that feed shadow.py's corpus and fork-target sourcing, but that's confirmed-tx anomaly detection, not mempool. (3) a marginal radar.py head-start watching pending txs to known deployers/upgrade-admins. Raw mempool ingestion (own reth+bxgateway, bloXroute newTxs at 10-100ms) is genuine MEV-bot infra with no finding-density payoff for us — SKIP.

**Tools:**
- **[STEAL] Flashbots Protect RPC** — https://docs.flashbots.net/flashbots-protect/overview  ()
  Free permissionless private RPC: txs go to a private mempool, only included if they don't revert, no fee on failed tx, hidden from frontrun/sandwich bots. Mainnet+Sepolia+Holesky. Just an RPC URL (rpc.flashbots.net).
- **[LEARN-FROM] flashbots/rpc-endpoint** — https://github.com/flashbots/rpc-endpoint  ()
  Open-source Go implementation of the Protect RPC endpoint — self-hostable if we ever want our own private-tx relay logic / multi-builder routing for rescue txs.
- **[LEARN-FROM] OpenZeppelin Monitor** — https://github.com/OpenZeppelin/openzeppelin-monitor  ()
  AGPL-3.0, self-hostable Rust monitoring daemon: watches EVM/Solana/Stellar for configurable on-chain conditions, checkpoint persistence, missed-block recovery, Slack/Discord/Telegram/webhook/custom-script triggers, cron scheduling. Production-grade alternative to our home-grown radar.py polling.
- **[LEARN-FROM] EigenPhi MEVScan (+MCP)** — https://eigenphi.com/  ()
  MEV/arb/sandwich/liquidation events exposed as MCP tools with SSE streaming — search by block/time/address/type, PNL + token-flow breakdown. The MCP fits our Claude fan-out model directly; useful as a fresh-victim / pattern feed, not mempool timing.
- **[LEARN-FROM] Forta detection bots (forta-bot-sdk + examples)** — https://github.com/forta-network/forta-bot-sdk  ()
  Open-source SDK to write detection bots; can run a PRIVATE node fully independent of the public network. 1000+ existing bots (Nethermind/SEAL) = a mineable library of real-time threat heuristics to port into recon.py reasoning-tier seeds. Note: scanner quickstart docs deprecated, SDK active.
- **[PAID-REF] bloXroute newTxs / pendingTxs stream + bxgateway** — https://docs.bloxroute.com/bsc-and-eth/streams/newtxs-and-pendingtxs  ()
  BDN mempool stream 10-100ms faster than txpool; free 'Intro' account for sending txs; gateway open-source. Real MEV infra — overkill for us, only relevant if we ever do pending-deployer watch on BSC.
- **[PAID-REF] Bitquery Mempool API** — https://docs.bitquery.io/docs/examples/mempool/mempool-api/  ()
  Hosted GraphQL/WS stream of pending txs filterable by sender/recipient/contract/method before they land; free dev key at ide.bitquery.io with quota. Cheapest way to prototype a pending-deployer/upgrade-admin watch without running a node.
- **[LEARN-FROM] alvidofaisal/fraud-mev-monitor** — https://github.com/alvidofaisal/fraud-mev-monitor  ()
  Python rule-engine over mempool w/ Redis sliding windows + FastAPI + Prometheus/Otel. 0 stars, unproven, but a clean reference architecture for a rule-engine-over-pending-stream if we build the radar pending lane.
- **[PAID-REF] Blocknative Mempool Explorer / webhooks** — https://www.blocknative.com/blog/explorer  ()
  Hosted mempool webhooks/websockets + dashboard. Reliable but paid for serious volume; reference for the UX of address-targeted pending alerts.

**Techniques:**
- Private-tx disclosure/rescue: route any PoC or white-hat rescue transaction through Flashbots Protect RPC instead of public mempool so generalized frontrunners can't steal the exploit when we go on-chain.
- Pending-deployer watch: eth_subscribe newPendingTransactions filtered to watched deployer/factory/upgrade-admin addresses -> fire radar alert seconds before confirmation (head-start on impl-upgrade slot-diff).
- Pending contract-creation sniff: flag pending txs with empty `to` + bytecode payload to catch brand-new deployments — but useless to us until verified (our no-decompile gap blocks bytecode-only analysis).
- Live-exploit feed as a fork-target source: ingest eigenphi/Forta anomaly events -> auto-enqueue the victim contract as a DIG / shadow.py corpus entry (sourcing, not timing).
- Heuristic mining: port Forta's 1000+ open detection-bot rules into recon.py reasoning-tier invariant seeds.
- Rule-engine-over-stream pattern (sliding windows / Redis) for stateful alerts like repeated high-value approvals to one spender.

**Applicability:** Three distinct integrations, by verdict: (1) BUILD-NOW — add a `--private` broadcast path to scaffold.py / any rescue-PoC step that sends through Flashbots Protect RPC (rpc.flashbots.net); zero infra, removes the real risk that disclosing a LIVE finding leaks it to sweepers. (2) PROTOTYPE — a 'pending lane' in radar.py/freshdeploy.py: subscribe to newPendingTransactions (Bitquery free key or a node) filtered to the deployer/upgrade-admin addresses radar already tracks, alerting before confirmation. (3) BACKLOG — wire eigenphi MEVScan MCP + Forta bot library as a SOURCING feed into the fan-out queue (fresh victim contracts -> DIG/shadow.py corpus) and mine Forta heuristics into recon.py reasoning-tier seeds. Raw mempool ingestion (own node / bloXroute) does NOT plug into anything that produces findings for us.

**Impact:** coverage (not speed). Flashbots Protect = small but real risk-removal on the disclosure path — high value the day we have our first live finding, near-zero before. Sourcing feeds (eigenphi/Forta) = modest coverage uplift to the freshness/fork-target pipeline. Pending-deployer watch = marginal: the few seconds saved rarely matter when L4 analysis takes hours. Net magnitude: small for finding-rate, moderate for disclosure-safety.

**Implementability:** Flashbots Protect: LOW effort (swap an RPC URL, no deps, free, mainnet-only) — a v1 is a one-line config in the PoC/rescue broadcast. Pending lane: MED effort — Bitquery free WS or a node subscription + a filter against radar's watched-address set + ledger dedup; node-based full mempool is HIGH opex and not worth it on Mac. eigenphi/Forta sourcing: MED — eigenphi MCP drops into the Claude fan-out cleanly, Forta rule-mining is manual curation. bloXroute/Blocknative: PAID at any real volume.

**Recommendation:** PROTOTYPE overall — but split: BUILD-NOW the Flashbots Protect private-broadcast path (free, one-line, closes a genuine disclosure-leak risk); PROTOTYPE the radar pending-deployer lane via Bitquery free key only if radar address-watching proves it earns its keep; BACKLOG eigenphi-MCP/Forta as sourcing+heuristic feeds; SKIP self-hosted node/bloXroute mempool ingestion — that's MEV-bot infra with no finding-density payoff for a solo white-hat. The timing edge is a mirage for our goal; the disclosure-safety and sourcing slivers are the only real wins.

---

## audit-findings-search

**State of the art.** The past-findings corpus is now large, free, and machine-readable — a step change for a solo engine. Two assets dominate: (1) FORGE (ICSE'26, MIT) — a bulk, CWE-labeled JSON dataset of 27,497 findings across 6,454 audit reports + the matching 81,390 Solidity files, downloadable wholesale; and (2) the now-live (Oct 2025) free Solodit API — a single POST endpoint over 50,000+ findings aggregated from Cyfrin/Sherlock/Code4rena/ToB/OZ with severity/firm/tag/protocol filters. Both directly serve two jobs OUR engine lacks: mining reasoning-tier detector seeds (T2/T3) from clustered real findings, and a "does this target share a known bug?" retrieval step. The semantic-match plumbing (pgvector + sentence-transformers) already exists as open reference code. This is the single best lever for the reasoning-tier automation gap and a cheap coverage multiplier vs our ~751-case DeFiHackLabs corpus.

**Tools:**
- **[STEAL] FORGE-Artifacts (ICSE'26)** — https://github.com/shenyimings/FORGE-Artifacts  (yes (MIT))
  Bulk vuln dataset: 27,497 findings / 6,454 audit reports / 6,579 DApps / 81,390 Solidity files, auto-classified into 296 CWE categories. Findings as structured files in dataset/results; contracts in dataset/contracts; reports via Cloudflare R2 or Google Drive. MIT.
- **[STEAL] FORGE-Curated** — https://github.com/shenyimings/FORGE-Curated  (yes (Apache-2.0))
  Manually-verified higher-quality subset of FORGE for benchmarking/eval. Use as ground-truth slice for shadow.py recall and for tuning detector precision against labeled real findings. Apache-2.0.
- **[STEAL] Solodit API (Cyfrin)** — https://docs.solodit.cyfrin.io/  (no (hosted, but free API + has solodit/solodit_content public mirror))
  Official free API over 50,000+ aggregated findings. POST https://solodit.cyfrin.io/api/v1/solodit/findings with header X-Cyfrin-API-Key (free key from account dropdown). Filters: keywords, severity, audit firm, tags, protocol category, language, quality score; plus get_finding/list_tags/get_statistics. Server-side cache 5min/1h/24h.
- **[LEARN-FROM] solodit-checklist-matcher** — https://github.com/hans-cyfrin/solodit-checklist-matcher  (yes (Docker Compose; needs pgvector + an embedding model — can drop OpenAI for local sentence-transformers))
  Reference impl: FastAPI + PostgreSQL/pgvector + sentence-transformers that semantically matches a security-issue description to checklist/finding items. Exactly the retrieval plumbing for a known-bug-match lane; swap checklist corpus for FORGE/Solodit findings.
- **[LEARN-FROM] search-solodit MCP server** — https://github.com/LyuboslavLyubenov/search-solodit-mcp  (yes)
  MCP wrapper exposing Solodit search to an agent — drop-in so the fan-out Claude agent can query past findings mid-triage without custom glue.
- **[STEAL] Code4rena org (raw findings repos)** — https://github.com/code-423n4  (yes)
  Per-contest *-findings repos: full judged/awarded reports as markdown, free bulk clone. Source-of-truth backfill where FORGE/Solodit lag the newest contests; pairs each finding with the in-scope source.
- **[LEARN-FROM] solodit/solodit_content** — https://github.com/solodit/solodit_content  (yes)
  Public content mirror behind Solodit — raw aggregated finding markdown without API rate limits for offline bulk mining.

**Techniques:**
- Bulk-mine FORGE by CWE cluster: group the 27,497 findings by CWE + protocol category, rank clusters by frequency*severity, and convert the top under-covered clusters (esp. T2/T3 economic/invariant) into recon.py detector specs or hypothesize.py INVARIANT_MENU seeds — data-driven detector backlog instead of one-off hack reads.
- Known-bug retrieval lane (RAG over findings): embed target's fetched source (function/contract chunks) with local sentence-transformers, index FORGE+Solodit findings in faiss/pgvector, retrieve top-k analog findings as a triage artifact feeding the L4 read — turns the reasoning-tier gap into 'here are 5 historically-similar bugs, check each'.
- Live known-bug check via Solodit API: at triage time, POST keyword/tag/protocol-category queries (e.g. fork base name + mechanism) to surface whether the exact pattern was already reported — cheap dedup so a known/fixed bug is killed before deep dive (matches the 'known bug != finding' rule).
- Corpus expansion for shadow.py: add FORGE-Curated verified findings (with their real victim source) as a second honest-recall corpus beyond DeFiHackLabs/DeFiVulnLabs, measuring recall on a far larger, CWE-stratified real-contract set.
- Quality-score + firm filtering: use Solodit's quality_score and audit-firm fields to weight which findings become detector seeds (high-signal firms first), avoiding noise from low-quality contest dupes.

**Applicability:** Three concrete integrations: (1) New offline miner toolkit/findings_mine.py that ingests FORGE JSON (MIT, one-time download), clusters by CWE*severity, and emits a ranked detector/invariant backlog into recon.py + hypothesize.py — directly attacks the WEAK reasoning-tier automation gap. (2) A known-bug-match step wired into the /hunt pipeline right after fetch_source.py and before the L4 read: embed target source, retrieve nearest FORGE/Solodit findings (faiss local, or Solodit API for freshest), attach as a VERIFY.md input and as a kill-gate ('already disclosed?'). Reuse solodit-checklist-matcher's pgvector+sentence-transformers code as the skeleton. (3) shadow.py gains FORGE-Curated as a second recall corpus. ledger.py can also auto-suppress leads whose Solodit query returns an exact prior disclosure.

**Impact:** Both, coverage-dominant. Coverage: corpus jumps from ~751 DeFiHackLabs cases to 27k (FORGE) / 50k (Solodit) labeled findings — roughly 35-65x more pattern material, with CWE stratification that exposes our T2/T3 blind spots. Speed: moderate — a known-bug retrieval step kills already-disclosed leads early and hands the L4 read concrete analogs, shortening time-to-verdict per target. Does NOT fix the freshness wall (these are historical), but materially raises per-target depth and detector breadth.

**Implementability:** Mixed, mostly low. FORGE ingest = LOW effort: download MIT JSON, parse, cluster — a day. Solodit API = LOW: free key, single POST endpoint with X-Cyfrin-API-Key, documented filters; thin wrapper in fetch/ledger flow. Known-bug RAG lane = MEDIUM: needs an embedding model (local sentence-transformers, no paid API required), a faiss or pgvector index, and source-chunking; solodit-checklist-matcher gives a working blueprint to fork rather than build from zero. Main cost is curating which CWE clusters convert to high-precision detectors vs reasoning-tier seeds (FP risk if naively regex'd). v1 = FORGE miner + Solodit known-bug query as a /hunt triage gate; RAG retrieval is a fast follow.

**Recommendation:** BUILD-NOW — FORGE bulk ingest + Solodit free API known-bug check are low-effort, free, and the highest-leverage move against our reasoning-tier coverage gap and known-bug dedup; PROTOTYPE the embedding-based retrieval lane (fork solodit-checklist-matcher) right after.

---

## defi-economic-tools

**State of the art.** The economic-attack tooling we do by hand (oracle-manip, flashloan PoCs, AMM price-impact, solvency) is now largely automatable by two mature, free, self-hostable stacks. (1) On-chain hybrid fuzzers — ItyFuzz (fuzzland, 1.1k stars, MIT, active Dec-2025) fork any chain at any block and auto-synthesize profitable exploits (flashloan + oracle + reentrancy oracles built in) at the BYTECODE level, which means it runs on UNVERIFIED contracts — directly hitting two of our named gaps (weak reasoning-tier economic automation + unverified blind spot). (2) Property-based invariant harness frameworks — Recon's Chimera / create-chimera-app give "write once, run on Echidna/Medusa/Halmos/Foundry" with an economic-invariant library, a direct upgrade to scaffold.py. The academic layer (POMABuster multi-tx oracle rules, A1/VERITE, PoCo) is mostly LEARN-FROM: A1 is closed-source, POMABuster is a stale notebook, but VERITE is a usable economic-bug benchmark for shadow.py. The state of the art is "fuzz on-chain state with infinite-money + price-oracle harnesses and let it find the economic path," not hand-modeling each one.

**Tools:**
- **[STEAL] ItyFuzz** — https://github.com/fuzzland/ityfuzz  ()
  Rust bytecode-level hybrid fuzzer (concolic+fuzz). On-chain mode forks any chain at a block, assumes infinite flashloan funds, and auto-generates exploits for precision-loss, fund-stealing, Uniswap pair misuse, oracle/price manipulation. Claims auto-exploit of >80% of historical hacks with zero prior knowledge; +44% bugs vs Echidna on Daedaluzz. MIT, 1.1k stars, actively maintained.
- **[STEAL] Recon Chimera + create-chimera-app** — https://github.com/Recon-Fuzz/create-chimera-app  ()
  "Write once, run everywhere" invariant-testing framework (chimera repo 158 stars, active Apr-2026) + Foundry starter that scaffolds the same property suite for Echidna/Medusa/Halmos/Foundry. Recon Handler Builder auto-generates target wrappers. The exact thing scaffold.py reimplements by hand.
- **[STEAL] immunefi forge-poc-templates** — https://github.com/immunefi-team/forge-poc-templates  ()
  Foundry templates for flashloan (Aave/Balancer/UniV2/V3), oracle-manip, and price-impact PoCs with a _executeAttack() callback pattern. Drop-in PoC scaffolding for the step after a DIG confirms an economic lead.
- **[LEARN-FROM] POMABuster** — https://github.com/DependableSystemsLab/POMABuster  ()
  S&P'24 engine detecting price-oracle-manipulation across MULTI-transaction attacks using stock-market manipulation first-principle rules; ~6.5x more POMAs than prior work, <1% FP. But it's a 7-star Jupyter notebook, stale since 2024 — value is the RULESET, not the code.
- **[LEARN-FROM] A1 agent + VERITE benchmark** — https://arxiv.org/abs/2507.05558  ()
  Agentic LLM exploit generator (Gervais/Zhou): 6 domain tools, validates only profitable PoCs on real chain state, 63% on VERITE. A1 itself is NOT open-source, but VERITE (27 DeFiHackLabs economic incidents) and the 6-tool decomposition are directly reusable for our fan-out + shadow corpus.
- **[LEARN-FROM] PoCo: Agentic PoC Exploit Generation** — https://arxiv.org/abs/2511.02780  ()
  Nov-2025 design for an agent that turns a vuln hypothesis into a validated Foundry PoC. No standout repo, but the agent-loop architecture is a blueprint for our Claude agent-per-target auto-PoC step.
- **[PAID-REF] Recon Pro (cloud fuzzing)** — https://getrecon.xyz/  ()
  Managed cloud Echidna/Medusa/Halmos/Foundry campaigns, 12.5k+ runs. Their Recon Fuzzer (Rust Echidna clone, 10x) and Magic (AI invariant orchestration) are the paid layer; the free path is Chimera + recon-extension self-hosted.
- **[LEARN-FROM] auto-gov / agent-based lending models** — https://github.com/xujiahuayz/auto-gov  ()
  RL/agent-based DeFi lending solvency + liquidation-cascade simulator (Aave/Compound-style). Reference for modeling collateral-factor / liquidation-threshold economic risk we currently eyeball.

**Techniques:**
- On-chain bytecode-level fuzzing: fork target at block N with infinite-money (flashloan) assumption and built-in price-oracle/balance comparators as the 'profit' objective — finds the economic path without a hand-written invariant, AND works on unverified contracts (no source needed).
- Write-once invariant harness (Chimera): author economic properties once (e.g. totalAssets>=totalSupply*price, bridge-minted<=locked, share-price-monotonic), then auto-run them on Echidna+Medusa+Halmos+Foundry instead of maintaining per-engine harnesses.
- Economic invariant menu tuned for hardened code: solvency, no-free-value, oracle-deviation-bound (OR/OD templates), liquidation-correctness, AMM k-invariant, round-trip-symmetry, share-price manipulation near-empty-vault.
- Multi-transaction oracle-manipulation detection rules (POMABuster): treat manipulation as cross-tx pump/dump on a price source, not a single-call check — extends our det_spot_oracle to a stateful heuristic.
- Profitability-validated PoC loop (A1/PoCo): only report a finding when an executed PoC extracts value on forked state — kills the 'code-bug but non-callable / non-profitable' FP class that already burned us (death.fun).
- Economic-bug recall measurement against a labeled corpus (VERITE) to honestly score reasoning-tier coverage, the same way shadow.py scores T0.

**Applicability:** ItyFuzz = a new on-chain ECONOMIC lane invoked by the hunt pipeline right after recon.py/forkdrift flags an oracle/AMM/lending/vault target: `ityfuzz evm -t <addr> -f --onchain-block-number <N>` against our Etherscan-v2 RPC, with the flashloan+oracle oracles on, output a candidate exploit trace -> feeds the DIG queue. Critically it ALSO unblocks the UNVERIFIED-contract gap (bytecode-level, no source). Chimera/create-chimera-app = rewrite scaffold.py's generator to emit a Chimera target so one property runs across all four engines (kills our per-engine harness drift) and ship a reusable economic-invariant library for hypothesize.py's INVARIANT_MENU. forge-poc-templates = the auto-PoC step after a DIG confirms a flashloan/oracle lead (templated _executeAttack). POMABuster rules = upgrade det_spot_oracle into a multi-tx stateful seed. VERITE = extend shadow.py with an ECONOMIC corpus so we measure reasoning-tier recall, not just T0. A1/PoCo = blueprint for the profitability-validated PoC gate in fan-out (only surface findings whose PoC extracts value on fork).

**Impact:** Both — large. ItyFuzz is the standout: it attacks our two worst gaps simultaneously (reasoning-tier economic automation + unverified-contract blindness) and converts hand-modeling into a fork-and-run job; realistically the single highest-leverage add for finding economic bugs that survive hardened code. Chimera is a coverage+maintainability multiplier on scaffold.py (one harness, 4 engines). VERITE+POMABuster are smaller, precision/measurement plays.

**Implementability:** ItyFuzz: MED effort, HIGH payoff. Mac/Rust binary (cargo/offchain installer), needs an archive RPC + our Etherscan-v2 key (have it). v1 = a thin toolkit/ityfuzz_lane.py wrapping the onchain CLI, triggered post-recon on economic targets, parse the exploit trace into the ledger/DIG queue. Caveats: onchain mode is noisy and RPC-hungry, best on EVM (doesn't fix non-EVM), and 'profitable trace' still needs L4 white-hat scope/callability review before disclosure. Chimera: MED — refactor scaffold.py templates to Chimera target shape; no license file on the repo (verify before vendoring, currently unlicensed = ask/fork carefully). forge-poc-templates: LOW — vendor templates, parameterize. POMABuster rules: LOW-MED (port heuristics, ignore the notebook). VERITE corpus: LOW — add to shadow.py. A1: not integrable (closed), design-only.

**Recommendation:** BUILD-NOW: prototype the ItyFuzz on-chain economic lane — it's the only tool here that automates reasoning-tier economic bugs AND reaches unverified contracts (our two biggest gaps), free/MIT/maintained. PROTOTYPE in parallel: migrate scaffold.py to Chimera (write-once, 4 engines) + vendor forge-poc-templates for the auto-PoC step. BACKLOG: POMABuster multi-tx oracle rules into det_spot_oracle, VERITE into shadow.py. SKIP as integrations (LEARN-FROM only): A1 (closed), auto-gov.

---

## storage-proxy-analysis

**State of the art.** The proxy/upgrade-safety tooling space is mature and almost entirely free/self-hostable, and OUR stack already ships the engine (Slither + Foundry) — we just aren't aiming it at this class. The canonical tool is `slither-check-upgradeability` (17 detectors: storage var-order collisions, function-id collisions, became/were-constant, missing init modifier, init front-run) which runs as a two-contract V1-vs-V2 diff. Native `forge inspect <C> storage-layout --json` gives a deterministic slot map we can diff with zero new deps. Modern ERC-7201 namespaced storage (OZ upgrades-core `validateUpgrade`) is the prevention pattern, so the live-finding opportunity is OLD-style sequential-layout proxies that upgrade unsafely. Transient storage (EIP-1153 tload/tstore) is a genuinely under-tooled new surface — ChainSecurity documented a TSTORE low-gas reentrancy class but no maintained detector exists, making it a clean greenfield for a recon.py rule. Bytecode-level collision detection for UNVERIFIED proxies exists only as abandoned research artifacts (Proxion, "Not your Type!").

**Tools:**
- **[STEAL] slither-check-upgradeability** — https://github.com/crytic/slither/wiki/Upgradeability-Checks  (yes / AGPL-3.0 (already installed))
  Ships inside Slither (already in our L2). 17 detectors run as a V1-vs-V2 / proxy-vs-logic diff: order-vars-contracts/proxy (storage collision), function-id-collision, became-constant/were-constant, missing-init-modifier, missing-calls (init front-run), variables-initialized. Source-required.
- **[STEAL] forge inspect storage-layout** — https://book.getfoundry.sh/reference/forge/forge-inspect  (yes / MIT-Apache (have it))
  Native Foundry command emitting deterministic JSON slot/offset/type map per contract. Diff two impls' JSON to flag any slot whose type/label changed (= unsafe upgrade) or appended-only (= safe). Zero new dependency, already on our Mac lane.
- **[STEAL] slither-read-storage** — https://github.com/crytic/slither/blob/master/slither/tools/read_storage/README.md  (yes / AGPL-3.0 (in Slither))
  Reads ACTUAL deployed storage values at a live address via RPC by computing slots from layout. Lets radar.py read a live proxy's real slots post-upgrade to confirm corruption/overlap, not just static diff.
- **[LEARN-FROM] OpenZeppelin upgrades-core** — https://github.com/OpenZeppelin/openzeppelin-upgrades  (yes / MIT)
  validateUpgrade / storage-layout comparator + ERC-7201 namespaced-storage rules. JS/Hardhat-oriented (awkward to call from our Python), but the comparison ruleset (gap shrinking, struct reordering, namespace slot derivation) is the reference spec to port into our diff logic.
- **[LEARN-FROM] sol2uml storage** — https://github.com/naddison36/sol2uml  (yes / MIT)
  `sol2uml storage <addr/dir>` renders slot-packing diagrams from source OR a verified address; 1.3k stars, MIT, maintained (pushed 2026-03). Good for human-eyeball triage of packing/collision during a DIG; not a programmatic gate.
- **[LEARN-FROM] Proxion** — https://github.com/Proxion-anonymous/Proxion  (partial / no license — cannot fork cleanly)
  Research tool that classifies proxy standard (1167/1822/1967/2535) and does collision detection INCLUDING a bytecode fallback for UNVERIFIED contracts — directly targets our unverified blind spot. But abandoned (2024, 3 stars, no license, anonymous); accuracy degrades without source.
- **[LEARN-FROM] ChainSecurity TSTORE-Low-Gas-Reentrancy** — https://github.com/ChainSecurity/TSTORE-Low-Gas-Reentrancy  (yes (PoC) / unlicensed reference)
  PoC + writeup of the EIP-1153 transient-storage reentrancy class (transient guard not reset, low-gas reenter). Stale repo (2023) but documents the exact pattern to encode as a new recon.py detector for tload/tstore misuse.
- **[SKIP] banteg/storage-layout** — https://github.com/banteg/storage-layout  (yes / no license, unmaintained)
  Readable EVM state diffs / full-contract storage enumeration in Python. Abandoned (2023, no license). forge inspect + slither-read-storage now cover this better.

**Techniques:**
- Two-impl storage-layout diff: pull V1 and V2 verified source via fetch_source.py, run `forge inspect storage-layout --json` on each, flag any slot where (type|label) changed in place = corruption, vs append-only = safe. Deterministic, no FP-prone heuristics.
- Live-upgrade collision radar: radar.py already slot-diffs on impl-upgrade — upgrade it to a SEMANTIC layout diff (old impl vs new impl) so it fires the moment a proxy upgrades with an incompatible layout. This is a freshness/timing edge: catch a bad upgrade as it lands, before the protocol notices.
- slither-check-upgradeability as a dedicated proxy-lane: auto-detect ERC-1967/1822/2535 proxy → run the 17 upgradeability detectors instead of (or alongside) generic L2.
- Transient-storage misuse heuristics for recon.py: tstore-set without matching tstore-clear at function exit; tload-gated guard reused across external-call boundary; transient state read after a call() — the EIP-1153 reentrancy class.
- ERC-7201 namespace verification: derive expected namespace slot keccak256(abi.encode(uint256(keccak256(id))-1)) & ~0xff and check declared @custom:storage-location matches — mismatch = silent collision in 'modern' code that looks safe.
- Bytecode-fallback proxy/standard classification (Proxion approach) for UNVERIFIED targets: detect 1167/1967/2535 signatures from runtime bytecode to at least TYPE an unverified proxy even when we can't read source.

**Applicability:** Three concrete integrations: (1) NEW proxy-lane in analyze.py — when fetch_source.py/forkdrift flags an ERC-1967/UUPS/Diamond proxy, route to `slither-check-upgradeability` (already installed, zero new dep) and a `forge inspect storage-layout --json` V1-vs-V2 diff; emits collision/var-order findings we currently miss entirely. (2) UPGRADE radar.py's existing impl-upgrade slot-diff into a SEMANTIC layout diff (old vs new impl JSON) — this turns a raw byte-diff into an exploitability verdict and is a live timing edge (fire on a bad upgrade as it lands). (3) NEW recon.py detector(s) for EIP-1153 tload/tstore misuse (transient guard not cleared / transient state across external call) — fills a real greenfield with no competing tool. Optionally feed slither-read-storage into a DIG to read the LIVE proxy's actual slots to confirm corruption before disclosure.

**Impact:** Coverage primarily: opens an entire vuln class (proxy storage collision + upgrade-unsafe changes + transient-storage reentrancy) we are currently blind to — sizable, since upgradeable proxies dominate live TVL. Secondary speed/freshness win: the radar layout-diff gives a timing edge (detect a corrupting upgrade at the block it lands), which directly attacks our #1 freshness bottleneck for one specific high-signal event type.

**Implementability:** LOW effort for the high-value pieces — Slither and Foundry are already in the stack, so the proxy-lane is mostly a router + JSON-diff (~1 day) and adds no deps. The radar semantic-diff is LOW-MED (reuse existing upgrade-detection hook, add layout-JSON comparison + a small type/slot-change ranker). The tstore/tload recon detectors are LOW (regex/AST heuristics matching our existing T0 detector style; gate FPs on missing tstore-clear at exit). HIGH effort / poor ROI: Proxion-style bytecode collision for unverified contracts (needs a decompiler we lack, abandoned unlicensed code) — defer. OZ upgrades-core is JS/Hardhat, so port its rules rather than shell out.

**Recommendation:** BUILD-NOW the proxy-lane (slither-check-upgradeability + `forge inspect storage-layout` V1/V2 diff) and 1-2 EIP-1153 tstore/tload recon detectors — both are near-free given installed tooling and open a class we have zero coverage on. PROTOTYPE the radar.py semantic layout-diff for a live-upgrade timing edge. BACKLOG slither-read-storage live-slot confirmation. SKIP Proxion bytecode fallback and banteg/storage-layout (unlicensed/abandoned, weak ROI vs. our unverified-decompile gap).

---

## diff-audit-drift

**State of the art.** "Hunt only the drift" is a mature, tooled workflow now. The canonical tool is lidofinance/diffyscan (MIT, ~140★, actively pushed June 2026): it pulls a contract's verified source from Etherscan-class explorers and diffs it file-by-file against a pinned GitHub commit, plus a default bytecode-comparison mode that locally compiles the GitHub sources and simulates constructor execution via eth_call to confirm the deployed runtime matches. Sourcify gives the same verified-source feed across all EVM chains with a free keyless API as a fallback/multi-chain source. The unverified-contract blind spot (OUR known gap) is partially answered by heimdall-rs decompilation — decompile-both-and-diff. The core leverage for us: an audit covers a specific commit/tag; the live deploy drifts from it; that drift is the highest-density bug zone (CLAUDE.md already notes "баги в audit-drift"), and it directly attacks the #1 freshness bottleneck because drift is, by definition, post-audit fresh code that no one re-reviewed.

**Tools:**
- **[STEAL] lidofinance/diffyscan** — https://github.com/lidofinance/diffyscan  (yes — MIT, pip/uv installable, pure Python, no SaaS)
  CLI that diffs Etherscan-verified source of a live address against a pinned GitHub commit/tag (exact hash, no floating refs), plus default bytecode binary-comparison (local solc compile + remote eth_call constructor sim vs deployed runtime). Python 3.11+/uv, config = {address, github url+commit+root, explorer host+chainid+apikey, optional constructor calldata/libs/evm-version}. --skip-binary-comparison, --prettify.
- **[STEAL] ethereum/sourcify (argotorg/sourcify)** — https://github.com/ethereum/sourcify  (yes — MIT; public API is free/keyless, can also self-host)
  Free keyless verified-source DB + APIv2 lookup across every EVM chain Sourcify recognizes; query by address+chainId or search all chains. Source feed when Etherscan-v2 lacks the contract or for chains we don't have keys on.
- **[LEARN-FROM] Jon-Becker/heimdall-rs** — https://github.com/Jon-Becker/heimdall-rs  (yes — MIT, single Rust binary)
  Rust EVM decompiler/CFG/selector-extractor for UNVERIFIED bytecode. Lets you decompile both the audited-but-unverified deploy and the live one (or recover function selectors) to diff when no verified source exists — directly targets our 'unverified = blind' gap.
- **[LEARN-FROM] banteg/storage-layout** — https://github.com/banteg/storage-layout  (yes — Python (Vyper/banteg tooling))
  Readable EVM storage-layout/state diffs, enumerate full contract storage. Useful to catch storage-collision / layout-shift on proxy upgrades — the dangerous class of drift that source-diff alone misses.
- **[LEARN-FROM] mds1/evm-diff** — https://github.com/mds1/evm-diff  (yes — MIT, Next.js)
  Diffs execution-level specs BETWEEN EVM CHAINS (precompiles/opcodes/gas), NOT two contracts. Marked early/'do not rely on yet'. Relevant only for cross-chain fork lanes (a contract safe on mainnet may drift in behavior on an L2).
- **[LEARN-FROM] theredguild.org diff methodology** — https://blog.theredguild.org/how-to-diff-smart-contracts-etherscan/  (n/a — blog)
  Red Guild writeup of the manual Etherscan-vs-GitHub diff workflow that diffyscan automates — good for the per-file fetch/locate/diff heuristics and gotchas (flattened vs multi-file, metadata hash).
- **[LEARN-FROM] aragon/diffyscan-workspace** — https://github.com/aragon/diffyscan-workspace  (yes)
  Thin wrapper repo showing diffyscan configs pinned to intended commit IDs — a template for how to structure per-target drift configs.
- **[SKIP] jmpark-eng36/evm-contract-differ** — https://github.com/jmpark-eng36/evm-contract-differ  (no — vaporware)
  Title promises bytecode-diff + proxy-upgrade watching, but the repo README is an LLM-generated placeholder ('Fast and reliable request handling library', process({key:value})) — no real implementation. Mirage.

**Techniques:**
- Audited-commit -> live-deploy diff: pin the commit/tag the audit report scoped, pull live verified source, diff, hunt ONLY changed functions (shrinks the read surface from whole-protocol to the drift).
- Bytecode binary-comparison: local solc compile of the GitHub commit + eth_call constructor simulation vs deployed runtime bytecode — catches silent post-verification swaps and metadata-only 'verified but not the audited code' deploys.
- Multi-source verified-source resolution: Etherscan-v2 primary, Sourcify keyless fallback, heimdall decompile for unverified — so the drift lane degrades gracefully instead of going blind.
- Storage-layout diff on upgrade: enumerate storage slots pre/post impl-upgrade to catch collision/shift bugs that source-diff misses.
- Drift -> function map -> targeted recon: parse diff hunks, map changed files to changed function bodies, run recon.py/L4 only on those (and their callers).
- Metadata-hash + flatten normalization before diff to kill false-positive churn (compiler-settings noise, import reordering).

**Applicability:** Three concrete integrations into named components: (1) NEW DRIFT LANE in forkdrift.py/analyze.py — `driftscan` wrapper that takes {live address, github repo, audited commit/tag}, shells diffyscan (or reimplements its fetch-locate-diff against Etherscan-v2/Sourcify which we already wire in fetch_source.py), then maps changed hunks to changed functions and feeds ONLY those to recon.py + the L4 read. This is the literal implementation of the engine's stated "копай только дрейф / баги в audit-drift" rule. (2) radar.py coupling — on an impl-upgrade slot-diff event (already detected 24/7), auto-pull the new verified source, diff vs the previously-cached verified source, and if the surface is non-trivial push a DIG into the fanout/DIG queue with the diff attached. Bytecode binary-comparison flags "verified but not the audited code" instantly. (3) freshdeploy.py data enrichment — when a new deploy from a watched deployer fingerprints as a fork of an audited base (forkdrift), run the drift diff vs the canonical audited tag automatically, so fork-with-mods gets triaged at deploy time. Sourcify becomes a secondary source feed alongside Etherscan-v2; heimdall-rs becomes the unverified-contract escape hatch (decompile-and-diff) for the engine's "unverified blind" gap.

**Impact:** both — large. Speed: collapses the read surface from a whole protocol to just the drifted functions (often 10x-100x less code to L4-read per target), the single biggest accelerator for a solo hunter. Coverage: directly attacks the #1 freshness wall — drift is post-audit code that, by construction, no auditor re-reviewed and that bounties DO cover (live deploy). Also adds an upgrade-time and deploy-time trigger (via radar/freshdeploy) so drift is caught when it's freshest, not weeks later.

**Implementability:** Medium effort, low new deps — diffyscan is MIT Python 3.11+/uv, same stack as recon.py; we already have Etherscan-v2 keys (fetch_source.py) and ledger/fanout plumbing. v1 (1-2 days): thin wrapper that (a) takes address+repo+commit, (b) calls diffyscan or our own fetch-locate-diff, (c) parses the unified diff, (d) maps changed files->changed function names, (e) hands that allowlist to recon.py and writes a DIG. v2: wire Sourcify fallback + bytecode binary-comparison + radar upgrade-trigger. The real friction (be honest) is SOURCING THE AUDITED COMMIT — audit reports state the scoped commit in prose/PDF, not machine-readable; v1 takes the commit as a manual arg, v2 can LLM-extract it from the audit PDF/README. Storage-layout diff and heimdall decompile-diff are separate later spikes (BACKLOG).

**Recommendation:** BUILD-NOW — wrap lidofinance/diffyscan into a drift lane in forkdrift.py/analyze.py (audited-commit -> live-source diff -> recon only on changed functions); it's MIT, matches our Python stack, and is the most direct lever we have on the freshness wall since drift is fresh, bounty-covered, un-re-audited code. Sourcify = BUILD-NOW as a secondary source feed; radar.py upgrade-diff coupling and heimdall unverified-diff = PROTOTYPE/BACKLOG.

---

## reachability-sourcing

**State of the art.** The reachability frontier has two fronts. (1) READABLE targets: Sourcify's APIv2 exposes a paginated, all-EVM-chains feed of verified contracts sorted newest-first (GET /v2/contracts/{chainId}?sort=desc&afterMatchId=...), effectively a real-time "a contract just became readable" firehose — directly attacking your #1 freshness bottleneck rather than your tooling. (2) UNREADABLE targets: heimdall-rs (Rust, fast) and shazow/whatsabi (TS, O(instructions), proxy-resolving) recover ABIs/selectors/decompiled Solidity from raw bytecode, turning your "unverified = blind" gap into at least selector-level reachability. The selector layer consolidated under Sourcify (4byte.sourcify.dev, ~4.7M sigs, absorbed openchain.xyz + 4byte.directory + etherface) gives high-coverage name recovery. All three legs are free/self-hostable.

**Tools:**
- **[STEAL] Sourcify APIv2 — GET /v2/contracts/{chainId}** — https://docs.sourcify.dev/blog/apiv2-lookup-endpoints/  (yes — public hosted API (free); full stack open-source (argotorg/sourcify) for self-hosting)
  Paginated feed of verified contracts per chain: sort=desc (newest first, default), limit max 200, afterMatchId cursor. Returns address, chainId, verifiedAt, matchId, creation/runtime match type. Chain-agnostic across all EVM chains. A polling source for newly-verified (therefore newly-readable) contracts.
- **[STEAL] shazow/whatsabi** — https://github.com/shazow/whatsabi  (yes — MIT, TS lib/CLI, runs local against any RPC)
  Recovers ABI (function+event selectors) and resolves proxies (EIP-1967/diamond/etc.) directly from on-chain bytecode, no source. Bounded O(instructions) static analysis, <15KB, viem/ethers compatible, autoload() with followProxies. Python port: bitrocks/whatsabi-py.
- **[STEAL] Jon-Becker/heimdall-rs** — https://github.com/Jon-Becker/heimdall-rs  (yes — open-source Rust binary, local; py bindings available)
  Rust EVM toolkit: decompile bytecode -> Solidity + ABI, CFG, calldata decode, storage dump. Faster/more accurate than Panoramix-class; experimental LLM postprocessing. heimdall-py (jalbrekt85/heimdall-py) for Python embedding.
- **[STEAL] 4byte.sourcify.dev (signature DB, ex-openchain.xyz)** — https://4byte.sourcify.dev/  (partial — public free API; dataset open but no documented one-shot bulk dump (cache via API))
  ~4.7M function/event signatures (absorbed openchain.xyz + 4byte.directory + etherface + Sourcify verified set). Implements the exact openchain API at api.4byte.sourcify.dev. Resolves selectors recovered by whatsabi/heimdall to human-readable signatures.
- **[LEARN-FROM] Etherscan-v2 getcontractcreation / verified-source (already integrated)** — https://docs.etherscan.io/etherscan-v2  (no — hosted API, free tier rate-limited)
  Single key -> 60+ chains for verified source + getcontractcreation (creator + creation tx, batch up to 5). You use this in fetch_source.py; pair with Sourcify feed so a target verified ONLY on Sourcify is still reached.
- **[LEARN-FROM] Blockscout API (Sourcify mirror)** — https://docs.blockscout.com/devs/verification/contracts-verification-via-sourcify  (yes — Blockscout self-hostable; public instances free)
  Open-source explorers (Optimism, Gnosis, Celo, many L2/L3s) auto-import Sourcify verifications and serve verified source via REST. Fallback reach for chains where Etherscan-v2 lags or doesn't cover.

**Techniques:**
- Newest-verified firehose: poll Sourcify GET /v2/contracts/{chainId}?sort=desc&limit=200 per watched chain, persist last matchId as cursor, emit contracts verified since last tick. Cross-reference verifiedAt vs creation time — freshly-deployed + verified-within-hours = prime fresh target (the exact freshness signal you lack).
- Three-source reach union per address: Etherscan-v2 -> Sourcify -> Blockscout. Mark UNREACHABLE only if all three miss, shrinking the blind set (Sourcify-only verifications are common on L2s Etherscan covers poorly).
- Bytecode-tier reachability: whatsabi autoload (proxy-resolved selectors + ABI) as cheap first pass; escalate to heimdall-rs decompile only when funded/active (gate on activity.py/legacy.py value) so you don't decompile dead code.
- Selector triage: run recovered selectors against 4byte.sourcify.dev; risky signatures (mint/sweep/withdraw/init/upgradeTo/delegatecall) on unverified-but-funded contract flags it for human decomp — recon-on-bytecode without source.
- Proxy follow-through: whatsabi proxy resolution reaches the IMPLEMENTATION when only the proxy is verified — pairs with radar.py impl-upgrade slot-diff to read the new impl the moment it's pointed to.

**Applicability:** (1) NEW freshdeploy.py data source — a "sourcify_feed" poller (cursor = last matchId per chain) emitting newly-verified contracts; a direct all-EVM-chain freshness lane feeding scout/radar, attacking the zero-live-findings freshness wall at its root. (2) NEW reach tier in fetch_source.py: after Etherscan-v2 miss, try Sourcify /v2/contract/{chain}/{address}, then Blockscout, before declaring UNREACHABLE. (3) NEW unverified lane in analyze.py: whatsabi (selectors+proxy) -> optional heimdall-rs decompile, value-gated, producing pseudo-source that recon.py T0 regex + selector-risk heuristics can scan. (4) radar.py: whatsabi proxy resolution to auto-read upgraded implementations.

**Impact:** both — coverage: union-reach + bytecode tier shrinks the UNREACHABLE/unverified blind set (largest concrete gain) and unlocks non-Etherscan L2s via Sourcify/Blockscout. speed/findings: the Sourcify newest-verified feed is highest-leverage — a continuous all-chain stream of freshly-readable targets is the most direct lever on your #1 bottleneck (freshness), potentially the difference-maker for a first live finding.

**Implementability:** Low-to-medium effort, no heavy deps. (a) Sourcify feed poller: ~half-day — HTTP + matchId cursor in a small state file, mirrors your radar cursor pattern; stdlib/requests. (b) Reach union in fetch_source.py: ~half-day, two HTTP fallbacks. (c) whatsabi lane: ~1 day — Node CLI shell-out (or whatsabi-py) + existing RPC; selector lookup one more HTTP call. (d) heimdall-rs: ~1 day incl. brew/cargo install on Mac (Rust binary, offline-friendly); gate behind value-check to bound cost. Risks: Sourcify/4byte public-API rate limits (cache + backoff); decompiled source is lossy — feed to detectors as hints, never ground truth for severity.

**Recommendation:** BUILD-NOW the Sourcify newest-verified feed as a freshdeploy/scout data source (directly attacks the freshness wall, half-day, free) plus the Etherscan->Sourcify->Blockscout reach-union in fetch_source.py. PROTOTYPE the whatsabi+heimdall unverified lane in analyze.py, value-gated, to chip at the unverified blind set. BACKLOG self-hosting Sourcify/4byte (only if public rate limits bite).

---

## benchmarks-coverage

**State of the art.** shadow.py today measures recall against DeFiHackLabs/DeFiVulnLabs — a small, T0-skewed, exploit-PoC corpus. The state of the art has moved well past SmartBugs-curated (143 contracts, DASP10) and SolidiFI (injected bugs): there are now large audit-derived labelled corpora that directly target the reasoning-tier gap. FORGE (ICSE'26) auto-built 27,497 CWE-classified findings across 81,390 real verified Solidity files from audit reports; Web3Bugs/"Demystifying Exploitable Bugs" labels Code4rena bugs as machine-auditable (L) vs semantic/logic (S) and empirically shows ~80% of high-sev bugs are logic bugs no static oracle can catch; EVMbench (OpenAI) scores agents on 120 high/critical Code4rena bugs. The honest move for our engine is two-tier benchmarking: a recall/FP regression gate on machine-auditable corpora (SmartBugs-curated + SolidiFI), and a separate "reasoning-tier blind-spot meter" on the L/S-split audit corpora so we can quantify exactly how much of the real bug surface our regex detectors structurally cannot reach.

**Tools:**
- **[STEAL] FORGE-Artifacts** — https://github.com/shenyimings/FORGE-Artifacts  ()
  ICSE'26 LLM-built dataset: 27,497 vulnerability findings across 81,390 verified Solidity files from 6,579 real audited projects, classified into 296 CWE categories; includes source code (dataset/contracts) + structured findings (dataset/results) + audit reports (R2/GDrive). MIT. 95.6% extraction precision vs human experts.
- **[STEAL] Web3Bugs (Demystifying Exploitable Bugs)** — https://github.com/ZhangZhuoSJTU/Web3Bugs  ()
  Code4rena audit-contest bugs with ground-truth labels split O/L/S = out-of-scope / machine-auditable / semantic-logic. The empirical proof that ~80% of high-sev bugs are functional/logic bugs unreachable by reentrancy-style oracles. bugs.csv + contests.csv + preserved contract source. MIT.
- **[LEARN-FROM] SmartBugs (framework + curated + wild)** — https://github.com/smartbugs/smartbugs  ()
  The orchestration runner that executes 20+ analysis tools (Slither, Mythril, etc.) over a dataset with unified SARIF-like output + DASP10 ground truth. smartbugs-curated = 143 labelled contracts (recall regression); smartbugs-wild = 47,398 real mainnet contracts (unlabelled, FP/throughput stress).
- **[STEAL] SolidiFI-benchmark** — https://github.com/DependableSystemsLab/SolidiFI-benchmark  ()
  Bug-injection benchmark: contracts with thousands of injected bugs at known locations + bug-free regions. Uniquely lets you measure FALSE POSITIVE rate and injection-recall precisely (DeFiHackLabs can't measure FP — it has no labelled-clean regions).
- **[LEARN-FROM] EVMbench** — https://arxiv.org/pdf/2603.04915  ()
  OpenAI agent benchmark: 40 curated Code4rena audit repos, 120 high/critical vulns with audit-firm ground truth; scores agents on detect/patch/exploit. The right yardstick for our fan-out Claude-agent-per-target workflow, not for regex detectors.
- **[LEARN-FROM] DAppSCAN** — https://github.com/InPlusLab/DAppSCAN  ()
  Large-scale dataset of weaknesses in real DApps mined from audit reports, SWC-mapped, with bytecode+source variants. Another audit-derived labelled corpus to widen shadow.py coverage beyond exploit PoCs.
- **[LEARN-FROM] awesome-smart-contract-datasets** — https://github.com/acorn421/awesome-smart-contract-datasets  ()
  Curated index of ~15 labelled corpora (ScrawlD real-world, DAppSCAN, Zenodo 4,364-contract/10-type set, VeriSmart-benchmarks, JiuZhou/HuangGai injection sets). Use as the menu for shadow.py corpus adapters.
- **[LEARN-FROM] DIVE multi-label dataset** — https://www.nature.com/articles/s41597-026-07025-5  ()
  2026 multi-label smart-contract vulnerability dataset (Scientific Data) — multiple co-occurring labels per contract, better for measuring detector co-coverage than single-label sets.

**Techniques:**
- Two-tier benchmarking: keep a strict recall+FP REGRESSION GATE on machine-auditable corpora (SmartBugs-curated DASP10 + SolidiFI injected), and a separate REASONING-TIER BLIND-SPOT METER on L/S-split audit corpora — report them as different numbers so we never overclaim.
- Use Web3Bugs L/S labels to compute an honest ceiling: 'recall on L (machine-auditable) bugs' is the only number our regex detectors can legitimately chase; the S-fraction quantifies the reasoning gap the CLAUDE.md already flags. This turns a hand-wavy 'weak T2/T3' into a measured percentage.
- Add FP measurement, which DeFiHackLabs cannot give: SolidiFI's bug-free regions + smartbugs-wild's 47k unlabelled mainnet contracts let you measure detector false-positive rate at scale (FP is our stated 'worse than a miss' priority).
- Map our 45 recon detectors to CWE via FORGE's 296-category taxonomy → produce a coverage matrix (which CWEs we touch, which we're blind to) → directly seeds the detector backlog and the hypothesize.py invariant menu.
- Score the fan-out Claude-agent workflow (not the regex layer) against EVMbench/Web3Bugs S-bugs to measure whether the reasoning tier actually finds logic bugs — the only fair benchmark for an LLM-agent hunter.
- Differential-tool baseline: run SmartBugs framework (Slither+Mythril+others) over the same corpus and diff against our recon.py output to find bugs the field catches that we miss (and our FP edge where we suppress their noise).

**Applicability:** Direct extension of shadow.py: add corpus adapters so `shadow.py --corpus forge|web3bugs|solidifi|smartbugs-curated` each emit a labelled run. Concretely — (1) FORGE adapter ingests dataset/contracts + dataset/results JSON to give a big CWE-labelled recall surface; (2) Web3Bugs adapter parses bugs.csv L/S/O so shadow.py prints two recall numbers (machine-auditable vs logic) — the blind-spot meter; (3) SolidiFI adapter adds a NEW FP/precision metric shadow.py currently lacks (DeFiHackLabs has no clean-labelled regions); (4) SmartBugs-curated stays as the fast DASP10 regression gate in CI alongside the 353 golden tests. Second integration: a CWE-coverage matrix script that maps the 45 recon detectors onto FORGE's taxonomy, feeding gaps into recon's detector backlog and hypothesize.py's INVARIANT_MENU. Third: EVMbench/Web3Bugs-S become the scoreboard for the fan-out agent workflow — the only honest way to measure the reasoning tier, not the regex layer. SmartBugs the framework is a LEARN-FROM reference for how analyze.py could orchestrate multi-tool runs with unified output.

**Impact:** Coverage, large. This won't itself produce live findings (freshness is still the wall), but it converts 'weak reasoning-tier' from a vibe into a measured number and 10-50x's the labelled surface shadow.py runs against (FORGE 81k files + Web3Bugs Code4rena vs current ~hundreds of DeFiHackLabs PoCs). Adds a FP/precision axis we currently can't measure at all. Net: better blind-spot targeting for the detector backlog + an honest reasoning-tier scoreboard.

**Implementability:** Med effort, low deps, all MIT/self-hostable. v1 (1 day): clone smartbugs-curated + SolidiFI, write a shadow.py adapter for each, wire SmartBugs-curated DASP10 into CI as a recall gate and SolidiFI as a first FP metric. v2 (2-3 days): FORGE adapter — it's ~tens of GB of contracts (R2/GDrive), so stage a sampled slice first; parse dataset/results to align findings-to-files; expect label noise since FORGE is LLM-built (95.6% precision, not 100%) so treat as fuzzy ground truth. v3: Web3Bugs L/S adapter (small, clean CSVs — easy) to emit the two-number blind-spot meter; CWE-coverage matrix script over recon detectors. EVMbench is an agent harness, heavier and partly OpenAI-tied — treat as a target to score the fan-out workflow against, not a CI gate. Main risk: corpus solc-version drift and FORGE label noise; mitigate by scoping recall claims to the reachable/compilable slice exactly as shadow.py already does (the 'HONEST recall' discipline).

**Recommendation:** BUILD-NOW for SmartBugs-curated + SolidiFI + Web3Bugs adapters in shadow.py (cheap, adds the missing FP axis + an honest reasoning-tier blind-spot number); PROTOTYPE the FORGE adapter + CWE-coverage matrix (big payoff for detector-backlog targeting, but large download + LLM-label noise warrant a sampled v1); BACKLOG EVMbench as the eventual scoreboard for the fan-out agent tier.

---

## triage-automation

**State of the art.** The candidate→confirmed-PoC loop — our slowest manual step — is now a solved-ish research problem for SINGLE-contract bugs. The dominant pattern is an agentic ReAct loop: an LLM with `forge build`/`forge test` as tools iterates against compiler+trace feedback in a Docker/fork sandbox until a PoC compiles and its assertions pass. Frontier models hit 65-92% well-formed-PoC rates (o3/Gemini 2.5 Pro lead) but stay weak on cross-contract/multi-step economic chains — which maps exactly onto our T2/T3 reasoning gap. Two open-source repos (PoCo, MIT; Quimera, AGPL) implement this end-to-end against Foundry, and the strongest validation idea — Proof-of-Patch (PoC must pass on vulnerable code AND fail on the patch) — is directly stealable. On triage/false-DIG cutting, the literature converges on an auditor/critic adversarial split plus a sharp, cheap finding: redacting the "this is a bug because…" framing before verification recovers 25-30% of detections lost to confirmation bias.

**Tools:**
- **[STEAL] PoCo (ASSERT-KTH/PoCo-public)** — https://github.com/ASSERT-KTH/PoCo-public  (yes (MIT))
  Agentic PoC generator: inputs = vulnerable contract + auditor-written NL vuln annotation + target path; output = executable Foundry test with assertions. ReAct loop (Claude reasoning + glob/grep/read/write + forge compile/test tools, Docker isolation) iterates until it compiles & passes. Validated by Proof-of-Patch (pass on buggy, fail on patched). o3 83% / Sonnet-4.5 65% well-formed; 32 correct exploits vs 13 workflow-baseline. MIT, paper+dataset (Proof-of-Patch, 23 real 2022-25 bugs from Solodit) public.
- **[STEAL] Quimera (gustavo-grieco/quimera)** — https://github.com/gustavo-grieco/quimera  (yes (AGPL-3.0 — copyleft; fine for solo/internal use))
  Data-driven economic-exploit generator. Works on DEPLOYED contracts via Etherscan+fork (or local Foundry). Loop: write profit goal ('balance up after flashloan') → LLM writes/improves Foundry test → run, read trace, check profit → feed failed trace back. Re-discovers DeFiHackLabs exploits (APEMAGA, VISOR, FIRE) with Gemini 2.5 Pro. Local-LLM (ollama) + 'manual mode' (no API key) supported. 94 stars, actively maintained (Dec 2025).
- **[LEARN-FROM] ReX / 'Prompt to Pwn'** — https://arxiv.org/abs/2508.01371  (no (paper only))
  Execution-grounded AEG framework over Foundry. Three reusable automation aids: prompt refactoring, compiler-feedback loop, templated test harnesses. Up to 92% on single-contract bugs (Gemini 2.5 Pro / GPT-4.1); explicitly weak on cross-contract. 38+ real-incident PoC dataset. No code released.
- **[LEARN-FROM] aether (l33tdawg/aether)** — https://github.com/l33tdawg/aether  (yes (MIT))
  Python framework: Solidity analysis → findings → Foundry PoC → validate on MAINNET-FORK. Useful reference for the fork-validation harness wiring (how to spin a forked exploit env per finding). MIT, 57 stars, updated Apr 2026.
- **[LEARN-FROM] Confirmation Bias in LLM Security Review** — https://arxiv.org/html/2603.18740v1  (yes (method, free))
  Empirical: biasing framing (PR/commit metadata, 'this is the bug' hints) HIDES real vulns from review agents. Redacting PR descriptions recovers 68.75% of missed detections; an 'ignore the metadata' instruction pushes detection to 94%. Cheap, directly-applicable verify-prompt hygiene.
- **[LEARN-FROM] Sifting the Noise: LLM Agents for FP Filtering** — https://arxiv.org/html/2601.22952v1  (yes (method))
  Comparative study of LLM-agent configs for filtering SAST false positives — informs how to build our adversarial critic gate (which agent topology actually cuts FPs vs adds latency).
- **[LEARN-FROM] GPTLens (auditor/critic pattern)** — https://arxiv.org/pdf/2310.01152  (yes (method))
  Two-stage adversarial LLM split: auditor proposes vulns with reasoning, critic scores validity to suppress FPs. The canonical adversarial-verify topology to port into our DIG-promotion gate.
- **[SKIP] SmartGuard (advaitbd/smartguard)** — https://github.com/advaitbd/smartguard  (no (no license))
  Multi-agent auditor with self-correcting PoC execution (auto-runs & repairs generated Foundry tests). Small (8 stars, no license) — concept reference only, not a dependency.

**Techniques:**
- Agentic forge-feedback loop: give Claude `forge build`/`forge test` as tools in a sandbox and let it iterate on compiler errors + call traces until assertions pass — replaces scaffold.py's one-shot static harness. This is the single highest-leverage steal.
- Proof-of-Patch validation: when a fix/patch exists (or we synthesize the obvious one-line guard), a candidate PoC is only 'logically correct' if it PASSES on the vulnerable code and FAILS on the patched code — kills PoCs that 'pass' for the wrong reason.
- Trace-feedback profit-oracle loop (Quimera): for economic/T2 bugs, define an invariant ('attacker balance increases') and feed failed-attempt traces back to the model — automates the reasoning-tier search we currently do by hand.
- Auditor/critic adversarial split (GPTLens): a separate critic agent must REFUTE each recon/hypothesize candidate before it's promoted to a DIG — cuts false-DIGs at the gate.
- Confirmation-bias redaction: strip the 'this is a bug because…' framing from the candidate before the verify pass and re-derive from raw code — recovers detections and avoids rubber-stamping our own hypothesis.
- Templated test harnesses + prompt refactoring (ReX) to raise first-attempt compile rate; honest scope limit — all of these are strong on single-contract, weak on cross-contract chains.

**Applicability:** PoCo's ReAct loop is a near-drop-in upgrade to scaffold.py: today scaffold emits a static Foundry/Echidna harness; instead, add an "auto-PoC step after a DIG" that runs an agentic loop (Claude + forge build/test as tools, fork via fetch_source.py-sourced source, Docker/anvil sandbox) and iterates on compiler+trace feedback until `forge test` passes the exploit assertion. The DIG hypothesis we already write IS PoCo's required auditor annotation — zero new input format. Proof-of-Patch becomes a new pass/fail signal in ledger.py (PoC must fail on the patched variant). Quimera plugs into the T2/economic gap as a separate "economic auto-PoC" lane: point it at a live verified target (Etherscan/fork it already supports) with a profit invariant from hypothesize.py's INVARIANT_MENU. The adversarial critic (GPTLens) + confirmation-bias redaction become a new pre-DIG gate in analyze.py / a VERIFY.md step: a critic agent in the fan-out must refute each candidate (with framing redacted) before it earns a DIG slot — directly attacking false-DIGs.

**Impact:** both. Speed: the agentic forge loop can compress the candidate→PoC step from hours of manual harness-writing to minutes for single-contract bugs (research shows 65-92% auto-success on exactly that class). Coverage: Quimera's trace-feedback loop is real, if noisy, automation for the reasoning-tier economic bugs we currently can't scale — plausibly turning some T2 hypotheses into confirmed PoCs we'd otherwise drop. The adversarial critic + redaction gate raises precision (fewer wasted DIGs) at modest latency cost. Honest ceiling: all of it stays weak on cross-contract/multi-step chains, so the freshness wall (no live targets) is untouched — this accelerates the loop AFTER a candidate exists, it does not source candidates.

**Implementability:** Med effort, low new deps (Foundry + Claude already in-stack). v1 of the PoCo loop: fork PoCo's tool-loop (it's MIT, Claude-native, Docker) and rewire its file/forge tools at scaffold.py's harness output — ~1-2 days for a working agentic 'confirm this DIG' command; reuse our existing forge --offline/brew solc Mac-lane. Quimera is `pip install git+…`, runs against local LLM/ollama or manual-mode (no API cost) — a half-day spike to point it at one fetched economic target; AGPL means keep it as a separate invoked tool, don't merge its code into our tree. The adversarial-critic + redaction gate is pure prompt engineering inside the existing Claude fan-out — hours, not days. Main risk: agentic loops burn tokens and can loop on compile errors — cap iterations and gate on Proof-of-Patch to avoid false-confirms.

**Recommendation:** BUILD-NOW: fork PoCo's agentic forge-feedback loop into scaffold.py as the "auto-PoC after a DIG" step (MIT, exactly our slow manual step, our DIG note = its annotation input) + add the cheap adversarial-critic/redaction gate to cut false-DIGs. PROTOTYPE Quimera as a separate economic-exploit lane for the T2 gap. LEARN-FROM ReX/aether/GPTLens. SKIP SmartGuard (unlicensed toy). Caveat: all of this speeds the post-candidate loop only — it does not touch the #1 freshness bottleneck.

---

## wildcard-emerging (2026 techniques for asymmetric solo bug-finding edge)

**State of the art.** Three things genuinely moved in 2026 that map onto OUR exact gaps. (1) Agentic exploit/PoC benchmarks went public and good: OpenAI+Paradigm's EVMbench harness (Foundry+Slither+codex in Docker) plus GoPlus's real-incident corpus give us drop-in datasets to MEASURE the reasoning-tier (T2/T3) recall we currently can't — frontier agents now exploit ~70% of Code4rena fund-draining bugs, so the bar and the test set both exist. (2) Agentic auto-PoC is now a published method (PoCo, SmartPoC) — turn a DIG into a validated Foundry exploit in a loop, directly attacking our "zero live findings" conversion wall. (3) EIP-7702 created a brand-new, under-tooled CONTRACT-level bug class (not just phishing): vaults/pools that assume msg.sender is a plain EOA or that a delegate can't make arbitrary calls (IPOR Fusion $336K, a QNT pool drain) — a freshness edge because almost no static tool models delegated-EOA callers yet. Skeptical note: the 100+ "ai-smart-contract-auditor" GitHub repos are near-universally GPT-wrapper toys; ignore them.

**Tools:**
- **[STEAL] paradigmxyz/evmbench** — https://github.com/paradigmxyz/evmbench  (yes / Apache-2.0)
  OpenAI+Paradigm open benchmark+agent harness for finding AND exploiting smart-contract bugs; 117 curated vulns from ~40 audits (mostly Code4rena), Dockerized base image bundles Foundry+Slither+codex; detect mode emits parseable {"vulnerabilities":[...]} JSON. Apache-2.0.
- **[STEAL] GoPlusSecurity/ai-auditing-benchmark** — https://github.com/GoPlusSecurity/ai-auditing-benchmark  (yes / Apache-2.0)
  Real-world exploit corpus: vulnerable source per incident folder {YYYYMMDD}_{Project}, in benchmark_complete (full deps) + benchmark_simplified (vuln fn only) forms, CSV metadata with date/type/tx-hash. Apache-2.0, fresh (updated 2026-06-27).
- **[STEAL] trailofbits/skills** — https://github.com/trailofbits/skills  (yes / CC-BY-SA-4.0)
  ToB's production Claude Code audit skills: variant-analysis (find similar bugs across a codebase), property-based-testing, mutation-testing (mewt/muton), trailmark (code-graph -> protocol verification + mutation-triage), static-analysis (CodeQL/Semgrep/SARIF). CC-BY-SA-4.0.
- **[LEARN-FROM] PoCo (agentic PoC exploit generation)** — https://arxiv.org/abs/2511.02780  (n/a (paper))
  Monperrus et al. agentic loop that auto-generates working Foundry PoC exploits for contract vulns (find->draft exploit->run->repair). Method paper; no public repo located yet — use as architecture blueprint.
- **[LEARN-FROM] SmartPoC** — https://arxiv.org/pdf/2511.12993  (n/a (paper))
  Generates executable+validated PoCs from natural-language bug reports — complements PoCo for the 'I have a hypothesis, prove it' step.
- **[LEARN-FROM] gmh5225/evmbench-certora-agent-harness** — https://github.com/gmh5225/evmbench-certora-agent-harness  (yes (check repo license))
  EVMBench wired to an iterative Certora (formal-verification) agent loop — a worked example of closing the reasoning-tier loop with a prover instead of just an LLM.
- **[LEARN-FROM] blocksecteam/ReEVMBench** — https://github.com/blocksecteam/ReEVMBench  (yes (check repo license))
  BlockSec's re-execution benchmark variant — second reference harness for grounding agent exploit claims in actual on-chain replay.
- **[LEARN-FROM] EIP-7702 Phishing/Attack analysis (arXiv 2512.12174) + CrimeEnjoyor on-chain detection** — https://arxiv.org/abs/2512.12174  (yes (heuristics, build ourselves))
  Characterizes SET_CODE (0x04) delegation attack surface: 150k+ auth/exec events, 26k addresses, small set of reused malicious delegate-contract families; basis for an on-chain delegate-target scanner and for the contract-side assumption-break class (IPOR Fusion $336K, QNT pool).
- **[LEARN-FROM] Liquidity-Exhaustion Attacks on Intent Bridges (arXiv 2602.17805)** — https://arxiv.org/html/2602.17805v1  (yes (invariant seeds))
  Models solver-profitability / liquidity-exhaustion exploits across 3.5M cross-chain intents (deBridge flagged with 210 historical instances) — concrete economic invariants for the intent/solver class.

**Techniques:**
- Reasoning-tier recall measurement: load EVMbench + GoPlus corpora as new shadow.py lanes (benchmark_simplified for cheap iteration, benchmark_complete for cross-contract). For the first time we get a HONEST T2/T3 number, not just T0 DeFiHackLabs token-class recall.
- Lexical-bias guard: 2026 benchmarking (arXiv 2605.11163) shows LLM/regex recall collapses when identifiers are sanitized — run shadow.py twice, once with variable names stripped/renamed, to catch detectors that are pattern-matching names not logic. Directly hardens recon.py FP/recall claims.
- Agentic auto-PoC after a DIG: wrap scaffold.py's Foundry harness in a PoCo-style draft->forge test->read-trace->repair loop (Claude agent) so a surviving DIG candidate auto-produces a validated exploit or self-refutes. Converts hypotheses to evidence without manual harness writing.
- New bug class — delegated-EOA assumption breaks: flag (a) access control that trusts msg.sender being a non-contract / tx.origin==msg.sender, (b) delegate/bundler contracts that expose arbitrary external call with admin-reachable state, (c) isContract()/extcodesize gates now bypassable by 7702 EOAs. This is the IPOR Fusion pattern.
- On-chain freshness via SET_CODE scanning: watch 0x04 set-code txs and cluster delegate-target contracts; a newly-popular delegate family = either a fresh drainer or a fresh integration target to audit before others.
- Formal-verification close-out: copy the evmbench-certora-agent-harness idea — when an LLM/recon flags an economic invariant, hand it to Halmos (already in scaffold.py) in an agent loop for a proof/counterexample instead of trusting the model.

**Applicability:** EVMbench + GoPlus -> two new corpus lanes in shadow.py (`--corpus evmbench`, `--corpus goplus`), each split simplified/complete, giving the first real reasoning-tier recall metric against OUR #1 known gap. EIP-7702 -> (1) new recon.py detectors det_7702_eoa_assumption (msg.sender/tx.origin/extcodesize trust) + det_delegate_arbitrary_call (bundler/delegate exposes attacker-reachable call) — fresh class, low competition; (2) a radar.py SET_CODE-delegation lane + a freshdeploy.py data source that surfaces newly-clustered delegate-target contracts. PoCo/SmartPoC -> a new autopoc step invoked by /hunt after a DIG survives kill-gates, built on existing scaffold.py Foundry generator as a draft->run->repair agent loop. trailofbits/skills variant-analysis + trailmark -> drop into the fan-out workflow as the per-target 'find siblings of this bug across the codebase' and code-graph step; mutation-testing skill validates that our Echidna/Medusa harnesses actually catch the bug they claim. Intent/solver + liquidity-exhaustion -> new seeds in hypothesize.py INVARIANT_MENU (solver-profitability bound, fill<=locked, batch-settlement conservation).

**Impact:** both. Coverage: EVMbench/GoPlus corpora + lexical-bias test finally quantify and grow the reasoning-tier (T2/T3) gap that is our biggest blind spot — potentially the difference between ~75% T0-only recall and a measured economic-bug number. EIP-7702 adds a whole 2026 bug class with live bounty relevance and little competing tooling (asymmetric). Speed: auto-PoC-after-DIG attacks the 'zero live findings' conversion wall — turning hypotheses into validated exploits is where the funnel currently dies; realistically the single highest-leverage speed item.

**Implementability:** LOW effort / high value: wiring EVMbench + GoPlus as shadow.py corpora is just a loader + path mapping (both Apache-2.0, structured folders/CSV) — a day each, no new deps. LOW-MED: the two EIP-7702 recon detectors are regex/heuristic in our existing det_* style (1-2 days + golden tests); the radar SET_CODE lane needs an Etherscan-v2/RPC log filter on type-0x04 txs (med, fetch_source.py already has the key for 60+ chains). MED-HIGH: auto-PoC loop is real engineering — needs an agent harness around forge with trace parsing and a repair budget; PoCo/SmartPoC give the blueprint but no public code, so v1 is a constrained Claude loop (cap iterations, fork-pin block) reusing scaffold.py. LOW: trailofbits/skills are plug-in Claude Code skills — install and call from fan-out, attribution required (CC-BY-SA). Intent invariants are config-only seeds in hypothesize.py (hours).

**Recommendation:** BUILD-NOW: add EVMbench + GoPlus corpora to shadow.py (cheap, measures our #1 gap today) and ship the two EIP-7702 recon detectors + radar SET_CODE lane (fresh class, low competition, live 2026 bounties — the asymmetric freshness edge). PROTOTYPE: auto-PoC-after-DIG agent loop on scaffold.py (highest-leverage on the zero-findings wall, but real eng — timebox a v1). BACKLOG: intent/solver invariant seeds in hypothesize.py and Halmos-in-the-loop close-out. LEARN-FROM (install, don't fork): trailofbits/skills for variant-analysis + mutation-triage in fan-out. SKIP: the 100+ generic 'ai-smart-contract-auditor' GPT-wrapper repos.

---

## symbolic-formal (reasoning-tier T2/T3 coverage the regex detectors miss)

**State of the art.** For a solo hunter, "formal verification" splits into two tiers with very different cost. The HEAVY tier (Kontrol/KEVM, Certora Prover) buys soundness but costs days-to-weeks of spec writing (K lemmas / CVL rules) per target — not usable in a per-target triage loop, and Certora is paid besides. The USABLE tier is bounded symbolic execution that reuses what you already have: Halmos runs your Foundry tests symbolically (no new language, pip-installable, FP-safe because it returns concrete counterexamples), and hevm does bytecode-level symbolic execution plus the standout feature for us — `hevm equivalence`, which mechanically proves whether two bytecode blobs behave identically. Both attack exactly OUR weak spot: economic/invariant bugs that recon.py's regex can't see, but where you can state a one-line property. The freshness wall is unchanged (these find bugs faster on a target you already have, they don't source targets), and full automation without any spec is still a myth — but a 10-line symbolic invariant per DIG is realistic same-day work.

**Tools:**
- **[STEAL] hevm** — https://github.com/argotorg/hevm  (yes (AGPL-3.0; static binaries + nix; Mac install fiddly = Haskell))
  Haskell EVM for symbolic execution, symbolic Foundry-test running, and bytecode EQUIVALENCE checking (Z3/CVC5/Bitwuzla). Operates on RAW BYTECODE via `hevm symbolic --code` — no source needed. EF-maintained, pushed 2026-06-27 (active today).
- **[STEAL] Halmos** — https://github.com/a16z/halmos  (yes (AGPL-3.0; `pip install halmos` / uvx — Mac-clean))
  Symbolic test runner for Foundry by a16z. Reuses your Solidity tests, adds svm_create* symbolic-input cheatcodes; bounded (loop/depth limits) but returns concrete counterexamples so verdicts are FP-free. No new language, no API key. 1k stars, pushed 2025-08.
- **[LEARN-FROM] Kontrol (KEVM)** — https://github.com/runtimeverification/kontrol  (yes (BSD-3; heavy — kup/docker))
  Runtime Verification's FV on top of Foundry+KEVM. Sound, compositional, supports loop invariants/lemmas — but needs K-framework familiarity for hard proofs and heavy docker; pushed 2026-06 (active).
- **[PAID-REF] Certora Prover + CVL** — https://docs.certora.com/  (no (cloud SaaS; free only in contests))
  Industrial SMT prover with declarative CVL spec language; strongest soundness, but commercial. Free access exists only via Certora verification CONTESTS, not a standing self-host tier.
- **[LEARN-FROM] Gambit (Certora)** — https://github.com/Certora/gambit  (yes (open source; Rust))
  Open-source Solidity MUTATION generator. Mutate a target, re-run your harness/detectors; surviving mutants = coverage holes. Decoupled from the paid Prover.
- **[LEARN-FROM] Mythril** — https://github.com/Consensys/mythril  (yes (MIT; pip/docker))
  Mature bytecode symbolic-execution vuln scanner (taint + SMT) that runs on on-chain BYTECODE directly. Dated detector set, slow/noisy, but works where there's no source. 4.2k stars, pushed 2026-04.
- **[LEARN-FROM] Pyrometer** — https://github.com/nascentxyz/pyrometer  (yes (open source; Rust))
  Rust range/bound-analysis + abstract interpretation for Solidity — shows reachable branches and variable value-ranges (good for over/underflow + path-feasibility). Beta, pushed only Feb 2025 (maintenance risk).

**Techniques:**
- Equivalence-as-triage: in forkdrift.py, after identifying a fork of an audited base, run `hevm equivalence <base_runtime> <fork_runtime>` to MECHANICALLY enumerate divergent function paths + the calldata that distinguishes them — turns 'substantive diff' from a manual read into a proof obligation, and the divergences ARE the audit targets.
- Bounded symbolic invariant per DIG: convert a hypothesize.py / deepdive bespoke-invariant seed into a Halmos test (check x*y>=k, no-free-mint, share-price-monotonic, sum-of-balances==totalSupply) with svm_ symbolic inputs — bounded proof or a concrete counterexample, same-day, no spec language.
- Symbolic auto-PoC: when a Halmos/hevm property fails it returns concrete calldata; feed that straight into a Foundry PoC (scaffold.py) as the witness — closes the DIG->PoC gap automatically instead of hand-deriving the exploit input.
- Bytecode symbolic for the UNVERIFIED gap: `hevm symbolic --code <runtime>` / Mythril on raw bytecode finds assertion/overflow/selfdestruct/arbitrary-call reachability with zero source — a partial answer to today's 'unverified = blind' wall.
- Mutation-gated detector calibration: use Gambit to mutate known-good targets and re-run recon.py + the symbolic harness; surviving mutants quantify reasoning-tier blind spots and feed shadow.py/calibrate.py honestly.
- Solver-portfolio + bounds discipline: run Bitwuzla alongside Z3 and cap loop/depth — the practical difference between a 5-min symbolic check and an unbounded hang on a solo laptop.

**Applicability:** Three concrete integrations, ranked: (1) `hevm equivalence` becomes a new TRIAGE step inside forkdrift.py — feed it the audited-base runtime bytecode vs the live fork's runtime (both already reachable via fetch_source.py), and it returns the exact diverging calldata; this directly upgrades our #1 lane (drift) from eyeballing to proof. (2) A new symbolic engine path in scaffold.py: it already lists Halmos as a target, so the missing piece is a GENERATOR that turns hypothesize.py INVARIANT_MENU seeds + deepdive bespoke-invariants into Halmos `check_`/svm_ tests — this is the reasoning-tier automation gap named in our KNOWN GAPS. (3) An auto-PoC step after a DIG: a failing Halmos/hevm property emits concrete witness calldata that drops straight into a Foundry PoC. Secondary: a Mythril/`hevm symbolic --code` bytecode lane in analyze.py for UNVERIFIED targets (today blind), and Gambit-driven mutation in calibrate.py/shadow.py to measure reasoning-tier recall.

**Impact:** Coverage: high — this is the most direct hit on our explicitly-weak T2/T3 invariant tier (the bugs regex structurally cannot see) and a partial crack at the unverified-bytecode blind spot. Speed: medium-positive on the drift lane (hevm equivalence replaces slow manual diff-reading with a proof + witness) but medium-negative per-invocation elsewhere (symbolic runs are minutes-to-timeout, need bounds). Net: meaningfully widens what we can CONFIRM/refute per live target; does NOT move the freshness wall, which remains the binding constraint on findings.

**Implementability:** Halmos: LOW effort — `pip install halmos`, Mac-clean, reuses Foundry; v1 = wire as scaffold.py engine + a seed->test template, ~1-2 days. hevm equivalence: MED — static binary or nix on Mac is fiddly (Haskell toolchain), but the CLI itself is one command; v1 = forkdrift.py shells out `hevm equivalence` on two fetched runtimes and parses divergences, ~2-3 days incl. install pain. Mythril bytecode lane: LOW-MED (pip/docker, but noisy — needs FP-filtering through ledger.py). Gambit: MED (separate from paid Prover, but mutation runs are slow). Kontrol: HIGH (K framework + docker + real spec time) — BACKLOG only. Certora: blocked by cost/cloud — SKIP for standing use, opportunistically free in contests. Deps to budget: an SMT solver (Z3 + ideally Bitwuzla) and strict loop/depth bounds to avoid laptop hangs.

**Recommendation:** PROTOTYPE — Build two things now in priority order: (1) `hevm equivalence` as a forkdrift.py triage step (highest leverage: proves drift + hands you the witness on our best lane), (2) a hypothesize.py-seed -> Halmos-test generator as the scaffold.py symbolic engine (closes the named reasoning-tier automation gap, trivial install). Mythril/`hevm --code` bytecode lane and Gambit mutation are BACKLOG; Kontrol BACKLOG; Certora SKIP for standing use (contest-only).

---

## decompilers-unverified

**State of the art.** The unverified-contract gap is solvable today with a mature, free, self-hostable toolchain — you don't need Dedaub's paid API for a v1. Three MIT tools cover the spectrum from cheap-fast to deep: whatsabi (ABI + selectors + proxy resolution from bytecode, TS lib), evmole (selectors + argument types + state mutability + storage layout, Rust core with Python/JS bindings, very fast), and heimdall-rs (full pseudo-Solidity decompile + disassemble + CFG + storage dump, Rust CLI). Dedaub remains the best-quality decompiler (free for manual individual use via web app, API is paid) and is the right escalation for a hot target. The honest caveat: most in-scope bounty targets ship verified source, so the realer payoff of a bytecode lane is COVERAGE for your freshdeploy/radar lanes (new unverified deploys from watched deployers/factories) and copycat/fork detection — not a big bump in classic verified-source findings.

**Tools:**
- **[STEAL] heimdall-rs** — https://github.com/Jon-Becker/heimdall-rs  ()
  Rust EVM toolkit for unverified contracts: `decompile` (pseudo-Solidity + solidity/yul + ABI JSON output), `disassemble`, `cfg` (control-flow graph), `dump` (storage), `decode` (calldata/traces). 1.5k stars, MIT, actively maintained (commit today). Installs on Mac via cargo / bifrost, no brew-CDN issue.
- **[STEAL] whatsabi** — https://github.com/shazow/whatsabi  ()
  TS/TS lib (~15KB, MIT, 1.1k stars, active) that extracts ABI, function selectors, event/error sigs from bytecode and RESOLVES PROXY implementation addresses; pluggable signature loaders (OpenChain/4byte/Sourcify/Etherscan/Blockscout). Pairs with viem/ethers getCode.
- **[STEAL] evmole** — https://github.com/cdump/evmole  ()
  Rust core + Python & JS bindings (MIT, 443 stars, active) extracting function selectors, ARGUMENT TYPES, state mutability and STORAGE LAYOUT from raw bytecode. Fast, embeddable, has a companion eval dataset (cdump/evmole-datasets) to benchmark accuracy.
- **[PAID-REF] Dedaub Decompiler + API** — https://dedaub.com/product/decompiler/  ()
  Best-in-class decompiler (claims ~99.98% coverage), indexes millions of contracts across EVM chains. Free for manual individual use at app.dedaub.com; programmatic API is a paid org subscription (POST bytecode -> md5 -> poll Status -> GetDecompilation).
- **[LEARN-FROM] Panoramix** — https://github.com/palkeo/panoramix  ()
  The original Python Etherscan decompiler (MIT, 932 stars). Still works but heimdall-rs supersedes it on quality/speed/maintenance; useful as a cross-check or for its readable pseudocode style.
- **[LEARN-FROM] sevm** — https://github.com/acuarica/sevm  ()
  TypeScript symbolic EVM interpreter/decompiler library — turns bytecode into a control-flow/IR you can query programmatically in-process (no external CLI), good for building custom bytecode-level invariants.
- **[SKIP] ethervm.io decompiler** — https://ethervm.io/decompile  ()
  Online-only EVM decompiler, no documented API/self-host. Convenient eyeball cross-check, not automatable.
- **[SKIP] pellucid** — https://github.com/meppent/pellucid  ()
  Early-stage Rust EVM decompiler (GPL-3.0, ~47 stars, low activity). Interesting to watch but not production-ready vs heimdall.

**Techniques:**
- Bytecode-lane fallback: when fetch_source.py returns UNVERIFIED, RPC getCode -> whatsabi (ABI+selectors+proxy resolve) -> evmole (arg types + storage layout) -> heimdall `decompile` (pseudo-Solidity). Cache artifacts next to the target like verified source.
- Proxy-first: whatsabi resolves implementation address; re-run fetch_source on the IMPL (often verified even when proxy is not) before falling to decompile — cheapest coverage win.
- Selector -> signature enrichment: feed evmole/whatsabi selectors through OpenChain/4byte to recover human function names, giving recon.py and the L4 read real handles on a blob.
- Storage-layout diffing: evmole storage layout on an unverified IMPL vs a known verified base = bytecode-level fork/copycat detection for radar.py's impl-upgrade slot-diff (catches malicious upgrades that swap logic without changing the proxy).
- Decompiled-source feed into recon.py is LOW-fidelity (regex detectors expect real Solidity; heimdall output is lossy) — treat it as L4/Claude-read input + selector/ABI triage, NOT as clean detector input. Use ABI surface to pick which detectors even apply.
- Escalation tier: for a single hot target, push bytecode to Dedaub free web app for the highest-quality read before committing to a deep dive.

**Applicability:** Concretely: (1) New 'bytecode lane' in fetch_source.py — UNVERIFIED no longer dead-ends; it returns whatsabi ABI + evmole storage/args + heimdall pseudo-Solidity as a synthetic target package. (2) analyze.py L2 gains a pre-step that resolves proxy->impl (whatsabi) and re-tries verified-source on the impl. (3) freshdeploy.py becomes far more useful: a brand-new unverified deploy from a watched deployer/factory now gets an instant ABI + decompile so you can triage it in minutes instead of skipping it. (4) radar.py impl-upgrade slot-diff gets an evmole storage-layout + selector-set diff to flag logic-swapping upgrades on unverified impls. (5) ledger.py keys verdicts by bytecode/codehash so the same unverified blob (and its clones) is suppressed across chains.

**Impact:** Coverage: meaningful — closes the 'unverified = unreachable' blind spot and turns freshdeploy/radar from verified-only into all-deploys lanes (the deploys most likely to be unverified are also the freshest, which is exactly your #1 bottleneck). Speed: modest-to-neutral for classic findings — bounty targets are usually verified, and decompiled source is too lossy to boost recon.py precision, so this widens the funnel rather than sharpening it. Net: a real coverage multiplier on the freshness frontier, low risk of FP inflation if decompiled output is kept out of the regex detectors.

**Implementability:** Medium effort, all deps free/MIT and Mac-friendly (cargo install heimdall+evmole-py, npm whatsabi — no brew-CDN blockage). v1 (~1 day): a `bytecode_lane.py` that takes addr+chain, pulls getCode via your Etherscan-v2/RPC, runs whatsabi for ABI+proxy-resolve, evmole for storage/args, heimdall `decompile -o` for pseudo-source, and writes a target package fetch_source's consumers already understand. v2: proxy->impl re-verify hop, selector->4byte enrichment, codehash-keyed ledger entries, and an evmole storage-diff hook into radar. Keep Dedaub as a manual escalation, not a coded dependency (API is paid). Main pitfall: don't pipe heimdall output into recon.py expecting clean hits — gate detectors by recovered ABI surface and route the pseudo-source to the L4/Claude read.

**Recommendation:** PROTOTYPE — build the whatsabi+evmole+heimdall bytecode lane (all free/self-hostable) wired into fetch_source/freshdeploy/radar; it closes a named coverage gap on the freshest deploys, but keep expectations honest (coverage not precision) and don't feed lossy decompiled source into the regex detectors.

---

## fork-cve-propagation

**State of the art.** Detecting one upstream vuln across all forks of a base is a real, underserved niche and a natural fit for our existing forkdrift.py + registry fork-index. The mature primitives exist but are fragmented: (1) source-level fork fingerprinting (what we already do, by hand-curated internal sigs), (2) bytecode/CFG similarity to find forks we DON'T know about — including unverified ones (Soptq forta-contract-simil, christoftorres CCD/ssdeep, academic Esim/SmartEmbed), and (3) differential fuzzing fork-vs-base to confirm a CVE actually applies to the live config (Diffusc = Slither+Echidna). The killer gap: nobody ties these into an automated "one upstream CVE -> rescan every fork" loop — that orchestration is the steal. Caveat: DeFiLlama /forks went paid, and Diffusc is now archived, so the clean propagation pipeline has to be assembled from parts rather than bought.

**Tools:**
- **[LEARN-FROM] crytic/diffusc** — https://github.com/crytic/diffusc  (yes / AGPL-3.0 — but ARCHIVED Aug-2025, 79 stars; fork-mode needs manual init effort)
  Differential fuzz-test generator: takes two impls (or two on-chain addresses in fork mode), uses Slither to find functions impacted by the diff, generates an Echidna harness that feeds identical inputs to base-vs-fork and asserts equal results. This IS the auto-PoC-confirm-a-CVE-applies step.
- **[LEARN-FROM] Soptq/forta-contract-simil** — https://github.com/Soptq/forta-contract-simil  (yes (Forta detection-bot, JS) — small/8 stars, reference impl not turnkey)
  Bytecode-similarity bot: clusters newly-deployed contracts against a reference by code similarity. The named primitive for discovering forks we don't have in our BASES list — works on UNVERIFIED bytecode (our blind spot).
- **[STEAL] christoftorres/contract-clone-detector (CCD, IMC 2024)** — https://github.com/christoftorres/contract-clone-detector  (yes / MIT — but only 4 stars, needs an ES index)
  Solidity SOURCE snippet clone detector: ssdeep fuzzy-hash fingerprints + Elasticsearch n-gram retrieval + order-independent similarity score. Good for fork-clustering verified source at scale and for fingerprinting a specific vulnerable function across a corpus.
- **[LEARN-FROM] webthethird/solidity-diff-fuzz-upgrades** — https://github.com/webthethird/solidity-diff-fuzz-upgrades  (yes (research repo))
  Academic predecessor/companion to Diffusc (same author lineage) — differential fuzzing of upgradeable contracts. Useful for the harness-generation logic if Diffusc bitrots.
- **[LEARN-FROM] Esim (Stable-Semantic-Graph bytecode similarity)** — https://arxiv.org/pdf/2511.12971  (paper only (no public weights yet) — adopt the CFG/SSG idea, not a binary)
  SOTA (Nov-2025) EVM bytecode similarity via heterogeneous GNN over a Stable-Semantic-Graph; 96.3% AUC, beats Etherscan-simil across 2.6M contracts / 6 chains. Robust to compiler/optimizer drift — exactly the noise that breaks naive bytecode-hash fork matching.
- **[PAID-REF] Dedaub Decompiler + similarity API** — https://docs.dedaub.com/docs/api/nested/  (no (hosted API/SaaS) — free tier exists for manual lookups)
  99.98%-coverage EVM decompiler with LLM-assisted similarity + 'Hack-Related Proximity' scoring across indexed millions of contracts. Could both find forks AND partially crack our unverified-contract blind spot (decompile-to-readable).
- **[PAID-REF] DeFiLlama /forks** — https://defillama.com/forks  (no for API; page scrape is a grey-area workaround)
  Ranked fork-index per base (Aave V3, UniV2/V3, Compound V2, Liquity, Balancer...). Ground-truth seed list of which protocols fork which base. NOTE: the /forks JSON API now returns 'upgrade to paid'; the public /protocols forkedFrom field is near-empty (6 of 7742). HTML page is scrapeable.

**Techniques:**
- One-upstream-CVE -> rescan-all-forks loop: when a base ships a fix / a hunt-DIG finds a base bug, encode the vulnerable function as a one-shot recon.py rule (regex over the drifted block) and replay it across every fork row in registry.py's fork-index.
- Two-tier fork discovery: tier-1 = our source-internal sig fingerprints (forkdrift BASES, conclusive but only for forks we curated); tier-2 = bytecode/CFG similarity (Soptq/Esim-style) to auto-find unknown + UNVERIFIED forks against freshly-deployed contracts.
- Drift-localized scanning: don't rescan whole forks — diff fork-vs-canon (forkdrift already does substantive_diff), then only run the CVE rule on the DRIFTED region, where fork-specific bugs and missed version-lag patches actually live.
- Differential-fuzz confirmation: after a static hit, generate a Diffusc/Echidna fork-vs-base harness so the upstream invariant (e.g. base patched a rounding/solvency check) becomes an assertion the fork must satisfy — converts a hypothesis into a PoC.
- Version-lag triage: fingerprint fork's base VERSION (forkdrift.detect_version) vs the version where the CVE was patched -> forks older than the patch are auto-prioritized (the missed-backport class).

**Applicability:** Concrete integration, mostly on rails we already have: (1) New subcommand `forkdrift.py propagate <base> <cve-rule>` — reads registry.py's fork-index (the rows tagged with FORK_BASES), runs the one-shot recon.py rule only over each fork's forkdrift `substantive_diff` region, writes hits to ledger.py + a fanout_log table. (2) freshdeploy.py gets a new filter lane: bytecode-similarity (Soptq/CCD-style) tags each new deploy with 'likely fork of <base>' so a live CVE auto-routes to fresh forks — this is the freshness-wall play, since a just-deployed unpatched fork is exactly a live, in-scope target. (3) A new scaffold.py engine target wrapping Diffusc fork-mode = the auto-PoC step after a DIG confirms drift. (4) Bytecode similarity partially cracks the unverified blind spot: cluster-by-bytecode even without source.

**Impact:** Both, skewed to COVERAGE with a real shot at the freshness bottleneck. Coverage: turns every single upstream finding into N fork-rescans for ~free (multiplier = fork count, often 10-50x for Aave/UniV2/Compound bases). Speed: drift-localized scanning + version-lag auto-triage cuts per-fork triage from manual read to a ranked queue. The freshness angle is the highest-value piece — a CVE rule standing watch over freshdeploy + similarity-tagged new forks can catch an unpatched clone in the live window, which is precisely where our zero-live-findings wall is.

**Implementability:** Tiered. LOW effort / high ROI: the `forkdrift.py propagate` orchestrator — pure glue over existing forkdrift + registry + recon + ledger, stdlib only, no new deps; a weekend. MED effort: bytecode-similarity fork discovery — needs a feature pipeline (CCD ssdeep is simplest/MIT; Esim-grade GNN is research-only, skip the weights). The honest blocker is a reference bytecode corpus per base + an index (ES or even sqlite+ssdeep). HIGH effort / fragile: Diffusc auto-PoC — it's archived (last commit Aug-2025), AGPL, and fork-mode needs hand-written init; budget real time and pin the toolchain, or port just its Slither-impacted-function logic. DeFiLlama /forks as a seed is now paid — bootstrap the fork-index from our own forkdrift BASES + page-scrape instead.

**Recommendation:** PROTOTYPE — build `forkdrift.py propagate` now (cheap glue over registry+recon+ledger, immediate coverage multiplier on every finding); BACKLOG bytecode-similarity fork discovery (CCD/ssdeep first, Esim as research); LEARN-FROM Diffusc for an eventual auto-PoC scaffold engine but don't depend on the archived binary.

---

## non-evm-coverage

**State of the art.** Non-EVM tooling is mature on Solana, thin-and-aging on Starknet, and effectively absent (for cheap static finding) on Move. Solana has three free, self-hostable, actively-maintained CLIs that mirror our exact stack: Radar (extensible static detectors = recon.py analog), sec3 X-Ray (50+ detectors = Slither/L2 analog), and Trident (Rust/Anchor fuzzer = scaffold.py analog) — plus solana-verifiable-build, the Solana analog of fetch_source.py that turns on-chain program bytecode back into reproducible source (partly solves our "unverified=unreachable" gap on that chain). Starknet has Caracal (SIERRA static analyzer, works on Cairo 2) but it's stale (last push Jan-2024, 149 stars), and its companions Amarna and Thoth are both ARCHIVED. Move is the weakest ROI: Move Prover is heavyweight formal verification (spec-writing effort, not a scanner), the academic "MoveScan/MoveScanner" tools are not open-sourced (the MoveScan/scan GitHub repo is an unrelated 2-star Vue frontend), and MoveBit's analyzers are dev-LSP, not security scanners. Bottom line: minimal coverage on the fastest-growing non-EVM value = Solana, and it's a wrapper job, not a from-scratch detector build.

**Tools:**
- **[STEAL] Radar (Auditware)** — https://github.com/Auditware/radar  (yes (Docker/CLI, GPL-3.0))
  Static analysis engine for Rust/Anchor (and Stylus/Solidity) with detectors written as Python template files + AST helper lib — directly mirrors recon.py's pattern-detector model, so our detector-authoring mental model transfers 1:1 to Solana.
- **[STEAL] sec3 X-Ray (open-source toolchain)** — https://github.com/sec3-product/x-ray  (yes (CLI, AGPL-3.0))
  Open-source CLI: parses Rust -> AST -> LLVM IR, applies 50+ Solana vuln detectors (missing-signer, missing-owner, account-confusion, unchecked-arith, CPI issues). Active (pushed 2026-03). The Slither-equivalent L2 lane for Solana.
- **[STEAL] Trident (Ackee)** — https://github.com/Ackee-Blockchain/trident  (yes (Rust, MIT, actively maintained, 395 stars))
  Rust/Anchor coverage-guided fuzzer with Anchor-like macros and stateful flow sequencing. The scaffold.py engine analog for Solana — auto-PoC after a DIG on a Solana target.
- **[STEAL] solana-verifiable-build (Solana Foundation)** — https://github.com/solana-foundation/solana-verifiable-build  (yes (active, 467 stars))
  Reproducible-build + on-chain verification; lets you confirm/recover source for deployed Solana programs. The fetch_source.py reachability analog for Solana — partially defeats our 'unverified=unreachable' blind spot on this chain.
- **[LEARN-FROM] Caracal (Trail of Bits / crytic)** — https://github.com/crytic/caracal  (yes (Rust/Cargo or Homebrew, AGPL-3.0, stale))
  Static analyzer over Starknet SIERRA, taint + dataflow, detectors for Cairo 2.x. Same crytic family as Slither — familiar UX. But last push Jan-2024; treat as best-effort Starknet lane only.
- **[LEARN-FROM] Thoth (FuzzingLabs)** — https://github.com/FuzzingLabs/thoth  (yes (Python, AGPL-3.0, ARCHIVED))
  Cairo disassembler/decompiler/CFG for raw bytecode — relevant to our decompile gap on unverified Starknet contracts. But ARCHIVED (read-only since 2025); reference-only.
- **[SKIP] Amarna (crytic)** — https://github.com/crytic/amarna  (yes (AGPL-3.0, ARCHIVED))
  Static analyzer for legacy Cairo 0; ARCHIVED and predates Cairo 1/2, so largely obsolete for current Starknet code.
- **[LEARN-FROM] Move Prover (aptos/move)** — https://github.com/move-language/move  (yes (Apache-2.0))
  Formal verifier for Move (Aptos/Sui). Powerful but requires writing MSL specs per function — high effort, not a push-button scanner; poor fit for fast fan-out triage.
- **[SKIP] MoveBit aptos/sui-move-analyzer** — https://github.com/movebit/aptos-move-analyzer  (partial)
  LSP/dev-tooling for Move, not a security scanner. No detector corpus to harvest. Note: academic 'MoveScan' (98.85% precision paper) is NOT open-sourced — the MoveScan/scan repo is an unrelated 2-star Vue frontend.

**Techniques:**
- Solana account-model bug classes our EVM detectors can't express: missing signer check, missing owner/account-discriminator check, account-confusion/type-cosplay, missing rent-exemption, arbitrary-CPI, unchecked PDA seeds, integer overflow in checked-math-off contexts — these are the T0/T1 equivalents to learn and seed.
- Radar's Python-template detector format is close enough to recon.py's heuristic style that detectors are portable concepts; harvest its detector library as a seed list rather than reinventing.
- Reproducible-build verification (solana-verifiable-build / OtterSec verify) as the non-EVM analog of Etherscan verified-source — a reachability gate before triage.
- SIERRA/LLVM-IR-level analysis (Caracal, X-Ray) instead of source regex — a different altitude than recon.py, gives some coverage even when only IR/bytecode is available.
- Coverage-guided stateful fuzzing of instruction sequences (Trident) as the auto-PoC step, replacing Foundry for Solana DIGs.

**Applicability:** Concrete integrations, Solana-first: (1) New "solana" lane in analyze.py that shells out to sec3 X-Ray and Radar on a fetched Anchor program and normalizes their JSON into our finding/ledger schema — same wrapper pattern we already use for Slither. (2) fetch_source.py gets a Solana branch: resolve a program address -> solana-verifiable-build / verified-programs registry to obtain reproducible source (defeats unverified blind spot on this chain). (3) scaffold.py gains a Trident harness generator alongside Foundry/Echidna for the auto-PoC-after-DIG step. (4) freshdeploy.py/radar.py add a Solana data source (watch known program deployers / Anchor IDL registry / Immunefi Solana-scoped bounties) — this attacks our #1 freshness bottleneck on a chain with real bounty value. (5) shadow.py adds a Solana corpus (sec3/Neodyme exploit datasets) to measure recall. Starknet would be a parallel but lower-priority Caracal lane; Move is not worth a lane yet.

**Impact:** Coverage: large — opens an entire high-value chain class (Solana TVL + active Immunefi programs) that we are currently 100% blind to, and the tooling is free/self-hostable so it's additive, not a tradeoff. Speed: neutral-to-positive (wrapping existing CLIs is fast; fuzzing PoC is slower per-target but only runs post-DIG). Net: high coverage upside on Solana, modest on Starknet, negligible on Move. Caveat: net new findings still gated by freshness/in-scope-bounty sourcing — the same wall — so impact is "new addressable surface," not guaranteed findings.

**Implementability:** Solana lane = MEDIUM effort. X-Ray and Radar are CLI/Docker with JSON-ish output -> a few days each to wrap into analyze.py mirroring the Slither integration. Deps: Rust/Cargo + Docker on the Mac (X-Ray is C++/LLVM, heavier build; Radar is Dockerized, easier — start with Radar). fetch_source Solana branch = MEDIUM (different RPC + verify flow, no Etherscan-v2 reuse). Trident harness gen = MED/HIGH (must model account/instruction setup, unlike stateless Foundry). v1 = Radar+X-Ray static lane on a hand-fed Anchor program + a Solana bounty source in radar.py; skip fuzzing until a real Solana DIG lands. Starknet/Caracal = LOW-effort wrapper but the tool is stale, so MEDIUM confidence. Move = HIGH effort / low payoff, defer.

**Recommendation:** PROTOTYPE — Solana-only: wrap Radar + sec3 X-Ray as a static lane in analyze.py and add a Solana bounty/deployer source to radar.py; it's the fastest-growing non-EVM value with free, stack-shaped tooling and a real verified-source path. BACKLOG Starknet (Caracal works on Cairo 2 but is unmaintained — thin lane only if a Starknet bounty appears). SKIP Move auto-scanning for now (Prover is formal-verification heavy, no open static scanner, lowest ROI).

---

## monitoring-platforms

**State of the art.** The self-hostable on-chain monitoring space splits in two. (1) Config-driven alerting engines like OpenZeppelin Monitor (Rust, AGPL-3.0, EVM 60-plus chains plus Solana and Stellar) match decoded function calls, event params and tx fields via filter expressions and fire custom Python/JS/Bash scripts. Built for defenders watching their OWN contracts, but for an offensive hunter it is a near-free FRESHNESS and UPGRADE radar: point it at bounty-scope addresses or known deployers and get notified the instant an implementation upgrades, a privileged function fires, or a factory spawns a contract. (2) Decentralized detection networks like Forta (detection bots plus scan nodes, now FORT-staked) and Drosera (Solidity traps with collect/isValid over historical state, operator-staked mainnet) — value to US is not running the network but mining their open bot/trap corpora as reasoning-tier invariant patterns and borrowing the invariant-over-history execution model. Hypernative and Hexagate are closed SaaS, pure paid reference. Net: OZ Monitor directly attacks our number-one freshness bottleneck at low effort; the networks are LEARN-FROM datasets, not platforms to adopt.

**Tools:**
- **[STEAL (integrate/fork)] OpenZeppelin Monitor** — https://github.com/OpenZeppelin/openzeppelin-monitor  (yes — AGPL-3.0, Docker, Rust 1.90-plus)
  Self-hosted Rust alerting service. Watches EVM 60-plus chains, Solana, Stellar; matches decoded function sigs plus args (transfer(address,uint256), value-above-threshold), events, and tx fields; cron plus block-checkpoint resume; fires Slack/Discord/Telegram/email/webhook OR custom Python/JS/Bash scripts that receive the match as JSON. AGPL-3.0, Docker, DAppNode package exists, actively maintained (June 2026).
- **[LEARN-FROM] Forta Bot SDK** — https://github.com/forta-network/forta-bot-sdk  (partial — SDK open (MIT/Apache), local runs yes; network node needs FORT stake)
  Open SDK/CLI for detection bots (handleTransaction/handleBlock). Bots encode reasoning-tier heuristics (read-only reentrancy, approval drains, anomaly thresholds) mineable into recon detectors and hypothesize seeds. SDK runs locally vs any RPC; productive scan-node network is FORT-staked/token-gated.
- **[LEARN-FROM] Forta bot-examples corpus** — https://github.com/forta-network/forta-bot-examples  (yes — open source)
  Reference bot implementations: a free runtime-heuristic pattern dataset (rake-scam, liquidity-drain, approval-anomaly, governor-quorum-change). Each is a labeled on-chain-suspicious rule, mineable into shadow.py corpus rows and reasoning-tier seeds.
- **[LEARN-FROM] Drosera Network examples** — https://github.com/drosera-network/examples  (partial — trap contracts/SDK open; live network staked/token-gated)
  Solidity traps expose collect (snapshot on-chain data) plus isValid (invariant over a HISTORY of snapshots, not just current state) — cleanest open model of stateful/temporal invariants (share-price drift, reserve ratio, solvency over time) for scaffold.py/hypothesize.py. Live network is operator-staked plus mainnet-token gated, not worth running.
- **[PAID-REF] Hypernative** — https://www.hypernative.io/  (no — closed SaaS)
  Closed SaaS real-time threat/anomaly plus pre-attack detection. Best-in-class precision, no self-host, no real free tier. Reference for what good anomaly coverage looks like.
- **[PAID-REF] Hexagate (Chainalysis)** — https://www.hexagate.com/  (no — closed SaaS)
  Closed SaaS real-time monitoring/threat detection, acquired by Chainalysis. Enterprise pricing, no self-host. Reference only.

**Techniques:**
- Offensive use of a defense tool: point OZ Monitor at bounty-scope addresses plus known deployers/factories and alert on (a) proxy impl-slot writes / Upgraded events, (b) privileged-fn calls (setOwner, grantRole, pause), (c) factory CreatedContract events — turns passive radar into a push-based freshness feed.
- Custom-script trigger as pipeline entrypoint: OZ Monitor fires a Python script with the match JSON which calls fetch_source.py plus recon.py on the new/changed address automatically (monitor-to-detector auto-handoff).
- Mining open bot/trap corpora (Forta examples, Drosera examples) into reasoning-tier invariant seeds — converting runtime defender heuristics into pre-deploy hunting hypotheses.
- Temporal/stateful invariants (Drosera collect/isValid): assert properties over a window of historical snapshots rather than single-state — for economic-drift detectors.

**Applicability:** OZ Monitor is a drop-in upgrade/anomaly radar augmenting BOTH radar.py and freshdeploy.py: (1) radar.py today polls impl-upgrade slot-diffs — OZ Monitor gives push-based, multi-chain, decoded-event upgrade detection on watched bounty targets for free, plus privileged-call alerts radar.py lacks; (2) freshdeploy.py watches known deployers/factories — OZ Monitor function-call plus event-based contract-creation matching is a ready-made data source across 60-plus chains with checkpoint resume. Killer integration is its custom-script trigger: wire it to call fetch_source.py then recon.py on every match so a new deploy or upgrade auto-enters TRIAGE (monitor-to-detect handoff). Forta bot-examples plus Drosera examples feed shadow.py (new corpus rows) and hypothesize.py (reasoning-tier seeds: approval-drain, read-only-reentrancy, quorum-change, temporal solvency drift) — directly attacking the KNOWN GAP of weak T2/T3 automation. Hypernative/Hexagate are reference-only.

**Impact:** both — freshness plus coverage. OZ Monitor converts polling into push-based upgrade/privileged-call alerts across 60-plus chains, shrinking time-to-known on a watched target from hours of polling to next-block (medium-high on freshness latency). Corpus mining widens the weakest lane, reasoning-tier coverage (medium).

**Implementability:** OZ Monitor: medium effort, low risk. Self-host via Docker on Mac (deps containerized). v1 = one monitor config over current bounty-scope plus deployer addresses, matching Upgraded()/proxy-slot plus privileged fns plus factory-created events, custom-script trigger shelling to fetch_source.py then recon.py, alert to Telegram. AGPL-3.0 fine for internal self-host. Gap: contract-creation detection is not first-class (docs lean on event matching), so freshdeploy-style any-new-contract-from-deployer may still need our deployer-txlist poll feeding addresses INTO the monitor. Forta/Drosera corpus mining: low effort (clone repos, extract heuristics into hypothesize seeds), no infra. Hypernative/Hexagate: zero (paid).

**Recommendation:** PROTOTYPE — Stand up OpenZeppelin Monitor self-hosted as an upgrade/privileged-call radar over current bounty-scope plus deployer addresses, wired via custom-script trigger into fetch_source.py then recon.py (monitor-to-detect auto-handoff); it directly hits the freshness wall and overlaps radar.py/freshdeploy.py with push-based multi-chain alerts. In parallel BACKLOG a one-day mine of Forta bot-examples plus Drosera examples into hypothesize.py reasoning-tier seeds and shadow.py corpus. SKIP running Forta/Drosera as networks (token/stake-gated) and SKIP Hypernative/Hexagate (closed, paid).

---

## hack-corpora-mining

**State of the art.** diagnostic

**Tools:**
- **[STEAL] FORGE-Curated** — https://github.com/shenyimings/FORGE-Curated  ()
  test

**Techniques:**
- one

**Applicability:** a

**Impact:** b

**Implementability:** c

**Recommendation:** d

---
