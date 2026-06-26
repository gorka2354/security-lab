---
name: hunt
description: >
  White-hat smart-contract bug hunt — the full security-lab pipeline in one command. Use when egor says
  "hunt <target>", "/hunt", "найди баги в <repo/address/protocol>", or "насёрчи свежий таргет". Sources a
  target (or takes one), reaches its live code, triages (fork? audited? novel?), runs the detectors +
  hypothesizer, does the L4 multi-mindset read, kill-gates every candidate, and only then proposes a finding.
  Orchestrates toolkit/ + the L4-READ / VERIFY methodology. White-hat only; egor discloses, never me.
---

# /hunt — one-command bug hunt (MVP)

A thin orchestrator over the security-lab engine. Run the phases in order; STOP early when a phase says clean.
Foundry not on PATH -> prefix `export PATH="$HOME/.foundry/bin:$PATH"`. Etherscan: `export ETHERSCAN_API_KEY=…`
(egor's free key) so `fetch_source` reaches Etherscan-verified source beyond Sourcify. ASCII output only.

## Hard rules (never break)
- **White-hat:** only in-scope authorised bounties/contests; responsible disclosure; never touch others' funds.
- **Known/fixed ≠ finding.** **egor discloses, never me.** **FPs are worse than misses** (see VERIFY).
- **LIVE-FIRST:** a bug matters only in DEPLOYED + active + in-scope code (verify deploy in Phase 1).

## Phase 0 — SOURCE a target (skip if egor gave one)
- Fresh live contest (best EV — guaranteed-unaudited + paid): `python toolkit/contest_monitor.py` -> pick a
  [FRESH] our-zone contest (hunt it first-hours). It's cron'd to alert on launches.
- Deployed-but-unaudited: `python toolkit/scout.py --source defillama --resolve-top 12` (CORE-repo resolve);
  for closed-source, get core addrs from the DefiLlama adapter (`projects/<module>/index.js`).
- In-scope + paid: `python toolkit/scout.py --source immunefi`.
- GameFi/gamble (egor's edge): scout covers Gambling/Luck Games/Lottery/Betting now; or a fresh game launch he names.
- DEPRECATED-but-funded (the Thetanuts class scout/contest STRUCTURALLY miss — de-listed, no bounty):
  `python toolkit/legacy.py check <addr>[,...] --chain <id>` (also `from-deployer`/`from-factory` w/ ETHERSCAN_API_KEY,
  or `sweep --file <addrs>` to rank a big list by residual value -- the class is RARE, prefer a broad sweep)
  -> LEGACY-FUNDED = residual value + no recent activity = forgotten contract, classic bug shapes
  (det_vault_share_math/det_erc4626). Inverse of activity.py. Skips EIP-7702 EOAs.
- Ledger suppresses already-hunted; pick the top un-suppressed, our-zone, reachable candidate.
- **REACHABILITY FIRST (dogfood lesson):** Phase 1 stalls on closed-source/obscure-chain protocols (Ample =
  no DefiLlama addr, no public repo, JS site, Base/Monad/Katana). Before committing to a candidate, confirm
  the CORE is reachable: a public GitHub repo, OR verified source on a fetch_source chain (eth/base/arb/bsc/
  op/polygon/linea via the Etherscan key), OR a CORE addr in its DefiLlama adapter. If the only "address" is a
  gov token / the chain is exotic / no verified source -> SKIP to the next candidate; don't burn time digging.

## Phase 1 — REACH the live code + LIVE-FIRST
- By address: `python toolkit/fetch_source.py <addr> --chain <id> --proxy` (verified on-chain impl). The
  DefiLlama `address` is often the GOV TOKEN -> use the adapter's CORE addr, or the protocol's GitHub repo.
- By repo: `git clone --depth 1 <repo> hunts/_volume/<key>`.
- **SECRETS lane (Taiko/Raiko layer-A):** `python toolkit/secrets.py <repo>` — committed keys/credentials in
  the working tree AND git HISTORY (the leaked key usually lives in OLD commits, removed from HEAD). For
  history, clone WITHOUT `--depth 1` (or `git -C <repo> fetch --unshallow`). Pairs with recon's
  `det_trust_anchor` (layer-B, the on-chain missing-quorum blast radius). A live in-scope key -> disclose.
- **Confirm DEPLOYED + in-scope + a real bounty** before prioritising. Not deployed -> fix-but-don't-prioritise.
- **ACTIVITY GATE (do this BEFORE the deep read, not after — heavy-helms lesson):**
  `python toolkit/activity.py <core-addr>[,...] --chain <id|name> [--counter "theBugPathCounter()"]`.
  DORMANT (no recent events + 0 value, or a path-counter still == 0) -> **PARK (watch.py) or SKIP**, don't
  deep-read. A bug in deployed-but-unused code with no value at stake is EV ~0 (Heavy Helms gauntlet:
  nextGauntletId==0, free entry, NFT-only rewards -> a real flaw that can't currently damage anything).

## Phase 2 — TRIAGE (fork? audited? novel?) -> route
`python toolkit/forkdrift.py fingerprint <src>`:
- **FORK of a known base** -> `forkdrift.py diff <src> <canon>/src`. Hunt only the DRIFT (custom mods) + any
  version-lag patch that APPLIES to the live config (check on-chain, e.g. whitelist activated?). Verbatim + moot = clean.
- **AUDITED** (audit/ dir, firms, or C4 comments in source) -> do NOT re-review the covered core. Route to
  (1) post-audit drift, (2) out-of-scope/integration code, (3) economic invariants. (Solodit-known -> kill, gate H.)
- **NO base + no audit** -> greenfield, high-EV: hunt the WHOLE surface.

## Phase 3 — DETECT (cheap pre-filter; this AIMS, it doesn't FIND)
- `python toolkit/recon.py <src>` (41 detectors) — read `[!]` first; ledger already suppresses known/FP.
- `python toolkit/hypothesize.py <src>` — shared-state EMERGENT seeds + ROUND-TRIP pairs + the invariant MENU
  (CORE/ECONOMIC/GAMEFI) to prove.
- (optional depth) `analyze.py` (Slither) / `scope.py` (function-role map) / `scaffold.py` (invariant harness:
  `--engine chimera` = Foundry+Echidna+Medusa from one harness; `--engine halmos` = symbolic `check_*`; Linux/CI/WSL).

## Phase 4 — L4 READ (this FINDS; never conclude "clean" from a quiet recon)
Run **`toolkit/L4-READ.md`** on each Tier-1 file / lead: 4 mindsets (Attacker/Accountant/Spec-Auditor/Edge-Case)
× 4 lenses + Feynman 7-cat interrogation + the 7-check "what's-missing" sweep + coupled-state + masking-code flag.
Output per lead: a concrete **WHO / WHAT / HOW MUCH** (else it's gate-D speculative).
(Shadow-benchmark lesson: recon points at the file; the L4 Accountant/coupled-state read finds the economic bug.)

## Phase 5 — VERIFY (FPs are worse than misses)
Run **`toolkit/VERIFY.md`** on every candidate: 8 kill-gates (generic/theoretical/intentional/speculative/
admin/dust/out-of-context/publicly-known) + 10 FP-patterns -> verdict TP / LT / DOWNGRADE / FP / IE. Only TP/LT
proceed. Calibrate severity HONESTLY.

## Phase 6 — PROVE
Foundry PoC on a fork/local, OR a verbatim-formula reimplementation (the Ledgity method) — NEVER "by reading".
Numbers before/after; a runnable WHO/WHAT/HOW-MUCH scenario.

## Phase 7 — RECORD
- EVERY verdict -> `python toolkit/ledger.py add --target … --detector … --verdict fp|known|wontfix|real|todo --reason "…"`.
  FP-by-pattern -> also a recon precision fix (the self-improvement loop).
- Hunt log -> `hunts/<target>/HUNT.md`. New transferable pattern -> `research/patterns/<class>/`.
- TP/LT -> disclosure draft (`hunts/<target>/DISCLOSURE-*.md`); confirm scope + bounty; **egor sends it.**

## Knowledge & memory
After each hunt, update the Obsidian vault (pattern + heuristic) per the project CLAUDE.md, and the project
memory if the diagnosis/strategy shifted. The engine compounds: every bug studied -> a detector; every FP -> precision.
