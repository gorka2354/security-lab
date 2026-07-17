# 🛡️ security-lab

[![CI](https://github.com/gorka2354/security-lab/actions/workflows/analyze.yml/badge.svg)](https://github.com/gorka2354/security-lab/actions/workflows/analyze.yml)
[![golden tests](https://img.shields.io/badge/golden%20tests-448%20passing-brightgreen)](tests/test_detectors.py)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](requirements.txt)

*[Русская версия](README.ru.md)*

> **A white-hat smart-contract bug-hunting engine** — a pipeline that sources fresh in-scope
> targets, sweeps them with static + dynamic analysis, remembers every verdict, and surfaces the
> whole hunt at a glance.

Think of it as a **detective agency for code**: a dragnet sources cases, a metal-detector (static
recon) plus a dynamic fuzzer find evidence, a case-file remembers verdicts, radars watch for
go-live, and a dashboard is the ops room.

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│  SOURCE  →  REACH  →  TRIAGE  →  DETECT  →  L4 (human)  →  VERIFY (Gate-0)  →  DISCLOSE │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

| | | |
|---|---|---|
| 🎯 **46** static detectors | 🧪 **448** golden tests (CI gate) | 📡 daily parked-finding watch |
| 🔑 secrets-sweep (tree + git history) | 🤖 dynamic fuzz (ItyFuzz) | 🖥️ dashboard + MCP platform |

> **Secret hygiene (verified):** an API key was used across all 287 commits and **never** committed —
> `.env`/`*.key` were never tracked, and the key appears in **0** commits and **0** tree files. A
> security repo that keeps its own secrets clean.

---

## 🧭 How the machine works

```
  SOURCE  ── where to look ──────────────────────────────────────────────────────────────
    scout.py          contests (C4/Sherlock/Cantina/Hats) + DefiLlama deployed-unaudited +
                      Immunefi (in-scope addresses + repos)
    freshfeed.py      newly-listed code (DefiLlama listedAt + Sourcify) — the freshness wall
    freshdeploy.py    new contracts from watched deployers/factories — timing edge
        │
  REACH  ── get the code ───────────────────────────────────────────────────────────────
    fetch_source.py   verified source by address (Etherscan-v2, 64 chains)
    reach_bytecode.py UNVERIFIED fallback: eth_getCode → recover the function surface from
                      bytecode; detects zkSync/EraVM (EVM-only lane)
    forkdrift.py      fork of an audited base? + the substantive drift diff (bugs live in drift)
        │
  DETECT ── find the evidence ──────────────────────────────────────────────────────────
    recon.py          STATIC: 46 detectors over source → WHERE the risk is
                      (access / spot-oracle / reentrancy / share-inflation / …)
    ityfuzz_lane.py   DYNAMIC: fork-fuzz with an economic oracle → PROVES an exploit (works on
                      unverified bytecode too). recon points, ItyFuzz proves.
    decompile_match.py recover share-inflation MATH from decompiled bytecode (panoramix/heimdall)
    secrets_sweep.py  committed keys across in-scope repos (tree + git history), at scale
        │
  L4 (human) + VERIFY ── prove it, don't fool yourself ─────────────────────────────────
    VERIFY.md         Gate-0 LIVE-FIRST + 8 kill-gates + 10 FP traps ("an FP is worse than a miss")
        │
  DISCLOSE          in-scope + responsible only. The researcher discloses, not the tool.
```

**Memory stitches it together:** every triage verdict → `ledger.py`; an auto-registry of targets →
`registry.py`; the radar tooling writes a work-list the next session reads first.

---

## 🧰 Tools by lane

### DETECT — the engine
| Tool | What it does |
|---|---|
| `recon.py` | **STATIC** — 46 detectors (access-control, spot-oracle, reentrancy, supply, decimal-scale, trust-anchor, **share-inflation / vault-share-math**, …); FP-tuned, class-gated, network-agnostic |
| `ityfuzz_lane.py` | **DYNAMIC** — ItyFuzz wrapper: fork-fuzz a live address, economic oracle (profit), unverified bytecode |
| `reach_bytecode.py` + `decompile_match.py` | reach + decompile an **UNVERIFIED** contract (surface from bytecode → share-inflation math via panoramix/heimdall); EraVM-aware |
| `hypothesize.py` | invariant seeds (CORE / ECONOMIC / GAMEFI / BRIDGE) for fuzz/symbolic |
| `secrets_sweep.py` | committed-key leaks across in-scope repos (clone + history) |

### SOURCE / REACH / MEMORY
`scout.py` · `freshfeed.py` · `freshdeploy.py` · `contest_monitor.py` (contest timing-edge) ·
`fetch_source.py` (64 chains) · `forkdrift.py` (audited-fork drift) · `activity.py` (LIVE-FIRST gate) ·
`ledger.py` (persistent verdicts) · `registry.py` (target cartography) · `calibrate.py` (precision/recall feedback).

---

## 🔁 The self-improvement loop

```
  real hack  →  transferable pattern  →  detector + golden test  →  test/tune on LIVE code
                                                  ↑                          │
                                     FP → precision fix  ←───────────────────┘
```

`shadow.py` measures **honest** recall on real victim contracts (DeFiHackLabs/DeFiVulnLabs).
`calibrate.py` calibrates clean verdicts against public ground-truth → precision/recall + blind spots.
Every finding below produced a detector or a hypothesize seed; every FP produced a precision fix.

---

## 🎯 Findings (honest calibration)

Selected real work — the repo tracks the full triage log under `hunts/`:

- **CapyFi** — a **live, in-scope** oracle-staleness lead (Gate-0 passed): a commented-out `updatedAt`
  check is *not* a check → stale-price window (Low–Med). Sharpened `det_oracle` from the miss.
- **wager-chess** — **PoC-proven HIGH**: on-chain wagered chess validates the `promotion` argument only
  for pawns but applies it to any piece → a legal knight move with `promotion=Queen` spawns a Queen →
  checkmate → steal the pot. `wager-chess-poc/` (Foundry 5/5, run against the real engine; deployed on
  a testnet). Produced the reusable "validation-gap" pattern.
- **ThetaNuts** ($2.1M legacy-vault hack, post-mortem study) — reproduced the bespoke share-inflation as
  a faithful PoC, then **broadened `det_erc4626`** to catch it by math-shape (not interface name), and
  built the **reach + decompile** lane so an *unverified* vault can be triaged from bytecode to the bug.
- Plus disciplined **honest negatives** (Onchain Heroes, Cambria, Spaceship, Mantle, Lorenzo): a mature,
  well-guarded contract earning a CLEAN verdict is a deliverable, not a failure.

**The lesson:** the reachable target space is dominated by hardened/audited deployments, so finding
density is bottlenecked by **freshness + scope**, not tooling depth. The real lever is being *first* on
fresh in-scope code (what the radars + `freshfeed` are for) + dynamic auto-confirmation (ItyFuzz).

---

## 🚀 Quick start

```bash
python -m pip install -r requirements.txt
python tests/test_detectors.py          # 448 golden tests (the CI gate)
python toolkit/recon.py <repo>          # static pass over a cloned repo
python toolkit/scout.py --source all    # source a fresh wave of targets   (needs ETHERSCAN_API_KEY)
python toolkit/reach_bytecode.py <addr> <chain>   # surface of an unverified contract
python toolkit/dashboard.py             # → http://127.0.0.1:8787  (visual ops room)
```

CI (`.github/workflows/analyze.yml`) runs the golden gate + a Slither pass on every push;
`watch.yml` polls parked findings daily and annotates when one fires.

---

## 📁 Repository layout

```
toolkit/         the engine — 46 static detectors + source/reach/dynamic/memory lanes
tests/           448 golden fixtures (the CI gate; pure-stdlib, no deps)
hunts/           per-target triage logs (the full, honest hunt record)
research/        knowledge base — vulnerability patterns, sector playbooks, tooling research
*-poc/           self-contained Foundry proofs-of-concept (nomad, oracle, thetanuts, wager-chess, …)
monitor/ + web/  radar state + the dashboard (labcore → MCP + web, one source of truth)
.github/         CI (golden gate + Slither) and the daily parked-finding watch
```

---

## ⚖️ White-hat (strict)

In-scope authorized bounties only · responsible disclosure · **never touch others' funds** · dynamic
fuzzing on a FORK only · a known/fixed bug is not a finding · **the researcher discloses, not the tool.**

---

*Assistant context — `CLAUDE.md`. L4 methodology — `toolkit/L4-READ.md` + `toolkit/VERIFY.md`.
Tooling roadmap — `research/tooling-research/ROADMAP.md`.*
