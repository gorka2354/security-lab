# security-lab — project context for Claude Code

A lab for **white-hat smart-contract bug hunting**: tooling, reproducible PoCs, and triage logs.
Read this when working in the repo. See `README.md` for the full overview and current counts.

## The hunter workflow (always)

```
read audit/code  →  extract a transferable PATTERN  →  reproduce a Foundry PoC  →
grade the real code against a checklist  →  write the finding  →
POST-FINDING THREAT ASSESSMENT (`threat.py`: is it live + ACTIVE-by-recency + funded, or dormant/abandoned?)
```

A finding's real-world severity + disclosure urgency depend on liveness, not just the code. After a
finding, run `threat.py` on the vulnerable contract (and its factory) — a count-based "ACTIVE" can hide
a product idle for months (the Krystal Community Vault lesson: real High-severity code bug, but the
product was dormant ~3mo with ~$1.4K, so current threat LOW). Don't overstate urgency; filter not-live
findings (gladiator not-deployed, equivaults pre-launch).

Every real hack becomes a detector + a golden test; every false positive becomes a precision fix.

## Where things live

- **`toolkit/`** — the engine, by lane:
  - **SOURCE:** `scout.py` (contests + DefiLlama deployed-unaudited + Immunefi), `githubsweep.py`
    (day-1 net-new channel: fresh Solidity repos via GitHub repo/topic search -> substantiveness filter
    [0x-address/chain/deploy-artifacts] -> WATCH-if-pre-mainnet; the automated form of the manual GameFi/
    prediction-market sweep that found pmarket/pulso/Dealers), `freshfeed.py`,
    `freshdeploy.py`, `contest_monitor.py`, `legacy.py` (dormant-but-funded contracts), `programs.py`
    (AUTHORIZED-SCOPE layer: live bounty/contest programs from Sherlock/Code4rena/Cantina -> `list --open`
    = hunt PAYABLE + in-scope targets first; `match <name|repo>` = is a finding in an open program + reward?
    So a real bug -> a payout, not a free disclosure. Refresh with `fetch`).
  - **REACH:** `fetch_source.py` (Etherscan-v2, 64 chains), `reach_bytecode.py` (unverified fallback:
    recover the surface from bytecode; EraVM-aware), `forkdrift.py` (audited-fork drift), `activity.py`
    (LIVE-FIRST Gate-0), `threat.py` (POST-FINDING threat assessment: deployed + ACTIVE-by-last-tx-recency
    + value-bearing, or dormant/abandoned? → a threat level that grounds severity + disclosure urgency;
    adds the recency signal activity.py's count-based gate lacked).
  - **DETECT:** `recon.py` (the static detectors), `ityfuzz_lane.py` (dynamic fork-fuzz),
    `decompile_match.py` (share-inflation math from decompiled bytecode), `hypothesize.py`
    (invariant seeds), `secrets_sweep.py`, `scaffold.py` (Foundry/Echidna/Medusa/Halmos).
  - **MEMORY/RADAR:** `ledger.py` (verdicts), `registry.py` (target cartography), `radar.py`
    (change/bounty radar: IMPL-UPGRADE + BOUNTY-OPEN over triaged targets), `watch.py` (VALUE/LIVENESS
    change-events over our real findings: FUNDED/GREW/DRAINED/CODE-CHANGE/REACTIVATED -> QUEUE.md + Windows
    balloon; covers exotic chains X Layer/Robinhood/ApeChain/opBNB where fresh GameFi finds live),
    `calibrate.py` (precision/recall feedback), `shadow.py` (honest recall).
  - **PLATFORM:** `labstate.py` → `labcore.py` → `lab_mcp.py` (MCP) + `web/` (dashboard) via `lab_http.py`.
- **`*-poc/`** — self-contained Foundry proofs-of-concept.
- **`hunts/<target>/HUNT.md`** — per-target triage logs (clones live under gitignored `hunts/_volume/`).
- **`tests/test_detectors.py`** — the golden suite (the CI gate; pure-stdlib).
- **`toolkit/VERIFY.md` + `toolkit/L4-READ.md`** — the human read + kill-gate methodology.

## Rules

- **White-hat, strict.** Analyze any publicly-deployed code (static + fuzz on a FORK/local = read-only over
  public data). On real impact → responsible disclosure (bounty if any, else privately to the team). NEVER:
  touch others' funds / live state, exploit on mainnet, publish a 0-day. A known/fixed bug is not a finding.
  **The researcher discloses, not the tool.**
- **LIVE-FIRST.** A bug matters only in **deployed + active + in-scope** code. Check deployment status in
  Phase 0 and prioritise live code; before assigning severity, run the callability gates (txlist-liveness +
  per-function usage + custodial-caller check).
- **Record every triage verdict** in the ledger (`ledger.py add …`: fp/known/wontfix/todo/real) so a lead
  never resurfaces twice. A pattern-found FP also gets a precision fix in the detector.
- **Freshness beats blue-chips:** un-audited / small / fresh targets are primary (bug density is there,
  not in audited-with-bounty blue-chips). For drift, diff against the last audit tag, not the whole repo.

## Conventions

- Detector changes must keep the golden suite green (`python tests/test_detectors.py` — the CI gate).
- Foundry/solc may not be on PATH → `source toolkit/env.sh` (sets PATH + reads `ETHERSCAN_API_KEY` from env).
- API keys are read from the environment only — never commit secrets.
- Printed output is ASCII (some consoles choke on unicode).
