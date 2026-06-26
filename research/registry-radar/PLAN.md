# Registry + Radar — structured plan (v1, research-backed)

> Supersedes `PLAN-v0.md`. Informed by `research-findings.md` (11-agent prior-art sweep, 2026-06-26).
> Principle: **reuse/steal proven prior art, build only the thin glue**; self-hostable, single-Mac + optional cloud.

## 1. Thesis (unchanged) + what research changed
**Thesis:** a categorized registry + change/freshness radar over our 93-target triaged universe turns sunk
triage cost into a recurring edge — it attacks **freshness** (our proven bottleneck), not tooling.

**What the sweep changed:** almost every layer has a proven artifact to steal, so this is mostly *glue*, not
new invention. The one thing we genuinely build is the **noise filter + significance scorer** (the hard part),
and even there the algorithms are off-the-shelf (Keep's fingerprint, OZ storage-layout diff, Slither upgrade-check).

## 2. Build-vs-reuse decisions (the spine)

| Component | Decision | Steal from | Notes |
|---|---|---|---|
| Registry data-model | **BUILD** (~30 LOC) | `cartography` reconciliation: `firstseen`/`lastupdated`/`run_tag`, MERGE-on-stable-id, **re-derive every run** | never hand-edit → can't rot |
| Protocol-type categories | **REUSE** | DeFiLlama `/categories` API | = our existing `zone` field |
| Vuln-class categories | **REUSE** (vendor JSON) | OWASP Smart Contract Top 10 2025 (SC01–SC10) + SWC/DASP aliases; Solodit checklist | cross-ref column |
| impl-upgrade detect | **BUILD** (~20 LOC) | ERC-1967 slot-diff + `Upgraded`/`BeaconUpgraded` events; generalize `watch.py:check_proxy_upgraded` | slot-first (catches non-emitting proxies) |
| source/bytecode drift | **REUSE** | `lidofinance/diffyscan` (Etherscan-v2, recompiles GitHub src, `allowed_diffs`) | don't write our own differ |
| bounty/contest launch | **REUSE APIs** | Immunefi `public-api/bounties.json`, Cantina `api/v0/competitions`, Sherlock `api/contests`, C4 `api/v1/audits` | switch watchlist off HTML-scrape → these JSON APIs |
| new-deployment discovery | **BUILD** (generalize) | `legacy.py from-deployer/from-factory` → radar `deployer_new_contract` (Etherscan-v2 txlist diff) | already own it; `cryo` if bulk needed |
| fork-fingerprint | **BUILD thin** | DeFiLlama `/forks` (free fork-family seed) + `whatsabi` (proxy-resolve+ABI) + `evmole` (selectors on unverified) | skip the ML clone-detection rabbit hole |
| **noise filter** | **BUILD** (~30 LOC) | `Keep` strip-then-hash fingerprint dedup, backed by `ledger.py` | partial+full dedup |
| **upgrade significance scorer** | **BUILD thin** | OZ `upgrades-core` storage-layout diff + `slither --check-upgradeability` | storage-layout change / new fn = "meaningful" |
| **agent re-triage on change** | **BUILD thin** | `anthropics/claude-code-security-review` (`findings_filter.py` + custom-FP-instructions) | feed delta + prior notes → our fan-out agent |
| scheduling | **REPLACE cron** | macOS `launchd` (survives sleep/reboot, catches missed runs) | + cheap cloud cron as backstop |
| dead-man's-switch | **REUSE** | `healthchecks` (heartbeat; a SILENT miss is itself an alert) | self-host or free tier |
| notification fan-out | **REUSE** | `apprise` (100+ backends) or `ntfy` (phone+desktop push) | Telegram/Discord/desktop |

## 3. Architecture (revised)

```
sources (ledger.json, hunts/_fanout/*.md, HUNT.md, DefiLlama categories/forks)
   │  re-derive every run (cartography model: firstseen/lastupdated/run_tag, MERGE on stable id)
   ▼
registry.py ──► monitor/registry.json  +  monitor/REGISTRY.md   (categorized inventory: zone/chain/fork-base/
   │             verdict, live addrs, reviewed impl-hash, OWASP-class tags)
   ▼
radar.py  (per live target, poll a CHANGE signal):
   ├─ impl_upgrade     slot-diff(eth_getStorageAt) ∪ Upgraded/BeaconUpgraded event   [BUILD]
   ├─ source_drift     diffyscan(addr vs known repo/tag)                              [REUSE]
   ├─ bounty_launch    snapshot-diff of 4 public contest/bounty JSON APIs            [REUSE APIs]
   ├─ new_deploy       txlist/txlistinternal child-set diff per deployer/factory     [BUILD/generalize]
   └─ each hit ─► significance scorer (storage-layout/slither) ─► noise filter (Keep fingerprint+dedup vs ledger)
                     │ only MEANINGFUL + un-seen passes
                     ▼
                 agent_retriage (claude-code-security-review pattern: diff + prior notes → real? severity?)
                     ▼
                 re-hunt queue (hunts/_radar/QUEUE.md) + notify (apprise/ntfy) + heartbeat (healthchecks)
   ▲
categories ─► batch action: on upstream fork CVE, `radar.py --fork aave-v3` re-scans ALL our aave-forks at once
```

## 4. The noise filter (the hard part — designed)
1. **Significance gate** (is the change worth a human?): for impl upgrades, run OZ `upgrades-core` storage-layout
   diff + `slither --check-upgradeability` between reviewed-impl and new-impl → score (storage collision / added
   external fn / changed modifier = HIGH; metadata-only / comment / same-bytecode-redeploy = DROP). Diff the **new
   bytecode hash**, not just the address (admin re-point ≠ upgrade).
2. **Dedup** (have we seen this exact change?): Keep's strip-then-hash — fingerprint = SHA-256 over the change
   dict minus volatile fields (timestamp, block); store in `ledger.py`. Partial dedup raises a counter, full dedup
   suppresses. A change already triaged in the ledger never re-fires.
3. **Agent re-triage** (is it a real bug?): only HIGH-significance + un-seen changes spawn an agent (our existing
   fan-out triage agent, specialized) fed **the delta + our prior HUNT notes for that target** → verdict + severity.
   Port `findings_filter.py` + the custom-FP-instructions block from `claude-code-security-review` verbatim.

This is what makes the feature *not* an alert-fire-hose: 80% hardened targets stay silent until a meaningful,
un-seen, agent-confirmed change.

## 5. Increments (each shippable, each reuses prior art)
- **Inc 0 — quick win (now):** switch `monitor/watchlist.json`/scout off the Immunefi HTML scrape onto the
  verified `immunefi.com/public-api/bounties.json` JSON (263 programs, has `launchDate`). Cheap, strictly better.
- **Inc 1 — `registry.py`** (zero-risk synthesis): re-derive categorized `registry.json` + `REGISTRY.md` from
  ledger+fanout+HUNT, cartography reconciliation, DeFiLlama category + OWASP-class tags, capture reviewed impl-hash.
- **Inc 2 — `radar.py` impl-upgrade radar** (highest EV): slot-diff over registry live addrs + significance scorer
  (storage-layout/slither) + Keep dedup → queue + notify. This is the killer feature.
- **Inc 3 — `radar.py` bounty_launch + new_deploy** checks (reuse 4 JSON APIs + generalize legacy.py).
- **Inc 4 — agent_retriage** step (claude-code-security-review pattern; delta + prior notes).
- **Inc 5 — scheduling hardening:** migrate cron→launchd + healthchecks heartbeat + apprise/ntfy fan-out.
- **Inc 6 — fork batch action:** DeFiLlama /forks seed + `--fork <base>` re-scan; upstream-CVE propagation.

## 6. Open decisions for egor
- **Notify channel:** Telegram bot vs ntfy (phone push, no account) vs just `monitor/ALERTS.md` + desktop? (apprise supports all.)
- **agent_retriage cost:** auto-spawn an agent on every HIGH-significance change (token spend) vs queue-and-batch nightly?
- **Scope of registry:** all 93 ledger targets, or only non-SKIP + live-address ones (leaner radar)?
- **launchd now or keep the 4h cron** until Inc 5? (cron works today; launchd is the robust end-state.)
