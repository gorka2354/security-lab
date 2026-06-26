# Registry + Radar — feature plan (v0, pre-research)

> v0 = the idea as proposed, BEFORE the 10-agent prior-art sweep. The structured/final plan
> (`PLAN.md`) supersedes this once `research-findings.md` lands.

## Problem / why
Our proven bottleneck is **freshness, not tooling** — reachable space is dominated by hardened/audited
deploys. We've already paid to triage **93 protocols** (architecture, fork-base, where the custom drift
is) — but that knowledge is **flat verdict-memory optimized for one thing: suppression** (don't re-hunt).
The category/architecture is trapped in free-text `reason` fields; there's no synthesis layer and no
active change-radar across the universe. When any triaged protocol **upgrades its implementation**, we
have a huge head-start (architecture already mapped → only diff the new code = audit-drift sweet spot),
but nothing tells us it changed.

**Thesis:** a categorized registry + code-change/freshness radar over our already-triaged universe turns
sunk triage cost into a recurring edge — it attacks freshness directly.

## What we already have (reuse, don't rebuild)
- `toolkit/triage-ledger.json` — 93 targets, `{target,file,detector,verdict,reason,date}`.
- `hunts/_fanout/*.md` — typed tables (type+chain+verdict) per fan-out run.
- `hunts/<t>/HUNT.md` — per-target deep logs.
- `toolkit/watch.py` — ALREADY has `check_proxy_upgraded` (impl-hash drift) + `github_new_repo` +
  `url_appears`; today wired only to 2 parked findings (`monitor/watchlist.json`).
- `toolkit/diffscan.py` (freshness vs audit tag), `legacy.py` (dormant+funded sourcing), `calibrate.py`.

## Architecture (3 layers)
1. **`registry.py`** — auto-derive a normalized registry FROM existing sources (ledger + fanout + HUNT).
   One row per protocol: `category-tags` (zone/chain/base-fork/verdict), live addresses, **reviewed-impl-hash**,
   source. Auto-built (never hand-edited → can't rot). Emits `monitor/registry.json` + `monitor/REGISTRY.md`.
2. **`radar.py` (KILLER FEATURE)** — per registry entry with live addrs, poll a change signal:
   impl-hash drift (`proxy_upgraded`) ∪ new bounty/contest (`url_appears`) ∪ version/audit-tag bump
   (`diffscan`). On change → push to a **re-hunt queue with prior notes attached**. Generalizes
   `monitor/watchlist.json` from 2 findings to the whole universe.
3. **Categories → batch actions** — the only reason categories earn their keep: on an upstream fork CVE
   (Aave V3 / Velodrome / Compound), `radar.py --fork aave-v3` re-scans ALL our forks of that base at once.
   One upstream bug → N forks.

## Honest caveats (the real work)
- **The noise filter is harder than the registry.** ~80% of targets are SKIP/hardened; re-surfacing all
  on any change = alert fatigue. Value is in the **trigger**: surface only on a *meaningful* change
  (impl upgrade / version bump / bounty launch), not any tx.
- **Categories for their own sake = dead metadata.** They must drive an action (the batch fork-CVE case).
- Registry must be **auto-derived**, not hand-maintained.
- macOS scheduling caveat (cron needs the Mac awake + Full Disk Access; consider `launchd`).

## Increments
- **Inc 1 — `registry.py`** (zero-risk synthesis; read-only over ledger/fanout). Categorized dashboard.
- **Inc 2 — `radar.py`** (generalize watch.py over the registry; impl-upgrade radar first = highest EV).
- **Inc 3 — batch fork-CVE re-scan** (categories drive forkdrift fan-out).

## Open questions for the prior-art sweep (→ research-findings.md)
- How do pros monitor on-chain impl upgrades (Defender Sentinels / Tenderly / Hypernative)? Steal what?
- Best bytecode/source diff for audit-drift (Diffyscan / evm-diff / verified-source diff)?
- Existing whitehat "watchtower"/target-inventory repos to fork instead of build?
- Fork/clone detection at scale + upstream-CVE→fork propagation prior art?
- New-deployment / funded-contract discovery pipelines (Dune/Allium/factory-enum)?
- DeFi protocol + vuln-class taxonomies to seed our category schema?
- Alert-dedup / noise-suppression patterns from monitoring systems?
