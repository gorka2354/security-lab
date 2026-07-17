# Registry + Radar — prior-art research findings (11-agent sweep, 2026-06-26)

> Source: `registry-radar-priorart` fan-out (GitHub + web). Feeds `PLAN.md`. Verdicts: STEAL=fork/reuse, LEARN-FROM=adopt pattern, AVOID, PAID-REFERENCE.

## onchain-upgrade-monitoring

**State of the art.** Detecting implementation upgrades on EIP-1967/UUPS/beacon proxies is a solved, well-standardized problem: every conformant proxy either emits a canonical `Upgraded(address)` / `AdminChanged` / `BeaconUpgraded` event OR writes the new impl address into a fixed storage slot (impl 0x3608...382bbc, admin 0xb531...6103, beacon 0xa3f0...3d50). So you can detect an upgrade two robust ways: (1) subscribe/poll for the canonical event topic, or (2) periodically `eth_getStorageAt(proxy, implSlot)` and diff vs the last-seen value — the slot diff also catches non-conformant proxies that upgrade without emitting events. The market is shifting toward self-hosting: OpenZeppelin is SUNSETTING Defender (final shutdown July 1, 2026) and has open-sourced its Monitor + Relayer as production-ready, self-hostable Docker images — directly the radar.py use case. Paid SaaS (Tenderly, Hypernative, Forta) add auto-proxy-detection and ML noise filtering but are overkill/closed for a single-Mac personal registry.

**Tools / repos / APIs:**
- **[STEAL] OpenZeppelin Monitor** — https://github.com/OpenZeppelin/openzeppelin-monitor  
  Open-source (Rust, ~135 stars, actively maintained as of 2026-06) blockchain monitoring service, the open replacement for Defender Sentinels. Watches on-chain activity via configurable YAML/JSON monitors: match event signatures (e.g. Upgraded(address)) or function calls, apply 'smart filter' boolean expressions on decoded args, run on a cron schedule, and fan out to Slack/Discord/Telegram/Email/webhook/custom-script. Architecture: ClientPool->BlockWatcher->FilterService->TriggerService->NotificationService with missed-block recovery. Self-hosted Docker, custom RPC, multi-chain EVM + Stellar/Solana.
- **[AVOID] OpenZeppelin Defender (Sentinels)** — https://blog.openzeppelin.com/doubling-down-on-open-source-and-phasing-out-defender  
  The hosted SaaS that historically did proxy-upgrade alerts. Being phased out: new signups disabled June 30 2025, full shutdown July 1 2026. Do not build on it; migrate to the OSS Monitor instead.
- **[LEARN-FROM] Forta Bot SDK + bot-examples** — https://github.com/forta-network/forta-bot-sdk  
  JS/Python SDK + CLI for writing 'detection bots' that scan each block's tx/logs/traces and emit Findings. forta-bot-examples (github.com/forta-network/forta-bot-examples, 123 stars) shows event/function handlers you can lift for an Upgraded/AdminChanged detector. Designed for the decentralized Forta scanner network but bots run locally too.
- **[LEARN-FROM] Nethermind Forta-Agents** — https://github.com/NethermindEth/Forta-Agents  
  Large collection (~122 stars) of production Forta bots for on-chain anomaly/threat detection, including admin/ownership/upgrade-change agents. Good reference for how to structure event-signature matching and reduce false positives.
- **[STEAL] ERC-1967 spec (storage slots + events)** — https://eips.ethereum.org/EIPS/eip-1967  
  Canonical source of the three deterministic slots (impl 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc, admin 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103, beacon 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50) and the SHOULD-emit Upgraded/AdminChanged/BeaconUpgraded events. This is the spec your detector keys off.
- **[PAID-REFERENCE] Tenderly Alerts / Web3 Actions** — https://docs.tenderly.co/monitoring/smart-contracts/proxy-contracts  
  SaaS that auto-detects EIP-1967/1167 proxies, tracks historical implementation destinations, and fires alerts -> serverless Web3 Actions (custom JS). Free tier exists but is browser-only with NO API access; automation needs a paid plan. Good UX reference for 'auto-detect proxy + show impl history'.
- **[PAID-REFERENCE] Hypernative** — https://www.hypernative.io/products/hypernative-platform  
  Enterprise real-time security platform, 300+ risk types incl. governance/upgrade threats, 70+ chains, ML+heuristics+simulation noise filtering. Closed, enterprise-priced. Reference for what a high-precision noise filter looks like, not self-hostable.
- **[AVOID] Drosera (Traps)** — https://github.com/drosera-network  
  Decentralized on-chain incident-response protocol: protocols deploy 'Trap' contracts that node operators evaluate for real-time detection + automated response (e.g. pause). On-chain, operator-node heavy — far too much infra for a personal read-only radar.

**Techniques to adopt:**
- Dual detection = events + storage-slot diff. Primary: match log topic0 of Upgraded(address)=0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b (also AdminChanged, BeaconUpgraded). Backup/robust: eth_getStorageAt(proxy, implSlot) each poll and diff vs last-seen — catches proxies that upgrade WITHOUT emitting the event (non-conformant/custom) and needs no log indexing.
- Slot-based polling is cheap and stateless-friendly: one eth_getStorageAt per target per poll, compare to the reviewed impl-hash already stored in registry.py. A change == meaningful by construction, so the noise filter is trivial (no decoding, no heuristics).
- Beacon proxies need a second hop: read the beacon address from the beacon slot, then read the beacon's implementation() — a beacon upgrade changes one beacon for MANY proxies, so monitor the beacon contract once, not every proxy.
- UUPS upgrades happen via upgradeToAndCall on the impl itself but still write the same impl slot + emit Upgraded — slot-diff covers UUPS and Transparent uniformly.
- Block-range catch-up / missed-block recovery (OZ Monitor pattern): persist last-scanned block per chain, on restart replay gap so a cron that misses a window doesn't miss an upgrade.
- Config-as-files (OZ Monitor YAML monitors + cron) maps cleanly to a registry-driven generator: emit one monitor entry per live address from registry.py.
- Noise reduction by canonical-event allowlist: only topic0 in {Upgraded, AdminChanged, BeaconUpgraded, OwnershipTransferred} count as 'meaningful' — everything else is suppressed.

**Pitfalls:**
- Non-conformant proxies (custom/diamond/old) may upgrade without emitting Upgraded — pure log-subscription misses them. Always back up with slot-diff.
- Diamond/EIP-2535 proxies have NO single impl slot; upgrades are DiamondCut events adding/replacing facet selectors. A 1967-only detector is blind to them — needs a separate DiamondCut handler.
- Beacon upgrades: monitoring the proxy's impl slot will NOT change on a beacon upgrade (the proxy stores the beacon, not the impl). Must resolve+watch the beacon, or you silently miss mass upgrades.
- Free public RPCs rate-limit eth_getStorageAt/getLogs and may return stale or pruned-archive data; for historical block-range replay you need an archive node or a provider that serves it. getLogs can false-0 (your own death.fun lesson) — slot-diff via latest block is more authoritative for 'current impl'.
- Defender is dead (July 1 2026) — any tutorial/repo pinned to defender-sentinel-client is a trap; don't adopt it.
- Tenderly free tier has no API — you cannot automate alerts on free; budget for paid or self-host OZ Monitor instead.
- An impl-slot change is necessary but not sufficient for 'worth re-hunting': admin re-points and same-bytecode redeploys exist. Diff the NEW impl bytecode/hash, not just the address, before queueing.
- topic0 hashes must be exact; AdminChanged has indexed args, Upgraded(address) has the impl indexed — get the ABI/topic layout right or you decode garbage.

**Applicability to us:** radar.py already has a proxy_upgraded check — this angle says make it dual-mode and slot-first. Concretely: (1) For each live address in registry.py store the reviewed impl-hash (already planned). The radar poll does eth_getStorageAt(proxy, 0x3608...382bbc) and compares to that stored hash; any diff -> push to re-hunt queue with prior notes. This is 1 RPC call/target, self-hostable on Mac cron, zero noise by construction — the cheapest possible meaningful-change detector and the single highest-leverage steal here. (2) Add a fallback log path matching topic0 of Upgraded/AdminChanged/BeaconUpgraded for proxies where you only have a fromBlock. (3) registry.py should record proxy TYPE (transparent/UUPS/beacon/diamond) so radar.py knows whether to watch the impl slot, resolve+watch a beacon, or handle DiamondCut — this is a needed schema field. (4) categories->batch action maps perfectly to beacon monitoring (one beacon upgrade => re-scan all proxies pointing at it) and to 'upstream fork CVE' (your fork-base category). (5) Architecturally, don't reinvent the watcher loop: either embed OZ Monitor (Rust, Docker) as the engine and generate its YAML monitors from registry.py, or just lift its ClientPool + missed-block-recovery + filter-expression design into radar.py's Python. (6) Before queueing, diff NEW impl bytecode hash (not just address) to avoid admin-churn false positives — that IS your noise filter for this signal.

**Recommendation:** BUILD the slot-diff detector in radar.py (do not buy). The core is ~20 lines: eth_getStorageAt(proxy, implSlot) per target per poll, diff vs registry's reviewed impl-hash, on change fetch new impl bytecode + hash and enqueue to re-hunt with prior notes. It is self-hosted, single-Mac, near-zero cost, and noise-free by construction (a slot change is definitionally meaningful). Add the canonical-event topic0 allowlist (Upgraded/AdminChanged/BeaconUpgraded) as a secondary path for log-range catch-up. STEAL the architectural patterns from OpenZeppelin Monitor (missed-block recovery, config-as-files, filter expressions, notification fan-out) rather than its Rust binary — but keep OZ Monitor as a known drop-in engine if radar.py outgrows a Python cron. Extend registry.py with a proxy-TYPE field so beacon (watch-the-beacon, fan-out to all dependents) and diamond (DiamondCut, separate handler) are handled, not silently missed. AVOID Defender (sunset July 2026) and Drosera (on-chain operator infra, overkill). Treat Tenderly/Hypernative as PAID-REFERENCE for UX (auto-proxy-detection, impl history) and for what a mature ML noise filter aspires to — not for self-hosting.

---

## bytecode-source-diff (audit-drift / code-diff detection)

**State of the art.** The state of the art for "did this contract drift from its audited tag" splits cleanly into two layers. (1) Verified-SOURCE diff: pull Etherscan/Sourcify verified source for an address and diff it against a known GitHub commit — Lido's Diffyscan is the mature, self-hostable, actively-maintained reference (140 stars, pushed today, Python, Etherscan-v2 multichain, and crucially an `allowed_diffs` allowlist that IS the noise-filter primitive we need). (2) BYTECODE diff: recompile-or-fetch runtime bytecode and compare, where the one make-or-break technique is stripping the trailing CBOR/IPFS-swarm metadata hash before comparing, otherwise a whitespace/filename change yields a 100% false "drift". Sourcify formalizes this as full_match vs partial_match. Heavyweight semantic/normalized diffing (Dedaub TAC, academic Esim/triplet-network similarity) exists but is paid or research-grade and overkill for a personal radar.

**Tools / repos / APIs:**
- **[STEAL] lidofinance/diffyscan** — https://github.com/lidofinance/diffyscan  
  Python CLI: diffs deployed verified source AND bytecode for an address against a specific GitHub repo commit. Recompiles GitHub sources, simulates constructor via remote eth_call against live chain state, reuses explorer-provided constructor calldata/library addresses/EVM version, and supports a configurable `allowed_diffs` allowlist + JSON/YAML config + explorer/github caching. Multichain via explorer APIs. Maintained daily.
- **[LEARN-FROM] Etherscan Contract Diff Checker** — https://etherscan.io/contractdiffchecker  
  Free built-in web tool that diffs the verified source of two addresses (e.g. old impl vs new impl after an upgrade). No API, manual, but the canonical 'what changed between two deployments' UX to mirror.
- **[LEARN-FROM] argotorg/sourcify (formerly ethereum/sourcify)** — https://github.com/argotorg/sourcify  
  Open-source verification service. Defines full_match (bytecode incl. metadata identical) vs partial_match (bytecode identical AFTER ignoring metadata hash) — the exact two-tier match model a drift radar should adopt to suppress metadata-only noise. Self-hostable; also a free API to fetch verified sources without Etherscan.
- **[STEAL] banteg/storage-layout** — https://github.com/banteg/storage-layout  
  Python tool for readable EVM storage-layout enumeration and state diffs. Directly useful for the OTHER half of upgrade-drift: detecting storage-slot collisions / layout changes across an impl upgrade (the dangerous, non-obvious kind of drift a source-diff alone can miss).
- **[LEARN-FROM] mds1/evm-diff** — https://github.com/mds1/evm-diff  
  TypeScript, 292 stars. NOTE: despite the prompt's framing, this diffs EVM CHAINS (opcodes/precompiles/params), NOT two contracts. Tangential to contract drift but a clean reference for our multichain fork-base reasoning. It is by Matt Solomon (mds1), not banteg — the 'banteg evm-diff' in the brief does not exist.
- **[PAID-REFERENCE] Dedaub Decompiler / TAC + AI-reconstructed Solidity** — https://dedaub.com/product/decompiler/  
  99.98%-coverage decompiler producing normalized TAC (3-address code) and Solidity-like output from raw bytecode — lets you semantically compare UNVERIFIED deployments where source diff is impossible. Free web app (app.dedaub.com/decompile); programmatic Decompiler API is paid.
- **[LEARN-FROM] Esim / triplet-network bytecode similarity (research)** — https://arxiv.org/abs/2511.12971  
  Academic EVM bytecode-similarity via Stable-Semantic Graph + heterogeneous GNN (~96% AUC), robust across compiler versions and optimization settings; companion triplet-network work (mdpi 11/4/597). Shows how to compare semantics when literal bytes differ. Research-grade, no production repo.
- **[LEARN-FROM] OpenZeppelin — Deconstructing a Solidity Contract Pt VI: the Metadata Hash** — https://www.openzeppelin.com/news/deconstructing-a-solidity-contract-part-vi-the-swarm-hash-70f069e22aef  
  Definitive write-up on the CBOR/IPFS-swarm metadata trailer appended to runtime bytecode — the thing you MUST CBOR-parse-and-strip before any bytecode comparison to avoid false drift. This is the core noise-filter recipe.
- **[AVOID] jmpark-eng36/evm-contract-differ** — https://github.com/jmpark-eng36/evm-contract-differ  
  Title claims 'diff deployed bytecode, detect proxy patterns, watch for implementation upgrades' — but the README body is a placeholder ('Fast and reliable request handling library', generic Handler.process example). Mismatched/abandoned/AI-spam stub, 5 stars. Do not use.

**Techniques to adopt:**
- Strip the trailing CBOR-encoded metadata section (IPFS/swarm hash) from BOTH bytecodes before comparing — parse the CBOR length at the end, don't pattern-match a magic prefix. This single step is what converts 'every recompile looks like drift' into a usable signal.
- Two-tier match like Sourcify: full_match (bytes incl. metadata identical = no change at all) vs partial_match (identical after metadata strip = code same, only metadata/comments/paths moved). Surface only partial-or-worse as candidate drift; full_match is silent.
- Source-diff path (Diffyscan model): fetch verified source files per address, locate corresponding files in our reviewed repo/commit, diff, and gate noise via an `allowed_diffs` allowlist of known-benign hunks. Allowlist persists per-target so re-runs only fire on NEW hunks.
- Constructor-aware bytecode reconstruction: reuse explorer-provided constructor calldata + library addresses + EVM version, simulate via eth_call against live chain state, so the recompiled artifact actually matches the deployed runtime.
- Storage-layout diff (banteg/storage-layout) as a separate signal: an upgrade can be source-clean yet shift storage slots — diff layouts across impl versions to catch collision-class drift.
- For UNVERIFIED targets, fall back to decompiled-normalized comparison (Dedaub TAC) or semantic similarity (Esim/triplet) rather than literal-byte diff, since optimizer/compiler changes perturb raw bytes.
- Cache explorer + GitHub fetches keyed by address+commit so radar re-polls are cheap and only re-diff when the on-chain impl hash actually changed.

**Pitfalls:**
- Metadata-hash naivety = the #1 false positive: a whitespace, filename, or path change flips the whole metadata hash and looks like total drift. Without CBOR-stripping the radar is unusable noise.
- Don't trust mds1/evm-diff or the 'banteg evm-diff' framing in the brief — the former diffs chains not contracts, the latter doesn't exist. Avoid citing/depending on them as contract-diff engines.
- jmpark-eng36/evm-contract-differ matches our exact use-case in its title but is a placeholder/AI-spam repo with a contradictory README — tempting trap, zero substance.
- Verified-source diff is blind on unverified or proxy-behind-minimal-proxy deployments; you need the bytecode/decompiled path as a fallback or you silently miss drift on exactly the sketchy contracts.
- Solidity compiler/optimizer version changes alter bytecode without any logic change (and vice versa) — literal bytecode diff over-fires; semantic/normalized comparison is the only robust answer but is heavy.
- Multichain explorer API drift: relying on Etherscan-only breaks on the 64 chains we already reach; Diffyscan + Sourcify both support multi-explorer, lean on that rather than hardcoding mainnet.
- Heavy semantic tools (Dedaub API, GNN similarity) are paid/research and will blow the 'single Mac, cheap' constraint — keep them as escalation-only, not the default radar path.

**Applicability to us:** registry.py already stores a reviewed impl-hash per target — that is exactly the anchor Diffyscan's model needs. Concretely: (1) radar.py gets a new `source_drifted` / `bytecode_drifted` check that, when proxy_upgraded or impl-hash-changed fires, runs a Diffyscan-style diff of the NEW verified source vs the GitHub commit we recorded at triage time, pushing to the re-hunt queue with the diff hunks as prior notes. (2) The hard noise-filter the brief calls out is solved by Diffyscan's `allowed_diffs` allowlist + Sourcify's partial_match logic: store a per-target allowlist of known-benign hunks in registry.py so re-polls only surface NEW drift. (3) Implement CBOR-metadata-stripping in a small helper before any bytecode compare — this is the single highest-leverage line of code for precision. (4) Categories -> batch actions maps perfectly: when an upstream fork-base (Aave/Compound/Lagoon) ships a CVE/audit-tag bump, radar diffs that base's new tag against the old, then re-scans ALL our forks of that base for whether they inherited the changed lines — a category-level source-diff fan-out. (5) For our unverified or hardened targets, escalate to banteg/storage-layout (slot-collision drift) or Dedaub (decompiled diff) only on demand. Self-hostable + cheap: Diffyscan + Sourcify API + cast, all run on the single Mac with the Etherscan-v2 key we already have.

**Recommendation:** REUSE, don't build. Adopt lidofinance/diffyscan as the engine for radar.py's source/bytecode drift check rather than writing our own differ — it already nails the three things that are annoying to get right (constructor-simulated bytecode reconstruction, multichain explorer fetch, and an `allowed_diffs` allowlist that IS our noise filter). Wrap it: feed it registry.py's (address, github-commit) pairs, trigger on impl-hash change / proxy_upgraded, and persist per-target allowlists so re-polls only fire on new hunks. Write exactly one piece of custom code — a CBOR/metadata-strip + Sourcify-style full/partial match helper — because that single step is what separates signal from noise and is too central to outsource blindly. Borrow banteg/storage-layout for the upgrade-safety (slot-collision) signal that pure source-diff misses. Keep Dedaub and GNN-similarity as paid/heavy escalation only. Explicitly do NOT depend on mds1/evm-diff (chain-diff, wrong tool) or jmpark-eng36/evm-contract-differ (spam stub).

---

## bounty-contest-aggregation

**State of the art.** Every major audit-contest/bounty platform except HackenProof exposes an UNDOCUMENTED-but-public JSON API that returns the full program/contest list with stable IDs and start timestamps — so "detect a new program the hour it launches" is a solved, cheap polling problem, not a scraping problem. I verified all four live today: Immunefi (immunefi.com/public-api/bounties.json, 263 programs, includes in-scope asset addresses), Code4rena (code4rena.com/api/v1/audits -> data.audits[]), Cantina (cantina.xyz/api/v0/competitions, 143 items w/ status+timeframe+createdAt), and Sherlock (audits.sherlock.xyz/api/contests, paginated items[] w/ starts_at). The proven open-source pattern is infosec-us-team's GitHub-Actions cron bot that snapshots each program to JSON and commits diffs — git history IS the noise filter. Note: Code4rena announced wind-down (May 2026, community/bounties migrating to Immunefi), so weight Immunefi/Cantina/Sherlock going forward.

**Tools / repos / APIs:**
- **[STEAL] Immunefi public API (bounties.json + bounty/{slug}.json)** — https://immunefi.com/public-api/bounties.json  
  Undocumented public JSON. Verified live: HTTP 200, 263 programs, ~6.5MB. Each entry has slug, launchDate, updatedDate, maxBounty, ecosystem/chain, and the IN-SCOPE asset list with on-chain addresses/repos. Per-program detail at /public-api/bounty/{slug}.json.
- **[STEAL] infosec-us-team/Immunefi-Bug-Bounty-Programs-Unofficial** — https://github.com/infosec-us-team/Immunefi-Bug-Bounty-Programs-Unofficial  
  GitHub-Actions cron bot: scrapper.sh curls bounties.json, iterates slugs, writes ./project/{slug}.json, and COMMITS changes. before/after diff of any program = its git history. This is exactly the snapshot-and-diff noise-filter pattern radar.py needs.
- **[LEARN-FROM] infosec-us-team/ibb** — https://github.com/infosec-us-team/ibb  
  Rust CLI, 'jq for the Immunefi REST API' — list programs, fetch by name, recursively filter nested fields (assets, urls, impacts). Good reference for ergonomic querying over the same endpoint we'd poll.
- **[STEAL] Code4rena audits API** — https://code4rena.com/api/v1/audits  
  Verified HTTP 200 JSON. Returns {data:{audits:[...]}, pagination}; each audit has contestId, auditType, codeAccess, hasLiveCode, reportExpectedBy, details. Stable contestId for new-vs-seen. Caveat: C4 winding down May 2026.
- **[STEAL] Cantina competitions API** — https://cantina.xyz/api/v0/competitions  
  Verified HTTP 200 JSON, 143 competitions. Fields: id (uuid), name, status (active/complete/upcoming), timeframe{start,end}, createdAt, kind (public_contest), totalRewardPot, kycRequired. createdAt enables hour-of-launch detection.
- **[STEAL] Sherlock contests API** — https://audits.sherlock.xyz/api/contests  
  Verified HTTP 200 JSON, paginated {page,items,total,has_next}. Each item: id, type_label (Public Bug Bounty / contest), starts_at+ends_at (epoch), prize_pool, private flag, judging_progress. Mirror at mainnet-contest.sherlock.xyz/contests.
- **[PAID-REFERENCE] VigilSeek** — https://www.vigilseek.com/  
  Web aggregator UI over Cantina/HackenProof/Immunefi/Sherlock/CodeHawks/Code4rena. No public API/RSS found; useful only to cross-check coverage and as a feature reference. Returned 404 to direct fetch (JS app).
- **[PAID-REFERENCE] Daily Warden** — https://www.dailywarden.com/  
  Email-digest aggregator of active+upcoming contests across platforms. Push/daily cadence (too slow for hour-of-launch), no API. Reference for the digest UX only.
- **[LEARN-FROM] SCH audit-competitions tool page** — https://smartcontractshacking.com/tools/web3-auditing-competitions-and-bug-bounties  
  Curated live tracker/filter of active competitions+bounties across all platforms. Marketing/lead-gen site, no API; good canonical list of which platforms exist to cover.
- **[AVOID] HackenProof programs** — https://hackenproof.com/programs  
  No open JSON API: /api/v1/programs returned HTTP 403 (Cloudflare). Would need headless-browser scrape or HTML parse; lowest-priority/most-fragile source.

**Techniques to adopt:**
- Poll-and-diff against stable IDs: for each platform keep last snapshot keyed by slug/contestId/uuid/sherlock-id; a NEW key = new program (emit), a changed value on existing key = scope/reward/upgrade change (emit), unchanged = suppress. This IS the meaningful-change filter.
- Git-history-as-audit-log (infosec-us-team pattern): write each program to its own JSON file and commit; `git diff` gives a free, human-readable before/after and dedup for free without a DB.
- Launch-hour detection: key off the earliest stable timestamp per platform — Immunefi launchDate, Cantina createdAt, Sherlock starts_at, C4 contest first-seen — and alert when a never-seen ID appears, rather than waiting for start time (catch 'upcoming' before it opens).
- Field-level change classes (not just new/gone): diff assets[]/scope, maxBounty/rewardPot, status transitions (upcoming->active), and audit-tag/version bumps separately so radar can route (new contest vs scope expansion vs reward bump).
- Asset-address extraction: Immunefi assets[] and Cantina repo URLs carry the actual in-scope addresses/repos — extract and cross-join against registry to auto-detect when a protocol WE already triaged opens a new program.
- Cheap cadence + ETag/If-Modified-Since or size-delta short-circuit on the 6.5MB Immunefi blob to avoid re-parsing when nothing changed.

**Pitfalls:**
- Code4rena wind-down (announced May 2026): bounties/community migrating to Immunefi — don't over-invest in C4; treat Immunefi+Cantina+Sherlock as the durable trio.
- HackenProof has no open API (403/Cloudflare) — any coverage there needs a headless browser (playwright) and will be the flakiest source; consider deferring it.
- Endpoints are UNDOCUMENTED/unofficial: paths/shapes can change without notice (e.g. cantina api/v0 vs v1=404). Wrap each in a tiny adapter and alert on parse failure so a silent schema change doesn't look like 'no new contests'.
- Private/invite-only and KYC programs appear in feeds (Immunefi inviteOnly/kyc, Sherlock private, Cantina kycRequired) — filter these out of the re-hunt queue, they're not actionable white-hat in-scope for us.
- Immunefi blob is ~6.5MB; naive per-poll full re-parse + storing all 263 files balloons git — diff only fields you care about or hash-gate before writing.
- 'createdAt/launchDate' semantics differ per platform (created vs goes-live vs first-indexed); upcoming contests may have a future start but already be in the feed — dedup on ID, not on date, to avoid re-alerting.
- Rate limits / WAF: space polls (every 15-30 min is plenty for 'within the hour') and set a real User-Agent; GitHub's own API rate-limited me mid-task, so don't build the radar on gh search.

**Applicability to us:** Add a `bounty_launch` check family to radar.py alongside the existing proxy_upgraded/url_appears/github_new_repo checks — four thin adapters polling the verified JSON endpoints (Immunefi/Cantina/Sherlock/Code4rena), each normalizing to {platform, stable_id, title, status, starts_at, reward, asset_addrs[]}. Reuse the snapshot-and-diff core (mirror infosec-us-team): persist last snapshot per platform (a JSON file or the ledger), emit ONLY new stable_ids or changed scope/reward/status -> push to the re-hunt queue with prior notes; this directly satisfies radar's 'meaningful change only' mandate. The registry.py join is the high-value bit: extract in-scope asset addresses/repos from Immunefi assets[] and Cantina entries and cross-match against registry's live addresses + fork-base — when a protocol WE already triaged (or a fork of a base we track) opens/expands a program, auto-enqueue a re-hunt with our prior verdict attached. This also feeds the categories->batch-action path: a new contest on a known fork-base can fan out to all our forks of that base, same as the upstream-CVE re-scan trigger.

**Recommendation:** BUILD-by-reuse, do not reinvent. Implement a single `bounty_launch` radar check that polls the four verified JSON endpoints (Immunefi public-api, Cantina api/v0/competitions, Sherlock api/contests, Code4rena api/v1/audits) on a 15-30 min cron and applies radar's existing snapshot-diff to surface only new IDs / scope-reward-status changes. Steal the GitHub-Actions snapshot-commit pattern from infosec-us-team/Immunefi-Bug-Bounty-Programs-Unofficial for the cheapest possible noise filter (git diff = change log). Prioritize Immunefi (richest: in-scope addresses, durable, absorbing C4) and Cantina (clean createdAt for launch-hour). Skip HackenProof for now (no API, Cloudflare 403 — revisit only via playwright if a target ever lands there) and treat Code4rena as legacy/wind-down. Use VigilSeek/Daily Warden/SCH only as coverage cross-checks, not as data sources (no APIs, paid/UI). Wrap each endpoint in an adapter that alerts on parse failure so undocumented schema drift surfaces as a bug, not as a silent empty feed.

---

## whitehat-target-frameworks

**State of the art.** No off-the-shelf whitehat target portfolio manager exists, but the building blocks live in two worlds we should fuse. On the web3 side the strongest reusable artifact is OpenZeppelin Monitor (OSS, Rust, self-hostable) - a config-driven block/event/function watcher with expression filters and pluggable notifications that is essentially radar.py done well; Forta and sec3 WatchTower prove the proxy-upgrade plus bytecode-diff meaningful-change pattern but are heavyweight or paid. On the web2 ASM side reconftw, osmedeus, axiom and nuclei contribute the portfolio-orchestration patterns we want: a target inventory file, a YAML template DB of checks, diff-mode notification that only surfaces NEW findings, and fan-out infra. The hard part - the noise filter - is solved in practice by expression-based trigger conditions, bytecode/source diffing of proxy upgrades against a stored baseline, and diff-since-last-run semantics.

**Tools / repos / APIs:**
- **[STEAL] OpenZeppelin Monitor** — https://github.com/OpenZeppelin/openzeppelin-monitor  
  Self-hostable Rust blockchain monitoring service (135 stars, actively maintained). Per-network JSON config inventory, FilterService with flexible expressions for trigger conditions over events and function calls, TriggerExecutionService, recovery_config for missed blocks, cron scheduling, notifications to Slack/Discord/Telegram/Webhook/custom-script. Docker and docker-compose provided.
- **[LEARN-FROM] sec3 WatchTower (ContractUpdateMonitor)** — https://medium.com/coinmonks/defeat-malicious-contract-upgrades-with-watchtower-contractupdatemonitor-96e551c2f225  
  Monitors proxy upgrades (TPP/UUPS) 24/7, then analyzes the new implementation bytecode against known attack signatures to flag whether the upgrade is potentially malicious - the meaningful-change filter done right: not just alert on upgrade, but diff and classify the new code. SaaS/closed.
- **[LEARN-FROM] Forta forta-bot-sdk / forta-bot-templates** — https://github.com/forta-network/forta-bot-sdk  
  Detection-bot SDK plus ready templates (proxy-upgrade, ownership-change, large-transfer, flashloan detectors). Proven model of small composable on-chain detectors emitting typed alerts. Built for a decentralized scanner network, so operationally heavy for a single Mac.
- **[PAID-REFERENCE] OpenZeppelin Defender SDK** — https://github.com/OpenZeppelin/defender-sdk  
  SDK for OZ Defender, the paid SaaS sibling of Monitor (Sentinels = monitors, Autotasks = reactions). Good UX reference for the monitor/trigger/action model, but hosted and paid; Monitor is the part to self-host.
- **[LEARN-FROM] tintinweb/smart-contract-sanctuary** — https://github.com/tintinweb/smart-contract-sanctuary  
  Massive archive of verified contract source across chains (1.6k stars). Pattern and data source for keeping a stored reviewed-source/impl-hash baseline and diffing verified source over time - supports reviewed-impl-hash and version/audit-tag-bump detection.
- **[LEARN-FROM] reconftw (six2dez)** — https://github.com/six2dez/reconftw  
  Web2 ASM orchestrator (7.7k stars). Adoptable patterns: a single target/scope file drives the whole pipeline; modular stage toggles; and a notification/diff mode that only alerts on NEW findings vs last run - exactly the radar dedup semantic we need.
- **[LEARN-FROM] projectdiscovery/nuclei** — https://github.com/projectdiscovery/nuclei  
  YAML-template vulnerability scanner (29k stars). The template-DB-with-tags model maps onto registry/detector design: tag templates by category, then run all templates carrying a given tag - our categories-to-batch-action (upstream fork CVE then re-scan all forks of that base) is the same select-by-tag fan-out.
- **[LEARN-FROM] pry0cc/axiom** — https://github.com/pry0cc/axiom  
  Distributed scan fan-out framework (4.4k stars) that spins ephemeral workers to parallelize tools across a target list. Reference for scaling our fan-out neod (agent-per-target) to cloud cron without re-architecting.
- **[LEARN-FROM] j3ssie/osmedeus** — https://github.com/j3ssie/osmedeus  
  Orchestration engine with a persistent workspace/DB inventory of targets, a workflow runner, and report diffing (6.4k stars). Closest web2 analog to registry.py plus radar.py as one system; structural reference for target store plus scheduled re-scan.
- **[AVOID] thirdeye-dev/thirdeye** — https://github.com/thirdeye-dev/thirdeye  
  Small OSS smart-contract monitoring project aimed at security engineers (low stars, early). Worth a skim for schema ideas but not mature enough to depend on.

**Techniques to adopt:**
- Config-as-inventory: a declarative per-target file (JSON/YAML) listing chain, addresses and watched events/functions drives the whole watcher - OZ Monitor networks+monitors config is the template for radar.py target config
- Expression-based trigger conditions (OZ Monitor FilterService) instead of code-per-check: the noise filter becomes data, e.g. only fire when an Upgraded event new impl differs from the stored baseline
- Upgrade-then-diff-then-classify (sec3 WatchTower): do not alert on the raw proxy_upgraded event; resolve the full proxy chain, diff new bytecode/source vs reviewed impl-hash, and only surface if the diff is substantive or matches attack signatures
- Diff-since-last-run notification mode (reconftw/osmedeus): persist last state per target, alert only on the delta - kills recurring-alert noise
- Tag/category-driven batch select (nuclei templates): label targets and detectors by fork-base/category so fork-CVE-then-rescan-all-forks-of-base is a tag query, not bespoke code
- Ephemeral fan-out workers (axiom) for scaling the re-hunt queue across many targets on optional cloud cron
- Typed composable detectors emitting structured alerts (Forta bot model) keeps each meaningful-change check small and individually testable
- Persistent target workspace/DB with run history (osmedeus) so radar keeps a memory of prior notes per target, feeding the re-hunt queue

**Pitfalls:**
- Most smart-contract-monitoring GitHub hits are abandoned hobby bots, telegram price bots, or academic projects - signal-to-noise is terrible; verify stars/recency/maintainer before reuse
- Forta is built for a decentralized scanner network (bot registration, scan nodes) - the full stack is overkill for a single Mac; lift only the detector/alert model
- OZ Defender and sec3 WatchTower are paid/hosted SaaS - reference their UX, but the self-hostable path is OZ Monitor plus your own diff logic
- Web2 ASM tools (reconftw/axiom/nuclei) are tuned for DNS/HTTP/subdomain surfaces; their orchestration and diff patterns transfer but none of their actual checks do - adapt the harness, not the templates
- Naive alert-on-every-upgrade or every-new-commit produces alert fatigue; benign upgrades (param tweaks, audited timelocked governance) dominate - the diff-and-classify step is mandatory
- RPC/getLogs gaps cause missed or duplicate events; OZ Monitor recovery_config (missed-block handling) shows you must design for backfill, matching our own getLogs-false-0 lesson
- No tool gives you the is-this-change-worth-re-hunting-by-ME judgment - that stays human; tools should only triage to the queue with prior notes attached

**Applicability to us:** OZ Monitor is the closest thing to a drop-in radar.py engine: its networks/monitors JSON config is a direct analog to registry.py auto-derived inventory (zone/chain/address/watched-fns), its FilterService expressions are how we encode meaningful change as data, and its recovery_config solves the backfill problem we already hit with getLogs false-0. Rather than fork its Rust, port its config schema and filter-expression idea into our existing watch.py (which already has proxy_upgraded/url_appears/github_new_repo). For the noise filter, copy sec3 WatchTower upgrade-resolve-chain-diff-vs-reviewed-impl-hash-classify against registry.py stored reviewed impl-hash, which turns proxy_upgraded from a firehose into a real signal. nuclei tag model is the blueprint for categories-to-batch: tag each registry target by fork-base so upstream-fork-CVE-then-rescan-all-forks is a tag query feeding the re-hunt queue. reconftw/osmedeus give the diff-since-last-run plus persistent-target-workspace semantics radar.py needs so the same change never re-queues twice (mirrors our ledger suppress). axiom matters only if the re-hunt fan-out outgrows a single Mac and moves to cloud cron. smart-contract-sanctuary is a ready baseline corpus for verified-source diffing on version/audit-tag bumps.

**Recommendation:** BUILD on our existing watch.py rather than adopt a framework, but steal aggressively. (1) Port OpenZeppelin Monitor config-as-inventory schema plus expression-based trigger conditions into radar.py - it is the proven self-hostable core and avoids reinventing block-polling/recovery/notifications. (2) Implement the meaningful-change filter as sec3 WatchTower upgrade-diff-vs-reviewed-impl-hash-classify, since raw proxy_upgraded alerts are pure noise. (3) Adopt nuclei-style category/tag selection so categories-to-batch (fork CVE re-scan) is a tag query, and reconftw/osmedeus diff-since-last-run semantics so radar dedups via our ledger. SKIP running Forta or Defender as platforms (network overhead / paid) and AVOID the long tail of low-star monitoring repos. Net: about a week of porting OZ Monitor config and filter ideas plus the upgrade-diff classifier gets us most of a target-portfolio radar without building from scratch.

---

## fork-clone-detection

**State of the art.** Detecting that a deployed contract is a fork/clone of a known base and propagating an upstream CVE to all forks is a solved-but-fragmented problem. At one end is heavy ML/research (bytecode-similarity via doc2vec+FAISS, triplet networks, CFG embeddings) which is overkill and noisy for a 93-target personal registry. At the practical end, the cheap+robust approach is metadata-stripped bytecode hashing + function-selector fingerprinting (whatsabi/evmole) to bucket forks, DeFiLlama's free /forks dataset to enumerate known fork families, and Diffusc (ToB, archived but usable) fork-mode differential fuzzing to actually confirm whether a given fork is vulnerable to a specific upstream CVE. The Compound V2 fork wave (Hundred/Midas/Sonne/Onyx, same empty-market/precision bug across 100+ forks) is the canonical "one CVE -> N forks" pattern this angle must support.

**Tools / repos / APIs:**
- **[STEAL] DeFiLlama Forks (page + API)** — https://defillama.com/forks  
  Free, curated, maintained inventory of which protocols are forks of which base (Compound V2, Aave V2/V3, Uniswap V2/V3/V4, Solidly, Liquity, etc.) with TVL. Reachable via api.llama.fi. The single best free 'who-forked-what' ground-truth.
- **[STEAL] shazow/whatsabi** — https://github.com/shazow/whatsabi  
  JS lib: extracts ABI/selectors from raw bytecode WITHOUT source, resolves proxies (EIP-1967/diamond/etc) to implementation, pulls metadata. 1.1k stars, actively maintained. Ideal selector-set fingerprint + proxy-impl resolver for radar.
- **[STEAL] cdump/evmole** — https://github.com/cdump/evmole  
  Rust/JS/Python: extracts function selectors, arg types, state mutability, storage layout from EVM bytecode even for UNVERIFIED contracts. 443 stars, updated 2026-06. Selector-set -> cheap fork fingerprint that survives non-verification.
- **[LEARN-FROM] crytic/diffusc** — https://github.com/crytic/diffusc  
  ToB tool: auto-generates Echidna differential-fuzz harnesses comparing two contracts; has FORK MODE (two on-chain addresses + RPC) and uses Slither to find upgrade-impacted functions. ARCHIVED Aug-2025 but functional. Use to confirm a fork IS vulnerable to an upstream bug, not just looks similar.
- **[LEARN-FROM] Soptq/forta-contract-simil** — https://github.com/Soptq/forta-contract-simil  
  Forta agent: builds CFG from bytecode, vectorizes per-function via doc2vec, indexes with FAISS, flags new deploys similar to known (scam) contracts at creation time. Only 8 stars; reference architecture for similarity-at-deploy, heavier than needed.
- **[PAID-REFERENCE] Dedaub Decompiler / Security Suite** — https://dedaub.com/feature/api/  
  Gigahorse-based decompiler with 99.98% coverage + clone/similarity analysis over its whole-chain contract index. Free for individuals via UI, REST API is paid for orgs. Best-in-class clone DB but not self-hostable.
- **[LEARN-FROM] acuarica/evm** — https://github.com/acuarica/evm  
  Pure-JS symbolic EVM bytecode parser/decompiler + util to extract selectors and strip CBOR metadata. Useful dependency-light building block for normalizing bytecode before hashing.
- **[AVOID] shmilyiris/ethereum_bytecode_similarity** — https://github.com/shmilyiris/ethereum_bytecode_similarity  
  Small (3 stars) research-grade bytecode-similarity experiment. Indicative of the academic doc2vec/triplet-net direction; not production.
- **[AVOID] jeffchen006/smart-contract-clone-detection** — https://github.com/jeffchen006/smart-contract-clone-detection  
  Repo is EMPTY (no README/code as of 2026-06). Do not cite as a working tool.
- **[LEARN-FROM] BlockSec/Verichains/Hacken write-ups on Compound-fork wave** — https://blog.verichains.io/p/compound-v2-forked-vulnerability  
  Post-mortems of Hundred/Midas/Sonne($20M)/Onyx($2.1M) — same empty-market + precision-loss CVE across 100+ Compound V2 forks. The reference 'one base bug -> propagate to all forks' case study; encodes the exact detection signature (new market mint+donate exchangeRate manip).

**Techniques to adopt:**
- Metadata-stripped bytecode hashing: strip the trailing CBOR metadata (last 2 bytes give length; everything after the IPFS/swarm hash region) then keccak the runtime code. Identical strip-hash = near-certain same compiled source = same fork. Cheapest, zero-ML, deterministic fork bucketing.
- Function-selector-set fingerprinting (whatsabi/evmole): treat the sorted set of 4-byte selectors as a fork signature; Jaccard similarity over selector sets clusters forks even across compiler-version/optimizer drift where exact bytecode differs. Works on UNVERIFIED contracts.
- Proxy-aware resolution before fingerprinting: resolve EIP-1967/diamond proxy to the implementation address first (whatsabi does this) — otherwise every proxy hashes identically and you cluster nothing.
- Two-tier match: tier1 = exact strip-hash (free, certain); tier2 = selector-set Jaccard / CFG-embedding (probabilistic, for near-forks). Only escalate to tier2 when tier1 misses, to keep cost down.
- Diffusc fork-mode differential fuzzing to VERIFY exploitability: don't assume 'looks like Compound V2' => vulnerable; auto-build a diff-fuzz harness base-vs-fork to confirm the specific invariant break (e.g. exchangeRate manip on empty market) actually reproduces on that fork.
- Use DeFiLlama /forks as the seed fork-family taxonomy instead of self-clustering from scratch — bootstrap known base->children edges, then only run similarity to place YOUR targets into a family.

**Pitfalls:**
- Metadata-hash false negatives: a 1-char source/comment change or different compiler/optimizer flips the IPFS hash AND can shuffle bytecode, so exact-hash misses real forks — must back it with selector-set similarity.
- Proxies destroy naive bytecode matching: 90% of live targets are minimal proxies/EIP-1967 — comparing proxy bytecode clusters all proxies together and none of the logic. Always resolve to impl first.
- ML similarity (doc2vec/FAISS/triplet-net) is heavy to host, needs a labeled corpus, and is noisy — high FP rate; wrong tool for a 93-target personal registry where you can afford exact+selector matching.
- 'Same base' != 'same vulnerability': forks patch some bugs and re-introduce others; a CVE-propagation alert that only checks lineage (not the actual vulnerable code path) is pure noise. Confirm the specific function/modifier still matches (or Diffusc-verify) before queuing a re-hunt.
- Diffusc is archived (Aug-2025) and Echidna/Slither version-sensitive — budget setup friction; treat as an on-demand verifier, not an always-on cron job.
- Dedaub's clone DB is the best data but the API is paid and not self-hostable — fine as a manual lookup, do not build radar.py to depend on it.

**Applicability to us:** For registry.py: add a per-target 'fork fingerprint' = {strip-hash(runtime), sorted-selector-set (via whatsabi/evmole on the resolved impl), defillama_fork_family}. This makes the existing 'fork-base' field machine-derived and verifiable instead of hand-labeled, and lets you bucket the 93 targets into fork families. For radar.py: two new checks beside proxy_upgraded — (a) impl_strip_hash_changed (re-fetch impl bytecode, recompute strip-hash; change = real logic upgrade, far less noisy than raw-bytecode or proxy-slot diff) and (b) selector_set_drift (added/removed selectors = new entrypoints worth re-hunting). For categories -> batch actions: store base->[our forks] edges seeded from DeFiLlama /forks plus your own strip-hash/selector clustering; when an upstream CVE drops for a base (e.g. Compound V2 empty-market), the category fans out to every registry target in that family and enqueues them with the prior CVE note — exactly the Hundred/Sonne/Onyx propagation pattern. Optional escalation: Diffusc fork-mode to auto-confirm exploitability before promoting a fork to the re-hunt queue.

**Recommendation:** BUILD a thin self-hosted fork-fingerprint module, REUSE three proven pieces, SKIP the ML clone-detection rabbit hole. Concretely: (1) STEAL whatsabi (proxy resolve + ABI/selectors) and evmole (selectors on unverified) as libs; (2) STEAL DeFiLlama /forks as the free fork-family seed dataset; (3) write ~100 lines: strip-CBOR-metadata + keccak for tier-1 exact fork hash, sorted selector-set + Jaccard for tier-2 near-fork. Wire both as a registry.py-derived field and as two new radar.py checks (impl_strip_hash_changed, selector_set_drift) — these are strictly lower-noise than raw bytecode diffing. For CVE propagation, maintain base->forks edges and fan out on upstream advisories; keep Diffusc as a manual on-demand exploitability verifier (don't cron it). Treat Dedaub as a paid manual cross-check, and AVOID the academic doc2vec/FAISS similarity stacks — they add hosting cost and FPs you don't need at 93 targets.

---

## new-deployment-discovery

**State of the art.** Discovering fresh attack surface (new/funded contracts) on EVM is a solved data problem with three cost tiers: (1) cheap pull-based polling of explorer APIs you already pay nothing for — Etherscan-v2 getcontractcreation / txlist / txlistinternal per deployer & factory across 64 chains; (2) self-hosted bulk extraction of CREATE/CREATE2 traces via cryo, ethereum-etl, Otterscan's ots_ namespace, or HyperSync, when you want a firehose; (3) managed push streams (Alchemy Custom Webhooks "contract creation", QuickNode Streams, Sim by Dune Activity API) and warehouse drops (Dune creation_traces, Allium, Footprint). For a single-Mac personal radar the right pattern is NOT a firehose — it is deployer-scoped + factory-scoped polling (you already own this code in legacy.py) plus a Dune/HyperSync query for periodic factory-child sweeps. The genuinely hard part — your stated noise filter — is unsolved by any of these; they all hand you 10k+ raw deployments/day and leave relevance scoring to you.

**Tools / repos / APIs:**
- **[STEAL] Etherscan-v2 getcontractcreation + txlist/txlistinternal** — https://docs.etherscan.io/api-reference/endpoint/getcontractcreation  
  Single multichain API key resolves contract->creator and (via account txlist/txlistinternal) deployer->all-spawned-contracts incl. internal CREATE2 from factories. You already use exactly this in legacy.py from-deployer/from-factory. getcontractcreation batches up to 5 addrs.
- **[STEAL] paradigmxyz/cryo** — https://github.com/paradigmxyz/cryo  
  1.5k-star Rust/Python tool that extracts blockchain data (incl. `traces` / creation traces, filter type=create) to parquet/csv/json straight off any RPC. The cheapest self-hosted way to get a full CREATE/CREATE2 feed without a paid indexer; run as a cron against an RPC URL.
- **[LEARN-FROM] blockchain-etl/ethereum-etl + BigQuery public datasets** — https://github.com/blockchain-etl/ethereum-etl  
  Mature Python ETL exporting a `contracts` table (and traces) to Postgres/BigQuery. Google's `bigquery-public-data.crypto_ethereum.contracts` is a free queryable mirror — SELECT new contracts by block_timestamp with zero infra.
- **[LEARN-FROM] Otterscan ots_ namespace on Erigon** — https://docs.otterscan.io/api-docs/ots-api  
  ots_getContractCreator + ots_searchTransactions* expose creator/creation-tx and address activity not in stock JSON-RPC, if you self-host an Erigon archive node (--http.api ots,trace). Good if you already run a node; heavy otherwise.
- **[LEARN-FROM] Envio HyperIndex / HyperSync** — https://github.com/enviodev/hyperindex  
  529-star ultra-fast multichain indexer with HyperSync data layer (much faster than getLogs) for many EVM chains, self-hostable, GraphQL out. Useful for periodic factory-child enumeration sweeps across all your chains in one config.
- **[LEARN-FROM] Dune creation_traces / evms.contracts + Sim by Dune Activity API** — https://docs.dune.com/data-catalog/evm/ethereum/raw/creation-traces  
  `<chain>.creation_traces` (filter type=create) gives address+creator+bytecode+block across all EVM chains via one SQL query; Dune API free tier can pull results on a cron. Sim by Dune Activity API gives realtime per-address feed (paid).
- **[PAID-REFERENCE] Alchemy Custom Webhooks (contract creation) / QuickNode Streams** — https://www.alchemy.com/docs/reference/custom-webhook  
  Push-based: Alchemy Custom Webhook can filter 'monitor any contract creation' and POST to your URL; QuickNode Streams runs custom JS filters with guaranteed delivery. Free tiers exist but rate/chain-limited; turns radar from poll to push.
- **[LEARN-FROM] indexsupply/shovel** — https://github.com/indexsupply/shovel  
  245-star config-driven Ethereum->Postgres indexer (declarative JSON, no code). Pattern worth copying: declare a 'tx.to is null' (creation) integration and let it backfill+follow into Postgres you already control.
- **[PAID-REFERENCE] Allium Datastreams / Footprint data-api** — https://www.allium.so/product/allium-developer  
  Enterprise real-time deployment/decoded streams and warehouse drops. Coverage is excellent but pricing is high-4 to mid-5 figures/mo — far outside a personal single-Mac budget.
- **[LEARN-FROM] joshstevens19/rindexer** — https://github.com/joshstevens19/rindexer  
  705-star no-code/framework Rust EVM indexer. Alternative to shovel/Ponder if you want a fast self-hosted indexer with YAML config; reference for the 'declare a contract-creation source -> Postgres/webhook' ergonomics.
- **[AVOID] DeFi pump.fun/uniswap sniper bots (e.g. chainstacklabs/pumpfun-bonkfun-bot)** — https://github.com/chainstacklabs/pumpfun-bonkfun-bot  
  Adversarial reference for low-latency new-deployment/new-pair detection (mempool + factory event tail) WITHOUT 3rd-party APIs. Mine their latency tricks, but most are Solana-only, single-purpose, and not maintainable as infra.

**Techniques to adopt:**
- Deployer-scoped enumeration: poll account txlist + txlistinternal for each known deployer; a contractAddress field / tx.to==null marks a CREATE, and txlistinternal captures factory CREATE2 children (legacy.py already does this — generalize it into a radar check).
- Factory-child enumeration: subscribe to the factory's deployment event (or query creation_traces WHERE from=factory) to enumerate every spawned clone — maps directly to your 'fork CVE -> re-scan all forks of that base' category action.
- Creation-trace filter: the universal primitive is traces WHERE type='create' (or tx.to IS NULL at top level). Every backend (cryo, ethereum-etl, Dune, Otterscan) exposes this; standardize radar on that single predicate.
- New-FUNDED detection (higher signal than new-deployed): watch for first inbound value/ERC20 to a tracked-or-new contract — funding is the Thetanuts/legacy.py 'dormant+funded' signal and a far stronger relevance filter than mere bytecode existence.
- Bytecode-similarity / selector-fingerprint as the noise filter: cluster new deployments by codehash or 4byte-selector set, match against your registry's reviewed impl-hashes and fork-base fingerprints, and only surface deployments that match a category you already hunt (this is the missing relevance layer none of the feeds provide).
- Tiered architecture: cheap poll (Etherscan-v2) for known deployers/factories continuously; periodic bulk sweep (cryo/HyperSync/Dune SQL) for net-new factory discovery; reserve paid push webhooks only for a handful of high-value targets.
- Public BigQuery / Dune free-tier as zero-infra backfill: SELECT contracts by block_timestamp on a cron instead of running a node.

**Pitfalls:**
- Firehose != useful: raw creation feeds are 10k-100k contracts/day/chain, ~99.9% spam tokens/airdrop farms. Without a fingerprint/funding filter the queue is pure noise — the feed is the easy 10%, the filter is the 90%.
- Etherscan-v2 free tier is 5 req/s & ~100k/day; deployer/factory polling fits, a full-chain creation crawl does NOT — don't try to firehose through it.
- getcontractcreation is contract->creator (reverse direction); to go deployer->contracts you must walk account txlist + txlistinternal, and internal CREATE2 only shows in txlistinternal (easy to miss factory children otherwise).
- Otterscan/Erigon and ethereum-etl-to-Postgres are real infra (archive node / TB of storage / sync time) — overkill for ~93 targets on a single Mac; only justified if you already run a node.
- CREATE2 counterfactual deploys: a contract can be funded BEFORE its code exists (address known via salt). Watching only 'code appeared' misses these; watch first-funding too.
- Managed streams (Alchemy/QuickNode/Sim) re-introduce a paid dependency and per-chain config sprawl across your 64 chains — they break the self-hostable+cheap constraint if used broadly.
- Proxy upgrades and 'new bug-bounty launch' are NOT new-deployment events — don't overload the new-deployment pipe with them; they belong to radar's existing proxy_upgraded / url_appears checks.
- Cross-chain dedupe: the same deployer/factory exists on many chains; without chain-keyed identity you'll re-alert the same logical deployment N times.

**Applicability to us:** radar.py: add two checks alongside proxy_upgraded/url_appears/github_new_repo — `deployer_new_contract` and `contract_first_funded`. Both reuse code you ALREADY have: legacy.py from-deployer/from-factory(txlistinternal) and the Etherscan-v2 multichain key (64 chains). For each registry.py row, store the deployer/factory address; radar polls txlist+txlistinternal per cycle and diffs the set of spawned contractAddresses against last seen -> push net-new to the re-hunt queue with the parent target's prior notes already attached. categories: this is the natural source for the 'upstream fork CVE -> re-scan all forks' action — enumerate a factory's children via creation_traces/txlistinternal to materialize every fork instance, tagged with the fork-base category so a base CVE fans out automatically. The noise filter (your hard part) is the registry's own asset: fingerprint each new deployment by codehash/selector-set and ONLY surface ones matching a reviewed impl-hash, a known fork-base, or a category zone you hunt — turning the registry from a passive inventory into the relevance oracle. Tiering: keep the continuous loop on free Etherscan-v2 polling (fits single-Mac cron); reserve a weekly cryo/Dune-free-tier creation_traces sweep to DISCOVER net-new factories/deployers not yet in the registry. Skip Allium/Footprint/managed webhooks unless a specific high-value target justifies one paid stream.

**Recommendation:** BUILD on what you own; do not adopt an indexer. Concretely: (1) Generalize legacy.py from-deployer/from-factory into a radar.py `deployer_new_contract` check that diffs txlist+txlistinternal-derived child sets per registry target — zero new dependency, reuses the Etherscan-v2 key across 64 chains. (2) Add a `contract_first_funded` check (first inbound value/ERC20) — higher signal than bytecode-appeared, mirrors your proven dormant+funded thesis. (3) Implement the relevance filter as codehash/selector fingerprint matched against registry impl-hashes & fork-bases — this is the differentiator and nobody ships it for you. (4) For net-new discovery (deployers/factories not yet in registry), run a weekly cryo OR Dune-free-tier `creation_traces WHERE type='create'` sweep as a cron, not a live firehose. STEAL: Etherscan-v2 endpoints + cryo. LEARN-FROM: ethereum-etl/BigQuery, HyperSync, Otterscan ots_ namespace, shovel's declarative-source pattern. SKIP/PAID-REFERENCE: Allium, Footprint, Alchemy/QuickNode webhooks (reserve for 1-2 marquee targets only); AVOID sniper-bot repos as infra.

---

## protocol-vuln-taxonomy

**State of the art.** There are two orthogonal axes to seed a registry with, and mature open schemas exist for both — don't invent your own. PROTOCOL-TYPE axis: DeFiLlama's category taxonomy (Lending, Dexes, CDP, Liquid Staking, Bridge, Derivatives/Perps, RWA, Yield, Restaking...) is the de-facto industry standard, machine-readable via a free API, and already maps to your "zone" field. VULN-CLASS axis: SWC Registry (frozen but canonical SWC-IDs), DASP-10 (outdated 2018), and especially OWASP Smart Contract Top 10 2025 (SC01-SC10, re-ranked from real 2024 incident loss data — Access Control #1 at $953M, Oracle Manipulation #2, Flash Loan, Logic Errors) are the live standards. Immunefi's Vulnerability Severity Classification System (v2.3) is the canonical IMPACT taxonomy (theft-of-funds / insolvency / freezing...) and is what actual bounties pay against, so it should drive your verdict/severity field, not the academic class. The hard part you flagged (meaningful-change filtering) is unrelated to taxonomy choice — taxonomy only buys you the category->batch-action routing (e.g. fork-CVE re-scan).

**Tools / repos / APIs:**
- **[STEAL] DeFiLlama Protocol Categories + API** — https://defillama.com/categories  
  De-facto industry protocol-type taxonomy: Lending, Dexes, CDP, Liquid Staking, Bridge, Derivatives (Perps), RWA, Yield, Restaking, Yield Aggregator, Basis Trading, etc. Free API (api.llama.fi/protocols returns each protocol's `category` + `chains` + addresses) — already a CORE-address source in your scout.py/fetch_source.py.
- **[STEAL] OWASP Smart Contract Top 10 (2025/2026)** — https://github.com/OWASP/www-project-smart-contract-top-10  
  Current, actively-maintained vuln-class taxonomy with stable codes SC01..SC10 (Access Control, Price Oracle Manipulation, Logic Errors, Input Validation, Reentrancy, Unchecked External Calls, Flash Loan, Integer Over/Underflow, Insecure Randomness, DoS). Re-ranked from 2024 incident loss data. 76 stars, markdown in-repo — easy to vendor as a code->label map.
- **[STEAL] Immunefi Vulnerability Severity Classification System v2.3** — https://immunefi.com/immunefi-vulnerability-severity-classification-system-v2-3/  
  Canonical IMPACT taxonomy used by real bounties: Critical = direct theft of user funds (at-rest/in-motion) or protocol insolvency; High = temporary freezing; etc. 'Primacy of Impact'. This is what determines payout, so it's the right schema for your verdict/severity dimension rather than academic class.
- **[LEARN-FROM] SWC Registry** — https://github.com/SmartContractSecurity/SWC-registry  
  Canonical historical weakness IDs (SWC-100..SWC-136) mapped to CWE. Officially frozen/deprecated in favor of EEA EthTrust + OWASP, but SWC-IDs are still the lingua franca many tools/audits cite. Python/JS/Go accessor libs exist.
- **[AVOID] DASP Top 10** — https://dasp.co/  
  The classic 10-bucket taxonomy (Reentrancy, Access Control, Arithmetic, Unchecked Low-Level Calls, DoS, Bad Randomness, Front-Running, Time Manipulation, Short Addresses, Unknown). Last updated 2018 — superseded by OWASP SC Top 10; useful only as historical label cross-reference.
- **[STEAL] Cyfrin Solodit Audit Checklist** — https://solodit.cyfrin.io/checklist  
  370+ concrete, categorized audit checklist items (by category: Governance, Oracle, ERC20, Reentrancy, Vault/share-math, etc.) aggregated from real audit findings. The most granular, hunter-oriented taxonomy. Mirrored as an installable skill (raihanmd/solodit-checklist-audit-skills) and queryable findings API (giannistbs/solodit-findings-mcp).
- **[LEARN-FROM] DeFiHackLabs incident corpus** — https://github.com/SunWeb3Sec/DeFiHackLabs  
  6.6k-star reproduced-incident repo you already mine. Each PoC is tagged by attack type — gives an empirical, frequency-weighted vuln taxonomy grounded in what actually got exploited (your 53-pattern mining already derives from this).
- **[LEARN-FROM] SoK: Unified Data Model for SC Vulnerability Taxonomies (ds-square)** — https://github.com/ds-square/smart-vulnerabilities  
  ARES'24 academic work that reconciles SWC/DASP/SmartBugs/etc. into one unified data model with cross-taxonomy mappings. Low stars but the mapping table is the value: lets you translate between SWC-ID <-> DASP <-> OWASP labels.
- **[PAID-REFERENCE] EEA EthTrust Security Levels** — https://github.com/EntEthAlliance/wg-ethtrust-registry  
  Enterprise Ethereum Alliance's formal successor to SWC — leveled security requirements spec. Heavyweight/compliance-oriented; useful as a reference for the 'official' replacement of SWC but overkill for a personal registry.
- **[LEARN-FROM] Rekt News Leaderboard** — https://rekt.news/leaderboard/  
  Curated largest-hacks list with informal root-cause tagging (exit scam / flash loan / oracle / access control / bridge). No structured export/API — scrape-only, editorialized. Good for sanity-checking which categories actually lose the most money.

**Techniques to adopt:**
- Use TWO independent taxonomy axes, not one: (A) protocol-type/zone from DeFiLlama categories, (B) vuln-class from OWASP SC Top 10 — keep them as separate registry columns so category->batch-action can fan out on either axis.
- Add a THIRD impact axis (Immunefi severity) decoupled from vuln-class — same class can be Critical or Low depending on reachability; matches your existing 'callability != code-bug' lesson.
- Vendor taxonomies as small frozen JSON label-maps with stable codes (SC01.., SWC-1xx, DeFiLlama category strings) rather than free-text — enables deterministic ledger keys and dedupe.
- Maintain a cross-walk table (SoK unified model) so a finding tagged once can be reported in whichever vocabulary a given bounty program expects.
- Frequency-weight your vuln categories from DeFiHackLabs/Rekt loss data so the radar re-hunt queue prioritizes high-$ classes (oracle, access-control, bridge), matching where money actually leaks.
- DeFiLlama's `category` field is fetchable per-protocol via api.llama.fi — auto-derive registry.py 'zone' instead of hand-labeling 93 targets.

**Pitfalls:**
- DASP-10 and SWC are both effectively frozen (2018 / deprecated) — anchoring your schema on them alone will miss the modern money-losers (flash-loan, oracle-manip, proxy-upgrade, vault share-math). Use OWASP SC Top 10 2025 as primary.
- Academic taxonomies (SWC/SoK) are detection-class oriented; bounties pay on IMPACT. If your verdict field mirrors only the academic class you'll mis-prioritize. Keep Immunefi impact separate.
- Taxonomy granularity mismatch: OWASP/SWC are ~10-30 buckets; your detectors (41) and real findings are finer (e.g. det_vault_share_math, det_decimal_scale). Map detectors->OWASP many-to-one, don't force your detectors into 10 buckets.
- DeFiLlama categories are coarse and occasionally mis-labeled (a perp protocol filed under Derivatives, restaking churn). Treat the API category as a seed/default, allow manual override in registry.
- Rekt leaderboard has no API and is editorialized — fine for eyeballing loss-weighting, not as a structured feed.
- Don't build a taxonomy microservice. This is static reference data — a checked-in JSON + a crosswalk is the whole job; the engineering effort belongs in radar.py's noise filter, not here.

**Applicability to us:** Concretely for our stack: (1) registry.py 'zone'/category column should be seeded from DeFiLlama's `category` (fetchable via api.llama.fi/protocols, already wired through scout.py/fetch_source.py) with manual override — auto-categorizes the 93 targets instead of hand-labeling. (2) Add a vendored toolkit/taxonomy.json with OWASP SC01-SC10 + SWC-ID + DASP labels and a crosswalk (from the SoK unified model), and map each of recon.py's 41 detectors to an OWASP code (many-to-one) so a hit emits a standard label into the ledger. (3) verdict/severity should carry an Immunefi-v2.3 impact tag (theft/insolvency/freezing) separate from the vuln-class, reinforcing the existing callability-gate lesson. (4) categories->batch-action: tag each target with both DeFiLlama-category AND fork-base; an upstream fork CVE re-scans by fork-base, an oracle-class disclosure re-scans all 'Lending'+'Derivatives'-zone targets. (5) radar.py meaningful-change detection is orthogonal — taxonomy only feeds the routing of the re-hunt queue, not the change-detection itself.

**Recommendation:** REUSE, don't build. Seed registry.py with two vendored axes: protocol-type from DeFiLlama categories (auto-pulled via the API you already call) and vuln-class from a checked-in JSON of OWASP Smart Contract Top 10 2025 (SC01-SC10) as primary, with SWC-IDs/DASP as alias columns for cross-referencing (use the ds-square SoK crosswalk). Add an Immunefi v2.3 impact tag as a separate severity dimension. Map your 41 detectors many-to-one onto OWASP codes so ledger entries get a standard label. Skip EEA EthTrust (compliance overkill) and don't anchor on DASP (stale). Optionally pull the Cyfrin Solodit checklist (370+ items) as the fine-grained heuristic layer feeding hypothesize.py. Total effort: one taxonomy.json + a detector->code map + a DeFiLlama category fetch — a few hours, no new service. Spend real engineering on radar.py's noise filter, which no taxonomy solves.

---

## alert-noise-suppression

**State of the art.** The on-call/SIEM world solved "drowning in alerts" with a small, battle-tested toolkit: a deterministic dedup key (a.k.a. fingerprint) per alert, time-windowed grouping/debounce (group_wait/group_interval/repeat_interval), inhibition (suppress B while A fires), silences/snooze (allow-deny matchers over a TTL), and rule-fidelity scoring to retire low-value rules. The dominant open-source references are Prometheus Alertmanager (grouping+inhibition+silences) and Keep/keephq (SHA-256 fingerprint dedup with partial vs full modes + a CEL rules engine for correlation). For OUR domain the "change-significance" half is unsolved by generic tooling and is the real work: a raw proxy Upgraded event is noise; the meaningful signal is a storage-layout/bytecode/selector diff vs the reviewed impl-hash (OpenZeppelin upgrades-core storageLayout, Slither --check-upgradeability). Steal the dedup-key + suppression-window + inhibition primitives wholesale; build the significance scorer ourselves.

**Tools / repos / APIs:**
- **[LEARN-FROM] Prometheus Alertmanager** — https://github.com/prometheus/alertmanager  
  Canonical noise-suppression model: alerts are deduped by a label-set fingerprint; group_by collapses related alerts into one notification; group_wait/group_interval/repeat_interval are the debounce + re-notify windows; inhibition_rules mute dependent alerts while a parent fires; silences are matcher-based time-boxed mutes. All config-as-YAML, single Go binary, trivially self-hostable.
- **[STEAL] Keep (keephq/keep)** — https://github.com/keephq/keep  
  Open-source AIOps alert mgmt (~12k stars). Dedup = SHA-256 hash over the alert dict after stripping configured fingerprint fields; two-tier: full-dup (same hash -> suppress) vs partial-dup (same fingerprint, different hash -> treat as UPDATE not new). Correlation rules use Google CEL (cel-python) to map alerts -> incidents. Docs at docs.keephq.dev/overview/deduplication.
- **[STEAL] Keep deduplication docs** — https://docs.keephq.dev/overview/deduplication  
  Precise spec of partial vs full dedup and the strip-then-hash fingerprint algorithm — directly portable as radar.py's change-key design.
- **[LEARN-FROM] Alerta** — https://github.com/alerta/alerta  
  Lightweight alert console (~2.5k stars). Core idea worth stealing: alert de-dup by (resource, event, environment) correlate-key + a status lifecycle (open/ack/closed) so a repeated signal bumps a counter+timestamp on the EXISTING record instead of spawning a new one. Maps cleanly to one re-hunt-queue row per target.
- **[STEAL] OpenZeppelin upgrades-core (storageLayout)** — https://github.com/OpenZeppelin/openzeppelin-upgrades  
  storageLayout extraction + layout-compatibility diff between implementations. This is the significance-scorer for the proxy_upgraded check: turns a raw Upgraded event into 'storage layout changed / selectors added / unrelated' — the meaningful-change signal radar.py needs.
- **[STEAL] Slither --check-upgradeability** — https://github.com/crytic/slither  
  Static detector that diffs two implementations for upgrade-relevant changes (storage collisions, changed/added functions, init issues). Run it impl-N-1 vs impl-N to score whether an upgrade is hunt-worthy.
- **[LEARN-FROM] Grafana OnCall** — https://github.com/grafana/oncall  
  Self-hostable on-call/incident routing. Its grouping + ack-suppression (mute repeats once acknowledged) is the UX pattern for 'I already triaged this change, stop re-surfacing it' — i.e. ledger-backed silence.
- **[PAID-REFERENCE] PagerDuty Event Intelligence** — https://www.pagerduty.com/platform/aiops/  
  Commercial reference for time-window + content-similarity alert grouping and 'intelligent' suppression. Useful for vocabulary (transient/flapping suppression, alert grouping windows) but closed + overkill for a single-Mac setup.

**Techniques to adopt:**
- Dedup/fingerprint key: hash a canonical subset of fields (target+chain+change-type+impl-hash) so the SAME meaningful change collapses to one queue entry; stripping volatile fields (timestamps, block#) before hashing is what makes it stable.
- Partial vs full dedup (Keep): same fingerprint + different content-hash = UPDATE an existing re-hunt item (bump 'last seen', append note); same fingerprint + same hash = suppress entirely. Avoids both dupes and silent staleness.
- Suppression / debounce windows: group_wait (wait N min after first signal to batch), group_interval (min gap before re-notifying a changed group), repeat_interval (re-nag cadence for still-open items). Cheap to implement as timestamps in a SQLite/JSON ledger.
- Inhibition: when a parent fact fires, mute children — e.g. target flagged DEAD/EMPTY (activity.py) => suppress ALL its change alerts; bounty-closed => suppress its contest/version alerts. Encodes dependencies so one root cause != ten pings.
- Silences / allow-deny matchers with TTL: explicit per-target mute (e.g. 'known noisy oracle push, mute price-feed changes for 30d') keyed by matchers, auto-expiring so mutes don't rot.
- Change-significance scoring: don't alert on the raw event; score the DIFF. Storage-layout change / new selectors / new external call = high; comment/metadata-only or re-verify with identical bytecode = drop. This is the proxy_upgraded false-positive killer.
- Rule-fidelity scoring (SIEM tuning): periodically score each radar check on fidelity/actionability (how often its alerts led to a real re-hunt); retire/downgrade chronic-FP checks instead of letting them desensitize you.
- State-transition (not level) alerting: fire on EDGE (clean->upgraded, no-bounty->bounty) once, not on every poll while the state persists — classic flapping/level-vs-edge fix.
- Thresholding/count-then-fire: only surface after a signal crosses a frequency or persists across K polls, filtering transient RPC/getLogs false-zeros (death.fun lesson already in activity.py).

**Pitfalls:**
- Generic dedup (Alertmanager/Keep) dedupes IDENTICAL alerts — it does NOT decide whether a smart-contract change is MEANINGFUL. The hard part (storage-diff/selector-diff significance) is entirely on us; importing Keep does not solve it.
- Fingerprint over-inclusion: if the dedup key includes volatile fields (block number, poll timestamp, RPC node), every poll looks 'new' and you get a flood. Under-inclusion: key too coarse -> two distinct upgrades collapse and you miss one. Tune the stripped-field set deliberately.
- Silences/suppressions that never expire become blind spots — a muted target that later gets a real bug. Always TTL mutes and surface a 'currently suppressed' audit list.
- Inhibition can hide real signal: muting a DEAD target's alerts is right until it gets re-funded/re-deployed; the EMPTY->live edge must NOT be inhibited.
- Bringing up a full Alertmanager/Keep stack (Go service + Postgres + web UI) is over-engineering for ~93 targets on one Mac; steal the algorithms, not the deployment. A SQLite ledger + cron is the right weight.
- Re-verify-after-noop: a contract re-verified on Etherscan with identical bytecode emits 'source changed' style signals that are pure noise — gate on bytecode/impl-hash equality, not on metadata.
- Acknowledgement state must persist across cron runs (cloud + local), or every invocation re-alerts already-triaged changes; the ledger is the source of truth, not process memory.

**Applicability to us:** radar.py should adopt three primitives directly. (1) A dedup/fingerprint key per (target, change_type): for proxy_upgraded use the NEW impl-hash; for bounty/contest use a normalized URL+payout; for version/audit-tag use the tag string. Strip block#/timestamp/RPC-node before hashing (Keep's strip-then-SHA256). Persist in the existing ledger.py so the same change never enqueues twice — this is exactly Keep's partial(=UPDATE existing re-hunt note) vs full(=suppress) split, and it generalizes watch.py's three existing checks. (2) A significance scorer on top of proxy_upgraded: don't enqueue on the raw Upgraded event — run OpenZeppelin upgrades-core storageLayout (or Slither --check-upgradeability) reviewed-impl vs new-impl and only enqueue HIGH (storage-layout change / new selectors / new external calls), drop metadata-only/identical-bytecode re-verifications. This is the meaningful-change filter the feature calls 'the hard part'. (3) Inhibition + edge-triggering wired to your existing gates: registry verdict EMPTY/DEAD (activity.py) inhibits that target's change alerts (but NOT the EMPTY->live edge), bounty-closed inhibits its contest alerts, and every check fires on state EDGE not on every poll. For categories -> batch actions, the 'upstream fork CVE -> re-scan all forks of base X' fan-out is itself an alert burst: dedup it under one parent fingerprint (the CVE/base id) and group_wait-batch the per-fork enqueues so you get ONE 'N forks affected' item, not N pings. Add periodic rule-fidelity scoring via calibrate.py (which check's alerts actually led to a re-hunt) to retire chronic-FP radar checks.

**Recommendation:** BUILD the noise filter ourselves but STEAL the proven primitives — do not deploy Alertmanager/Keep as services (over-weight for ~93 targets on one Mac). Concretely: (a) add a strip-then-hash fingerprint + partial/full dedup to radar.py backed by ledger.py (Keep's algorithm, ~30 lines); (b) implement a change-significance scorer that gates proxy_upgraded on a storage-layout/selector diff via OpenZeppelin upgrades-core / Slither --check-upgradeability — this is the single highest-leverage piece and the only one without good generic prior art; (c) port Alertmanager's three control knobs as ledger fields: suppression-window (debounce repeat polls), inhibition (DEAD/EMPTY/bounty-closed parents mute children, except the EMPTY->live edge), and TTL'd silences (manual per-target mutes that auto-expire). Edge-trigger every check. Feed FP rates back through calibrate.py to retire noisy checks. Skip ML/clustering and any hosted SIEM — deterministic keys + significance diff + inhibition cover the noise problem at our scale.

---

## asset-inventory-datamodel

**State of the art.** Mature ASM/CAASM systems converge on one core data-model idea: never hand-curate the inventory — DERIVE it from sources on every sync, and use timestamp-based reconciliation (firstseen / lastupdated + an UPDATE_TAG per run) to auto-expire records that the source no longer reports. Cartography (CNCF) is the canonical reference: MERGE-on-stable-id for dedup, two temporal fields per node/edge, and a scoped DETACH-DELETE cleanup of any node whose lastupdated != current run-tag — that single pattern is the anti-rot engine. Faraday adds the multi-tool dedup/merge layer (collapse the same host/finding seen by N scanners into one canonical entity), and OCSF gives a normalized schema vocabulary. The hard part everyone hits is exactly yours: distinguishing a meaningful change from sync noise, which is solved by diffing the previous synced state against the new one and emitting change-events only on whitelisted attributes.

**Tools / repos / APIs:**
- **[STEAL] cartography (CNCF, ex-Lyft)** — https://github.com/cartography-cncf/cartography  
  Python tool that syncs cloud/SaaS assets + relationships into Neo4j. Data-model gold: every node/edge carries firstseen + lastupdated; each sync run stamps an UPDATE_TAG; dedup via MERGE on an external stable id (never invent your own id); cleanup = DETACH DELETE where lastupdated != current tag (scoped per 'tenant'). cascade_delete for hierarchies. Custom security flags on nodes (exposed_internet, anonymous_access).
- **[LEARN-FROM] Faraday** — https://github.com/infobyte/faraday  
  Open-source vuln-management platform that ingests 90+ tools and normalizes/dedups into Host/Service/Vulnerability entities. Merge engine: same host found by Nmap+Nessus collapses to one record; vulns deduped by (host, service, CVE/name). The 'many noisy sources -> one canonical asset' merge logic is the part to learn from.
- **[LEARN-FROM] OCSF schema** — https://github.com/ocsf/ocsf-schema  
  Open Cybersecurity Schema Framework: attribute dictionary + event classes incl. an inventory/'device' entity and change/activity event classes. A vendor-neutral vocabulary for naming your fields so you don't reinvent attribute names.
- **[LEARN-FROM] CloudQuery** — https://github.com/cloudquery/cloudquery  
  ELT for cloud/SaaS config into a SQL DB (asset inventory as plain Postgres tables). Declarative source plugins -> normalized relational tables; incremental syncs. Shows the 'inventory = derived tables you re-query with SQL' model — simpler than a graph DB for ~93 rows.
- **[AVOID] Steampipe** — https://github.com/turbot/steampipe  
  Zero-ETL: query live APIs as SQL tables, no DB to keep fresh (the inventory is recomputed on read). Relevant tension: live-derive vs. materialize. For radar you WANT materialized prior state to diff against, so this is the anti-pattern reference.
- **[LEARN-FROM] natlas** — https://github.com/natlas/natlas  
  Self-hosted ASM that scans hosts on a schedule and stores timestamped scan snapshots, surfacing diffs between scans. Good small-scale reference for snapshot-per-run + diff-to-detect-change on a single box.
- **[LEARN-FROM] nuclei** — https://github.com/projectdiscovery/nuclei  
  YAML-template scanner. Not an inventory itself, but the YAML-template-as-detector model maps onto your radar.py 'check' registry (proxy_upgraded/url_appears as templates). Output is per-target findings you'd fold back into the inventory.
- **[LEARN-FROM] open-asm (OASM)** — https://github.com/oasm-platform/open-asm  
  Newer open ASM platform (asset discovery + scan orchestration + result store). Worth a glance for its entity schema, but young (~130 stars) and infra-asset oriented, not contract-oriented.
- **[PAID-REFERENCE] RegScale** — https://regscale.com  
  Commercial GRC/CMDB-as-code with continuous control + asset sync. Reference only for the 'CMDB Configuration Item + relationships + change-control' framing; closed and overkill.

**Techniques to adopt:**
- Source-of-truth derivation: treat registry.py as a PURE PROJECTION of upstream sources (scout/fetch_source/on-chain). Never edit the inventory by hand; re-derive on each run so it can't rot.
- UPDATE_TAG reconciliation (cartography's core): stamp every record with the run timestamp on sync; anything whose lastupdated != latest run is stale -> mark dead/archived instead of silently lingering.
- firstseen + lastupdated on every entity AND every relationship: cheap audit trail + powers 'new since last run' and 'gone since last run' change-events for free.
- MERGE on an EXTERNAL stable id, never a self-minted one: for contracts the natural key is (chain, address); for impl use reviewed impl-hash. Upsert semantics give you idempotent dedup.
- Multi-source merge (Faraday): when the same target arrives from Immunefi + DefiLlama + a contest, collapse to one canonical entity keyed by (chain,address) and keep a 'sources[]' provenance list rather than duplicate rows.
- Change-event modeling as first-class rows: don't overwrite-in-place. Append an immutable event {entity, attr, old, new, run_tag, ts}; radar's queue is just a filtered view over the meaningful subset of these events.
- Whitelisted-diff to kill noise: only certain attribute deltas are 'meaningful' (impl_hash, proxy_admin, bounty_status, audit_tag, version). Diff is computed over the whole snapshot but events are emitted ONLY for the whitelist — exactly your noise-filter requirement.
- Snapshot-per-run + diff (natlas): persist last synced state per target so radar compares new-vs-prior locally; no need for the source to tell you what changed.
- Tag/category as derived facets, not free-text: zone/chain/fork-base/verdict are computed labels, enabling category->batch actions (fork CVE -> select all entities where fork_base=X).

**Pitfalls:**
- Inconsistent/invented IDs are the #1 dedup killer — if you key on anything but (chain, lowercased-address) you'll get phantom duplicates across sources. Normalize address casing + chain id before MERGE.
- Aggressive stale-deletion is dangerous for a hunt registry: cartography DELETEs stale nodes, but you want to ARCHIVE (verdict=dead/dormant) not erase — your legacy.py 'dormant+funded' class proves dead-looking targets still matter. Use soft-expire.
- Graph DB (Neo4j) is overkill at ~93 targets; you'd inherit ops cost for no benefit. The VALUE is the firstseen/lastupdated/UPDATE_TAG reconciliation pattern, not the graph engine — keep it in SQLite/JSON.
- Overwrite-in-place loses the very signal radar needs. If you mutate impl_hash on the row without emitting an event, the upgrade is invisible. Always diff-then-emit before write.
- OCSF is heavyweight and enterprise/IT-asset shaped; adopt a few field NAMES, don't drag in the full taxonomy.
- Steampipe-style live-query (no materialized state) makes change-detection impossible — you must persist prior state to diff against.
- Multi-source provenance collapse can hide a NEW source signal (e.g., a target newly appearing on Immunefi is itself a meaningful event). Track per-source firstseen, not just entity firstseen.
- Sync flakiness causes false 'gone' events: a source timing out shouldn't expire targets. Gate cleanup on a successful full sync per source (cartography's scoped-cleanup lesson).

**Applicability to us:** registry.py = cartography's node store: give every target firstseen + lastupdated + last_run_tag, key (dedup/MERGE) on (chain, lower(address)), and re-derive the whole table from scout.py/fetch_source/on-chain each run rather than hand-editing — that is the anti-rot guarantee. Store zone/chain/fork-base/verdict/reviewed-impl-hash as derived facets so categories->batch actions become a trivial WHERE filter (fork_base='Aave' -> re-scan queue). radar.py = cartography's cleanup + a change-event table: instead of DETACH DELETE, do a soft reconcile — any target not re-seen this run gets verdict-aged (dormant/dead, not erased, per legacy.py), and any whitelisted attribute delta (impl_hash, proxy_admin, bounty_status, audit_tag, version) appends an immutable event row that feeds the re-hunt queue with the prior HUNT.md notes attached. radar's existing proxy_upgraded/url_appears/github_new_repo are just three event-emitters in that whitelist; generalize them into a small check-registry (nuclei-template-style) all writing the same {entity,attr,old,new,run_tag} event shape. Faraday's merge logic maps onto your multi-source fan-in (same target from Immunefi+DefiLlama+contest -> one row, sources[] provenance, per-source firstseen so a NEW listing is itself an event). Keep it all in SQLite/JSON on the Mac — skip Neo4j/CloudQuery; steal only the reconciliation pattern.

**Recommendation:** BUILD it yourself but steal cartography's reconciliation model wholesale — it is ~30 lines of logic, not a dependency. Concretely: (1) add firstseen/lastupdated/last_run_tag to each registry entry and re-derive registry.py from sources every run (pure projection, no hand-edits); (2) MERGE/upsert keyed on (chain, lowercased address) with a sources[] provenance array (Faraday-style fan-in dedup); (3) make radar.py diff new-vs-prior snapshot and append immutable change-events ONLY for a whitelist of meaningful attrs (impl_hash, proxy_admin, bounty_status, audit_tag, version, new-source) — that whitelist IS your noise filter; (4) soft-expire (verdict-age to dormant/dead) instead of deleting, gated on a successful per-source sync to avoid false 'gone' events. Do NOT adopt Neo4j (cartography), CloudQuery, or Steampipe — at ~93 targets they are pure ops overhead; SQLite + JSON is correct. Borrow a handful of OCSF field names for consistency, nothing more. Generalize the existing 3 watch.py checks into a small template-style check-registry, all emitting the same event shape.

---

## scheduling-monitoring-arch

**State of the art.** For a single-Mac + optional-cloud whitehat radar the proven pattern is a three-layer split: (1) a dumb scheduler that just fires the job (launchd on Mac, a cheap cloud cron as redundant backstop), (2) a dead-man's-switch heartbeat monitor so a SILENTLY missed run is itself an alert (healthchecks.io self-hosted or free hosted tier), and (3) a fan-out notifier abstraction (Apprise / ntfy) so radar.py never hardcodes Telegram/Discord/desktop. The scheduler choice matters less than people think — the hard guarantees come from heartbeats + idempotent state, not from the cron engine. Critical gotcha: GitHub Actions cron and Cloudflare Workers cron BOTH silently drop/delay runs and DO NOT retry, so neither can be your only path for a "must not miss a launch" radar.

**Tools / repos / APIs:**
- **[STEAL] healthchecks/healthchecks** — https://github.com/healthchecks/healthchecks  
  Open-source (Django/Python, 10.1k stars, active) cron/heartbeat monitor = dead-man's-switch. Job sends an HTTP ping on success; if the ping doesn't arrive on schedule, IT alerts you. Self-host on a $5 VPS or use the free hosted hc-ping.com. Handles start/success/fail pings, grace periods, and fans out to its own integrations.
- **[STEAL] caronc/apprise** — https://github.com/caronc/apprise  
  Single Python lib (16.8k stars, very active) that abstracts 100+ notification backends (Telegram, Discord, ntfy, Slack, desktop, email) behind one URL-string API (e.g. tgram://, discord://, macosx://). Drop-in replacement for hand-rolled notify code.
- **[STEAL] binwiederhier/ntfy** — https://github.com/binwiederhier/ntfy  
  Self-hostable pub-sub push (Go, 31k stars). PUT/POST to a topic URL -> instant push to phone + desktop, no account. Ideal as the actual delivery channel behind Apprise for the 'launch detected, hunt NOW' alert.
- **[LEARN-FROM] cronitorio/cronitor-cli** — https://github.com/cronitorio/cronitor-cli  
  Go CLI that wraps any command, auto-pings a monitor, and can import a whole crontab. Good reference for the 'wrap the job, ping on start/end/fail' idiom even if you point it at self-hosted healthchecks instead of their SaaS.
- **[LEARN-FROM] dgtlmoon/changedetection.io** — https://github.com/dgtlmoon/changedetection.io  
  32k-star self-hosted website-change watcher with scheduler + diff + restock/price-drop alerting via Apprise. Not your engine (it's generic web-diff, not impl-hash/proxy-upgrade aware) but the best reference for noise-filtered change detection + notification fan-out architecture in one box.
- **[LEARN-FROM] GitHub Actions scheduled workflows** — https://github.com/orgs/community/discussions/156282  
  Free cloud cron. BUT community-confirmed unreliable: 5-15min drift routine, 30min+ on busy hours, runs SILENTLY DROPPED under load, no built-in failure alert, disabled after 60 days repo inactivity. Always pair with workflow_dispatch + external heartbeat.
- **[AVOID] Cloudflare Workers Cron Triggers** — https://developers.cloudflare.com/workers/configuration/cron-triggers/  
  Free-tier serverless cron, ±30s precision. NO retry on failure/CPU-timeout — a missed tick is gone until the next scheduled tick. Recent multi-day dispatch-silence outages reported. Fine as a redundant backstop, NOT as sole path.
- **[PAID-REFERENCE] AWS EventBridge Scheduler** — https://docs.aws.amazon.com/scheduler/latest/UserGuide/what-is-scheduler.html  
  Serverless cron with at-least-once delivery, configurable retries w/ exponential backoff, and dead-letter queue. The only one of the cloud options with real reliability guarantees — but heavier setup and ties you to AWS. Overkill for a personal radar unless you already live in AWS.
- **[PAID-REFERENCE] healthchecks.io (hosted)** — https://healthchecks.io/  
  Hosted tier of the OSS tool above — generous free plan (20 checks). Zero-maintenance dead-man's-switch if you don't want to run the Django app yourself.

**Techniques to adopt:**
- Dead-man's-switch / heartbeat: don't watch for a failure event, watch for the ABSENCE of a success ping. radar.py pings a healthchecks URL on every completed poll; a missed launch-scan run becomes an alert by itself — the single most important pattern for 'must not miss a launch'.
- Three-layer split: scheduler (fire) / monitor (did it fire?) / notifier (tell me). Keep them decoupled so swapping launchd<->cloud cron doesn't touch radar logic.
- Redundant schedulers, idempotent job: run the SAME radar poll from two independent triggers (local launchd + a cloud cron) and make the job idempotent via a state file / content-hash dedup so double-fires are harmless. Belt-and-suspenders beats any single 'reliable' cron.
- Run dedup via persisted state: store last-seen impl-hash / audit-tag / bounty-URL set; only emit + enqueue on a real delta (this is your noise filter, identical in spirit to the existing exit-code-10 'only-if-new' pattern in contest_monitor.py).
- Exit-code-as-signal (already in your stack): job exits 10 when something meaningful changed; the wrapper turns exit-10 into a push. Portable from PowerShell to a shell/launchd wrapper.
- Notifier abstraction over a URL string (Apprise model): radar config holds notify targets as strings, so adding Discord or a phone push is a config line, not code.
- launchd over cron on Mac: launchd survives reboots, catches up MISSED runs while asleep/off (StartCalendarInterval runs at next wake — cron just skips them), and has KeepAlive. For a laptop that sleeps, this is the decisive difference vs cron.
- Grace-period tuning: set the heartbeat grace window wider than worst-case scheduler drift (GH Actions can be 30min late) to avoid false 'job dead' alarms.

**Pitfalls:**
- GitHub Actions cron silently drops runs under load and disables schedules after 60 days of repo inactivity — if your radar lives only there, you WILL miss a launch and never know. Never the sole path.
- Cloudflare Workers cron has zero retry: one thrown error or CPU-timeout and that tick is lost until the next cron interval. Multi-day silent-stall outages have happened.
- Plain cron on a laptop = missed runs whenever the Mac is asleep/off at the scheduled minute; cron does not catch up. launchd does. Don't reach for crontab on macOS out of habit.
- Self-hosting healthchecks adds its own ops burden (Postgres, mail server, upgrades) — and a monitor that itself dies defeats the purpose. For a solo whitehat the free HOSTED tier is often the saner choice; don't over-engineer.
- Notification fan-out without dedup = alert fatigue. If radar double-fires (redundant schedulers) you must dedup the NOTIFICATION too, not just the work, or you train yourself to ignore it — fatal for a 'hunt first-hours' edge.
- Timezone/UTC mistakes in cron expressions are the classic 'why didn't it run' — and high-load top-of-hour slots make drift worse; schedule at an odd minute (e.g. :17) not :00.

**Applicability to us:** radar.py becomes the polled job; wrap it exactly like the existing contest_monitor.py exit-10 idiom. Concretely for OUR stack: (1) Scheduler — replace the Windows Task / watch_contests.ps1 layer with a macOS launchd plist (StartCalendarInterval) calling a shell wrapper that runs `python toolkit/radar.py`; this is the MAC-LANE successor to register_contest_watch.ps1 and fixes laptop-sleep misses. (2) Backstop — a thin GitHub Actions or Cloudflare cron that runs the same radar.py against the same registry state, purely as redundancy, since the registry/last-seen hashes are committed and idempotent. (3) Heartbeat — radar.py curls a healthchecks ping on completion so a missed launch-scan is itself an alert (directly serves the 'must not miss a launch' requirement; the existing engine has NO such safety today). (4) Noise filter is already half-built: radar.py's proxy_upgraded/url_appears/github_new_repo checks plus registry.py's reviewed impl-hash ARE the persisted-state dedup — emit only on delta, then push to the re-hunt queue with prior notes. (5) Notifier — swap any hardcoded desktop-balloon for an Apprise/ntfy URL list in config so the same 'FRESH -> /hunt NOW' alert reaches phone+desktop+Discord; categories->batch-action alerts (upstream fork CVE -> re-scan all forks of that base) become just another Apprise message with the affected registry slice attached.

**Recommendation:** BUILD-with-reuse, don't reinvent. Adopt the three-layer split: (a) launchd as the primary Mac scheduler (StartCalendarInterval, survives sleep/reboot, catches missed runs) replacing the Windows-Task path; (b) make radar.py ping a healthchecks heartbeat on every completed run — STEAL healthchecks/healthchecks (self-host later, free hosted tier now) — this is the one piece the current engine lacks and is exactly what guarantees 'never miss a launch'; (c) STEAL Apprise (+ ntfy as the channel) for notification fan-out so desktop/Telegram/Discord is config not code. Add ONE redundant cloud cron (GitHub Actions with workflow_dispatch) as a backstop only, knowing it drifts/drops — never as the sole trigger. AVOID making Cloudflare Workers cron or GH Actions your only path. SKIP AWS EventBridge unless you already run AWS. Keep the existing exit-code/last-seen-hash dedup as the noise filter — it's the right idea; just generalize it into registry-state deltas.

---

## llm-agent-monitoring — using LLM agents for security monitoring / triage of code (and on-chain) changes; agent-on-change re-triage for radar.py

**State of the art.** The "continuous, agentic, on-change security review" thesis is now mainstream: commercial platforms (Octane, Almanax, Cantina AI, Nethermind AuditAgent) all pitch an LLM agent that re-reviews every commit/dependency-bump/protocol-upgrade instead of periodic manual audits, and on-chain side Forta/Hypernative do agent-style anomaly watch. The single most reusable open artifact is anthropics/claude-code-security-review (5.4k stars, Apache-ish, actively maintained): a diff-aware Claude audit followed by a SECOND Claude call that filters false positives — exactly the noise-filter architecture radar.py needs. The credible-but-skeptical signal is that autonomous SC agents still produce both misses and spurious findings (EVMBench re-eval, arXiv 2603.10795), so the agent should be a triage/prioritization layer over your deterministic detectors, never an autonomous verdict. Self-hostable general PR-review plumbing (The-PR-Agent/pr-agent) exists but is web2-generic and not contract-aware.

**Tools / repos / APIs:**
- **[STEAL] anthropics/claude-code-security-review** — https://github.com/anthropics/claude-code-security-review  
  GitHub Action + /security-review slash command. Two-phase: github_action_audit.py runs Claude on ONLY the PR diff (changed files, in context), then findings_filter.py + a SECOND Claude API call (claude_api_client.py) applies false-positive filtering with customizable instructions (examples/custom-false-positive-filtering.txt, docs/custom-filtering-instructions.md). Hard-exclusion rules + per-project tunable scan prompt (prompts.py). Ships an evals/ harness to score the agent on arbitrary PRs.
- **[LEARN-FROM] The-PR-Agent/pr-agent (ex-Qodo)** — https://github.com/The-PR-Agent/pr-agent  
  11.8k-star fully self-hostable AI PR reviewer, Apache-2.0, Docker, webhook-driven for GitHub/GitLab/Bitbucket/Gitea. Mature change-trigger + diff-chunking + structured-comment plumbing. General-purpose, not smart-contract-aware, fairly heavy.
- **[LEARN-FROM] atahabilder1/AuditAgent (OSS)** — https://github.com/atahabilder1/AuditAgent  
  Tiny (2-star) LangChain agent that runs Slither+Mythril then uses an LLM to EXPLAIN/triage the static findings and suggest fixes. Demonstrates the 'deterministic tool -> LLM triage layer' wiring, which is the exact shape for feeding recon.py output into an LLM.
- **[PAID-REFERENCE] Octane (octane.security)** — https://www.octane.security/  
  Commercial 'AI security layer': reviews every commit, dependency change, and protocol upgrade with auditor-depth, CI/CD-integrated, traces data flow + models attacker behavior. The clearest articulation of the 'agent on every change' product thesis.
- **[PAID-REFERENCE] Almanax** — https://almanax.ai/  
  'AI Security Engineer' for web3 that finds logical vulns; maintains an open 'Web3 Security Atlas' dataset — potentially mineable as ground-truth/eval corpus for calibrate.py.
- **[PAID-REFERENCE] Cantina AI** — https://cantina.xyz/welcome  
  AI-native web3 security platform: AI code analysis + 24/7 monitoring + human auditors over PR/upgrade events. Reference for the human-in-the-loop agentic monitoring workflow.
- **[PAID-REFERENCE] Nethermind AuditAgent** — https://auditagent.nethermind.io/  
  Hosted autonomous SC audit agent marketed for proactive detection + continuous monitoring of deployed Solidity. Reference for the continuous-monitoring product surface.
- **[AVOID] GitHub Copilot CLI /security-review (pre-commit scanner)** — https://github.blog/ai-and-ml/generative-ai/agent-pull-requests-are-everywhere-heres-how-to-review-them/  
  LLM inference at the detection layer: gathers local diff, sends to cloud model, returns findings scored by severity+confidence, tuned to 5 high-impact classes. Cloud/proprietary, not self-hostable.
- **[LEARN-FROM] EVMBench re-evaluation (arXiv 2603.10795) + OpenAI EVMbench** — https://arxiv.org/pdf/2603.10795  
  Skeptical benchmark study: current AI agents are NOT yet reliable for autonomous SC security — both missed vulns and spurious detections; prior benchmarks overstated readiness. Empirical backing for keeping the agent advisory, not authoritative.

**Techniques to adopt:**
- Two-call audit->filter split: one LLM call generates findings on the diff, a SEPARATE LLM call (different, stricter prompt) decides keep/drop — this decouples recall from precision and is the cleanest noise-filter pattern to port into radar.py
- Diff-scoped context, not whole-repo: feed the agent ONLY the changed surface (impl-hash delta / upgrade diff / new-bounty delta) plus your prior notes, never the full contract — cuts cost and hallucination
- Customizable hard-exclusion rules + per-project FP-filter instructions file (examples/custom-false-positive-filtering.txt) — lets you encode your own kill-gates / known-FP classes as text the filter LLM enforces
- Severity + CONFIDENCE scoring on each finding so radar.py can threshold (only enqueue medium+/high-confidence to the re-hunt queue)
- Detector-feeds-LLM pattern (Slither/Mythril -> LLM explain): run your deterministic recon.py detectors first, then have the agent triage/dedupe/prioritize their output rather than scan raw code blind
- Ship an evals/ harness (run the agent against past triaged targets) so the agent's precision/recall is measured against your ledger ground-truth before you trust it — mirrors calibrate.py
- temperature=0 + explicit 'you MUST flag X' instructions to stabilize agentic review output

**Pitfalls:**
- Autonomous SC agents still both miss real bugs and emit spurious findings (EVMBench re-eval) — an agent verdict is a HYPOTHESIS, not a finding; keep it advisory feeding the re-hunt queue, never auto-disclose
- Cost/noise on every commit: claude-code-security-review's own run-every-commit=false default exists because per-commit scanning inflates FPs — radar.py should trigger the agent on MEANINGFUL deltas (impl/proxy upgrade, audit-tag bump, new bounty) not every poll
- LLM-as-judge FP filter can over-filter and drop real logic bugs (their exclusion list literally drops DoS/input-validation) — tune the exclusion text to web3 (don't blanket-exclude rounding/DoS, which matter on-chain)
- Prompt-injection / hostile-diff risk: a watched repo's README or comments can carry instructions to the agent — sandbox and treat fetched content as untrusted
- Most 'AI auditor agent' GitHub repos are 1-4 star hackathon demos (Loupe, nitsaw, atahabilder AuditAgent) — architecture-only value, do not depend on them
- Commercial tools (Octane/Almanax/Cantina/Nethermind/Forta/Hypernative) are $500-$10k+/mo subscription — reference the workflow, don't pay; your edge is self-hosted single-Mac + your own detectors

**Applicability to us:** Map directly onto radar.py as a new check type 'agent_retriage', invoked ONLY after watch.py-style deterministic signals fire (proxy_upgraded / new impl-hash / audit-tag bump / new bounty launch from registry.py). Pipeline per fired target: (1) compute the delta — upgrade diff or impl-hash-vs-reviewed-hash — and pull the target's prior notes from the ledger; (2) AUDIT call: Claude reviews ONLY that delta in context (steal github_action_audit.py + prompts.py); (3) FILTER call: a second stricter Claude pass enforces your kill-gates/known-FP text (steal findings_filter.py + custom-false-positive-filtering.txt) and emits severity+confidence; (4) only medium+/high-confidence survivors get pushed to the re-hunt queue with the prior notes attached. For categories -> batch actions: on an upstream fork-CVE event, fan the agent across all registry rows sharing that fork-base, feeding each the CVE description + that fork's drift diff — this is the agentic version of your existing fan-out neuvod. Run the evals/ harness against already-triaged HUNT.md targets and pipe results into calibrate.py so the agent's precision is measured against the operator's ground-truth before it's trusted. Keep the agent output typed as a hypothesis (matching fanout_log.py's TRIAGE-level verdicts), with the L4 human read + VERIFY kill-gates still mandatory before any disclosure.

**Recommendation:** BUILD a thin 'agent_retriage' step in radar.py by porting the two-call architecture from anthropics/claude-code-security-review (STEAL its findings_filter.py + custom-FP-instructions pattern verbatim — it is the noise filter you said is the hard part), but feed it your delta+prior-notes instead of a raw PR, and gate it behind deterministic change-signals so it only runs on meaningful upgrades (cheap on a single Mac via the Claude API). Do NOT build a standalone autonomous auditor or pay for Octane/Almanax/Cantina/Nethermind — use them only as workflow references. Keep the agent strictly advisory: it ranks and enriches the re-hunt queue; your recon.py detectors + L4/VERIFY remain authoritative, because EVMBench shows agent verdicts aren't trustworthy alone. Add a small evals harness wired to calibrate.py so you can prove the agent's precision against your ledger before relying on it.

---
