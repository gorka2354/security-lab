# Tooling roadmap — what to actually build (synthesis of the 20-agent sweep)

Source: `research-findings.md` (2026-06-27). Ranked by impact × (1/effort), grounded in our two named
bottlenecks: **freshness** (zero live-findings = the wall) and **reasoning-tier** (regex misses economic bugs).

## The honest meta-conclusion
More *static* detectors on already-reachable, hardened code = diminishing returns. The research converges on
THREE game-changers: **(1) DYNAMIC exploit-finding** (ItyFuzz/PoCo auto-find, incl. unverified code),
**(2) FRESHNESS data sources** (be first on new code), **(3) REASONING-tier automation** (LLM/symbolic on top
of recon). Everything else is incremental coverage. Prioritize the three.

## Tier 1 — BUILD-NOW (low effort, ships this week, high leverage)
| # | Build | What it gives | Effort | Plugs into |
|---|---|---|---|---|
| 1 | **Slitherin sub-lane** (`pip install slitherin`, `slitherin-cli --pess`) | read-only-reentrancy + price-manip-via-arbitrary-call + UniV2/AAVE-integration detectors — the T2-adjacent classes recon misses, ~zero plumbing (Slither already integrated) | LOW (1 day) | `analyze.py` L2 |
| 2 | **Freshness feeds**: DefiLlama `protocols` `listedAt` + **Sourcify newest-verified** (`GET /v2/contracts/{chainId}`) | brand-new protocols + freshly-verified contracts across chains — directly attacks the #1 wall; turns freshdeploy from "watched-deployers only" into "all new verified code" | LOW (½–1 day) | `scout.py` / `freshdeploy.py` |
| 3 | **diffyscan audit-drift lane** (lidofinance/diffyscan) | audited-commit → live-source diff → run recon ONLY on the drifted functions; collapses the read surface (speed) + finds audit-drift bugs | LOW-MED (1-2 d) | `forkdrift.py` |
| 4 | **Corpus expansion for shadow.py**: FORGE-Artifacts (27k labelled findings), Web3Bugs, SmartBugs-curated, SolidiFI, EVMbench, GoPlus | measures our TRUE blind-spot rate (we only had ~751 DeFiHackLabs) → data-driven detector backlog + the missing FP axis | LOW-MED (1-2 d) | `shadow.py` |
| 5 | **Pre-built invariant auto-mount**: crytic/properties + a16z/erc4626-tests | recon detects target type (ERC20/721/4626) → auto-mount the matching property suite in a fork harness → run; ready-made reasoning-tier coverage for standard types | MED (2-3 d) | `scaffold.py` |
| 6 | **Proxy storage-collision lane**: `slither-check-upgradeability` + `forge inspect storage-layout` V1↔V2 diff | opens the storage-collision class (a measured blind-spot) + upgrade-unsafe changes; pairs with the radar's impl-upgrade signal | LOW-MED (1-2 d) | `analyze.py` / `radar.py` |
| 7 | **Solodit known-bug check** (Cyfrin free API) | on any candidate: is this exact bug already disclosed? kills known-bug FPs fast | LOW (½ d) | triage / `ledger.py` |

## Tier 2 — PROTOTYPE (the big levers, medium effort, build next)
| # | Build | Why it's a game-changer | Effort |
|---|---|---|---|
| **A** | 🥇 **ItyFuzz dynamic fork-fuzz lane** (MIT, bytecode-level) | THE standout — appeared as top pick in 3 angles. Auto-FINDS exploits with zero/minimal harness, **works on UNVERIFIED code**, has an economic oracle (profit). Hits BOTH our worst gaps at once. Wire as the auto-confirm/PoC step after a DIG. | MED-HIGH |
| **B** | **PoCo agentic auto-PoC** (ASSERT-KTH/PoCo, MIT) | forge-feedback agent loop that turns a finding → a working Foundry exploit; automates our slowest manual step (candidate→PoC, like today's concurrency model). | MED |
| **C** | **LLM-reasoning lane** (port claude-code-security-review's MIT filter + confirm-then-reason) | the T2/T3 economic/invariant tier regex structurally can't reach; anchored to recon findings + prior notes, FP-filtered. This is OUR fan-out agent, specialized as a per-target reasoning pass. | MED |
| **D** | **Bytecode lane for UNVERIFIED** (whatsabi + evmole + heimdall-rs, all free) | turns freshdeploy's unverified finds (Boar/1sec class) into triageable ABI/selectors/decompiled logic; closes the "unverified = unreachable" gap. | MED |
| **E** | **hevm / Halmos symbolic** (forkdrift `equivalence` + bounded invariant proofs) | most direct hit on the explicitly-weak T2/T3 tier; `hevm equivalence` proves drift + yields a witness without spec-writing. | MED-HIGH |

## Tier 3 — BACKLOG (bigger / lower marginal value now)
- **fork-CVE propagation** (`forkdrift.py propagate` — one upstream CVE → rescan all registry forks; we already have the fork-index).
- **Solana coverage** (Radar/Auditware + sec3 X-Ray static lane + a Solana bounty/deployer radar source) — opens a large non-EVM value class.
- **OZ Monitor** self-hosted (push-based upgrade/privileged-call radar over bounty-scope + deployer addrs).
- **HyperSync CREATE-trace provider** for freshdeploy (sees ALL new contracts, not just watched deployers).
- **EIP-7702 recon detectors + radar SET_CODE lane** (emerging 2026 account-abstraction attack surface).
- Aderyn second SARIF lane + Decurity exploit-rule mining into recon (cross-tool consensus scoring).

## Recommended sequence
1. **Tier-1 #1,#2,#4** first (Slitherin + freshness feeds + corpus) — cheapest, hit coverage + freshness + data-driven roadmap.
2. **Tier-2 A (ItyFuzz)** — the single highest-leverage build (dynamic auto-find + unverified). Make it the post-DIG confirm step.
3. **Tier-2 C (LLM-reasoning lane)** + **B (PoCo)** — close the reasoning-tier + auto-PoC speed gap.
4. Backlog as capacity allows.


## Tier-2 follow-up notes (2026-06-30)
- **ItyFuzz dynamic fork-fuzz lane (Tier-2 #1) = BUILT** — `toolkit/ityfuzz_lane.py`: wraps ItyFuzz as the
  post-DIG auto-confirm / auto-find step (onchain-fork fuzz of a live address+chain+block; economic oracle
  via `-f`; works on unverified bytecode). `build_cmd` + `parse_output` pure + golden-tested (15); graceful
  when the binary is absent (prints install, never crashes).
  - **INSTALLED + PROVEN (2026-06-30):** prebuilt via `curl -L https://ity.fuzz.land/install.sh | bash &&
    ityfuzzup` worked on Mac darwin/arm64 (nightly fb4e87a; ~/.ityfuzz/bin). Lane proven END-TO-END: run() on
    BEGO/BSC invoked ityfuzz, captured, parsed, returned clean `{ok:true,...}` (no crash).
  - **CALIBRATED vs real CLI:** dropped `-o` (this version has NO onchain flag; onchain = `-c <chain>` +
    `--target-type address`); confirmed `-t/-c/-b/-f/-w/-k/-u/-e`.
  - **KEY CONSTRAINT (found live):** ItyFuzz fetches ABI from the chain's LEGACY explorer (eth->etherscan.io,
    bsc->bscscan.com). Our Etherscan-**v2** multichain key is native on ETH but REJECTED by bscscan.com etc ->
    non-eth chains need a chain-native key or `--explorer-url`. Added `-e/--explorer-url` + a warning.
  - **STILL UN-VALIDATED:** parse_output markers vs a REAL find (the BSC run found nothing: ABI fetch failed on
    the v2-key/bscscan mismatch). Calibrate markers on the first real find on an **in-scope ETH** target (key
    native there) -> that's a HUNT (Gate-0), not a benchmark guess.
  - Follow-up: MCP trigger-tool `lab_ityfuzz` + `--from-dig` (pull a target address from labcore).

## Tier-1 follow-up notes (2026-06-28)
- **registry --query DONE** — instant memory recall over monitor/registry.json (`--query <text>` + `--status/--zone/--fork/--chain/--owasp`). E.g. `registry.py --fork liquity` = the batch-CVE family. +5 tests.
- **Solodit known-bug check = DEAD END** — no free public API (solodit.cyfrin.io is a SPA, /api/ 404s). Would need auth or scraping -> backlog, low priority.
- **shadow corpus = located, NOT cheap** — FORGE-Artifacts (`shenyimings/FORGE-Artifacts`, [ICSE'26], 27k findings) is the RIGHT modern corpus but 150MB + submodules + needs a vuln-label -> det_key map = a deliberate integration, not a quick win. SmartBugs-curated (smartbugs/smartbugs-curated) is cheaper but OLD (2019 SWC classics, solc-mitigated) = low value for our modern-DeFi focus. -> proper next-session task.
