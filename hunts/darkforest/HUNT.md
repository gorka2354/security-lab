# HUNT: Dark Forest (darkforest-eth/eth)

Famous fully-on-chain zkSNARK space-conquest game; EIP-2535 diamond (facets + AppStorage via
`gs()`/`ws()` getters) + zk `Verifier`. Battle-tested, semi-dead (rounds ended). Skill-practice
(no bounty). Clone: gitignored `hunts/_volume/darkforest` (28 .sol). Dual-engine run
(recon-21 + hypothesize-with-bridge). Recon: `hunts/_volume/darkforest-recon.md`.

## Triage (verify-before-claiming) -- no finding

| Lead | Detector | Verdict | Why |
|---|---|---|---|
| `LibPlanet.initializePlanet:99` / `initializePlanetWithDefaults:122` | initialize `[!]` | **refuted** | `_initializePlanet` has `require(!isInitialized, "Planet is already initialized")` (line 142) -> no re-init/reset. These are SNARK-gated GAME actions, not contract initializers (name-match FP class) |
| `DFCoreFacet.upgradePlanet:161` | sibling `[!]` | **by-design** | ownership-gated inside `LibPlanet.upgradePlanet`; `onlyWhitelisted` is for JOINING, not in-game actions (different gating models; thin-facet -> Lib) |
| `DFInitialize:215/359` | initialize/access `[!]` | **by-design** | diamond init, run once via owner-gated `diamondCut` |
| `LibGameUtils.updateWorldRadius:562` | access `[!]` | **FP** | public LIBRARY fn (diamond pattern); recomputes worldRadius deterministically from state; idempotent, no privileged effect |

The real attack surface (zk move/artifact/capture validation) is reasoning-tier, not pattern-
detectable -- and this is a heavily-played, much-audited game. No finding (expected).

## The durable value: a HYPOTHESIZER upgrade (separate engine, from a live gap)
Dark Forest stores state via getter FUNCTIONS (`gs().planets[id] = x`, `ws().whitelist[a]`), not
the `state.`/`s.` local convention. The shared-state matrix was **BLIND** to it (0 roots) -> the
EMERGENT+RECON bridge couldn't fire. Fixed:
- `find_getters` learns storage-getter names per repo (`function NAME() internal ... returns (X storage)`).
- `build_state_re` extends the accessor to `getter().field` (low FP: only declared getters).
- Result on Dark Forest: matrix went 0 -> rich (`gs().worldRadius` <- 6 fns, `gs().nextChangeBlock`,
  `gs().paused`, `ws().drip`, `gameConstants().*`), and **EMERGENT+RECON now fires**:
  `updateWorldRadius` (recon:access) shares `gs().worldRadius` with the admin setters;
  `setTokenMintEndTime` (recon:supply) shares `gs().TOKEN_MINT_END_TIMESTAMP` with `init`.
- Triage of the top fused hypothesis: worldRadius is deterministic game-balance state, admin
  setters are owner-gated -> low/by-design. But the bridge AIMED correctly. +4 tests (112).

**Lesson:** this is the hypothesizer's own learning loop (parallel to the detector loop). A live
target exposed that the bridge only saw `s.`/`state.` storage; now it sees the getter-accessor
convention too -> the analyzer->hypothesizer bridge works across the whole diamond/AppStorage class,
not just `s.`-named ones. (Storage-pointer-aliased writes still need Grade B / Slither.)
