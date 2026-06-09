# HUNT: Royco V2 "Dawn" (roycoprotocol/royco-dawn) -- scout v2 candidate #4 (first NON-fork novel target)

Fourth scout-v2 target and the **first to escape the fork-wall**: genuinely-NOVEL, unaudited code.
DefiLlama "Royco V2" (Yield, audits=0, ~$15.7M, Eth/Avax/Arb). Repo `roycoprotocol/royco-dawn`
(found via the org's repo list; V1 `royco` is the audited RecipeMarketHub/Weiroll -- different codebase).
Clone gitignored `hunts/_volume/royco-v2`. **Workflow win: `forkdrift fingerprint` ran FIRST -> "no base"
-> original code -> recon/hypothesize the whole surface (not a diff).** CODE-STUDY pass (deploy unconfirmed).

## What it is -- structured-credit tranching (genuinely novel)
Senior/Junior tranche vaults (ST/JT) over yield sources (IdleCDO, ERC4626, Makina, Maple, reUSD, USDai,
USDat, apyUSD). Per-market the **RoycoFactory** CREATE3-deploys 4 contracts: senior tranche + junior tranche
+ **RoycoKernel** (966 L, strategy/NAV) + **RoycoAccountant** (916 L, ST/JT NAV attribution). YDM =
Adaptive-Curve Yield Distribution between tranches. Auth = OZ AccessManager (`restricted`); Factory is the
global access-manager. Tranche shares are WAD-precision, minted at the tranche's effective NAV.

## ENGINE WIN -> fix#32 (the self-improvement loop fired)
recon flagged **47 access-control leads** (28 access + 19 sibling) -- ALL false: every privileged fn uses
OZ AccessManager's `restricted` modifier (`AccessManagedUpgradeable`), which recon didn't recognize as a
gate. **Forged fix#32:** added `\brestricted\b` to `WARD_MOD` (it's a trailing auth modifier, same shape
as the ward `auth` gate). OZ AccessManager is OZ v5's recommended access-control -> this de-noises ALL
modern OZ-AccessManaged codebases, not just Royco. 47 -> 0 false leads; +3 golden tests (151 -> 154, green).
Ledger: burn/burnFrom FP. Guard test keeps a `setRestrictedFlag` (names but doesn't USE the modifier) flagged.

## Leads after fix#32 (35 total) -- PARKED for a deep pass (deploy-gated)
- **ORACLE 3-guard x10** -- the prime target. Royco prices tranche NAV via Chainlink (`*ToChainlinkOracle`
  kernels, `RoycoTrancheChainlinkOracle`, `FundamentalStablecoinChainlinkOracle`). Verify staleness/price>0/
  decimals on each feed AND whether a stale/manipulable feed mis-prices a tranche's effective NAV -> mint/
  redeem at a wrong price (cross-tranche value transfer). 
- **Tranche NAV donation / first-depositor inflation** -- `RoycoVaultTranche._convertToShares` (362-371):
  first depositor mints 1:1 (no virtual/dead shares); zero-`totalAssets` boundary deliberately dilutes
  existing holders to the new depositor (line 368, "majority ownership to new depositor"). Need to check the
  KERNEL's NAV source: if NAV derives from `yieldAsset.balanceOf(kernel)` (not bookkept) -> donation moves
  share price -> live inflation; if oracle/bookkept -> mitigated. (Tranche deposit routes assets->KERNEL then
  `stDeposit/jtDeposit` returns valueAllocated+effectiveNAV -- trace where that NAV comes from.)
- **Accountant ST/JT attribution** -- the prime ECONOMIC surface. State `lastJT/STRawNAV`,
  `lastJT/STEffectiveNAV`, `lastJT/STImpermanentLoss`, `twJTYieldShareAccruedWAD`, `st/jtOwnedYieldBearingAssets`
  (hypothesizer: 10-18 writers each, many reachable via deposit/redeem). Their OWN latest merge is
  `bugfix/accountant-attribution` -> attribution is where THEY find bugs -> round-trip/rounding value leak
  between senior & junior is the hypothesis to fuzz (deposit ST/JT then redeem -> caller never richer; SUM
  claims <= assets). 
- REENTRANCY x6 / SUPPLY x3 -- lower priority (burn/mint are `restricted`/kernel-gated; verify on the deep pass).

## Status -- CODE-STUDY (no live finding; deploy UNCONFIRMED -> not prioritized per LIVE-FIRST)
royco-dawn shows NO deployment artifacts (no broadcast/deployments, no audit/mainnet mention), codename
"Dawn" + a `royco-dusk-paper` formal-specs repo + active self-bugfixes -> looks PRE-deploy / in active dev.
Per CLAUDE.md LIVE-FIRST: any finding here is "fix but do NOT prioritize" until deployment + in-scope bounty
is confirmed (check RoycoFactory on-chain / their docs / Immunefi before any disclosure). Primary win this
pass = the ENGINE (fix#32) + proving the forkdrift-first workflow surfaces genuinely-novel targets.
Next session (if pursued): confirm deploy/scope -> deep-dive the oracle-3guard x10 + accountant attribution
(scaffold an ST/JT round-trip + solvency invariant in invariant-lab).
