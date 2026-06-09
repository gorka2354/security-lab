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

## Status -- ABANDONED: deployed BUT heavily audited (DefiLlama "audits=0" was a DATA ERROR)
Deploy check (the question that gated everything): **DEPLOYED.** `script/config` references a pre-deployed
`ROYCO_FACTORY = 0x7cC6fB28eC7b5e7afC3cB3986141797ffc27253C`; on-chain `eth_getCode` confirms it is LIVE on
**Ethereum + Arbitrum** (no code on Base). So LIVE-FIRST is satisfied.
BUT the repo's `audit/` dir holds reports from **Cantina + Certora (formal verification) + Hexens x3 +
whitelist audits** (+ WatchPug/Hexens for the Pendle-SY integration). i.e. Royco Dawn is among the MOST-
audited protocols -- the exact opposite of "under-reviewed". **DefiLlama's `audits=0` is a data error**, and
scout v2 trusted it. Per the core diagnosis (audited code = competing with pro wardens + here, formal
verification) -> very LOW EV. ABANDONED (not worth the oracle/accountant deep-dive).

## Wins banked (despite no finding)
1. **fix#32** (OZ AccessManager `restricted`) -- broadly useful, 47->0 FPs, +3 golden tests. The real take.
2. **forkdrift-first workflow proven** -- it correctly classified Royco as original (non-fork) novel code.
3. **Lesson -> next tool:** scout v2 must NOT trust DefiLlama's `audits` field. A cloned repo with an
   `audit/` dir or `*audit*.pdf` (or README "audited by") is audited regardless. Add a post-clone audit-
   evidence check (natural home: extend `forkdrift fingerprint` -> "AUDITED: N reports in audit/ -> downgrade")
   so we never again sink a hunt into an audited-but-mislabeled target. (Would have saved this entire hunt.)
