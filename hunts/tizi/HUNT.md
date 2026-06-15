# HUNT — Tizi (cross-chain yield stablecoin, hub-and-spoke on Base) — DEEP DIVE

A full 6-phase deep dive (comprehend → formalize invariants → adversarial break → invent patterns → verify → feed
back), the "reasoning-depth game". 33 contracts / 6320 LOC. Phase-1 used a 5-agent subsystem-mapping невод;
Phases 2-6 by hand. Sourced via the under-reviewed fan-out (2026-06-14); **gate = REPO-ONLY** (likely-deployed on
Base, unproven here; no bounty/scope in repo — confirm before any disclosure).

## The unifying insight (the invented pattern class)
Tizi's accounting integrity rests on a single logical quantity being mutated through **multiple unreconciled
writers** — the **split-brain accounting** class (new, written to `research/patterns/accounting/split-brain-accounting.md`,
seeded into `hypothesize.py` CORE menu). Three axes, all present in Tizi:

### 1. async-snapshot rebase contamination  — CONFIRMED on code, permissionless, the centerpiece
`TiziDollar.netAsset` is written **live** by `mint()` (`+= amount`) / `burn()` (`-= amount`) on every user
deposit/withdraw, AND **wholesale-overwritten** by `updateYield()`:
```
oldNetAsset = netAsset                                            // live
newNetAsset = TokenStats.calculateTotalChainValues() - nftQueueUSDC*1e12   // off-chain NAV snapshot (incl. USDC.balanceOf(vault) sampled when admin last ran strategiesStats) - live nftQueue
addYield(newNetAsset - oldNetAsset);  netAsset = newNetAsset      // mint/burn the delta into stTD
```
The NAV is snapshotted at block **B0** (admin `strategiesStats`); `updateYield` applies it at **B1 > B0**. A user
who **front-runs `updateYield` with a LIQUID withdrawal `w`** does `netAsset -= w`, but the NAV snapshot does NOT
see the USDC leave the vault → `delta = trueYield + w` → **+w phantom yield minted to stTD while real USDC backing
simultaneously dropped by w** (double solvency hit). Repeatable each rebase; an stTD holder captures their share.
**Surgical, not "centralisation":** the NFT-withdrawal path is *correctly* neutralised by a matching
`nftQueueUSDC += w` term — only the **liquid** path lacks the compensator. (`TiziDollar.sol:119/133/172-198`.)
WHO: any stTD holder watching the admin's `updateYield` in the mempool. Severity: **High if deployed + mempool-visible.**

**PROVEN (Foundry PoC, `tizi-poc/`):** a faithful verbatim-arithmetic reimplementation of `updateYield` + the
two withdrawal paths. `forge test`: start solvent (1000 USDC / 1000 TD) → attacker liquid-withdraws 100 TD before
`updateYield` → **100 TD phantom yield minted to stTD, backing = 900 USDC, supply = 1000 TD → INSOLVENT**. The
NFT-path control mints **zero** phantom (compensated). Fuzz (256 runs): phantom == the withdrawn `w` exactly, and
backing drops by exactly `w`. 3/3 pass. → "confirmed by reading" is now "proven by running".

### 2. weakest-adapter NAV replay — High (conditional on Axelar live)
`MainTokenStats.updateFromStructs` is reachable from `MainTokenLayerZero._lzReceive` (nonce + deadline +
`targetContract==this`) **and** `MainTokenAxelar._execute` (NO nonce, NO deadline, NO source check) **and**
`execute()` (admin, no nonce/deadline). A captured admin-signed NAV blob is **replayable via the Axelar path** to
re-pin a stale-favourable NAV right before `updateYield`. The channel is only as fresh/replay-safe as its weakest
writer. (`MainTokenAxelar.sol:50-78`.)

### 3. bridge-decoupled supply — Medium-High
TD is a LayerZero OFT; `_credit/_debit` call OZ `ERC20._mint/_burn` directly, which **do NOT touch `netAsset`**
(the protocol's own `mint()` is a different private fn). Bridge TD off Base and back → circulating supply moves,
`netAsset` doesn't → the next rebase sizes against a stale accumulator. (Confirmed against canonical OFT source.)

## Other real (non-admin-trust) candidates
- **Unbounded-loop griefing (Medium):** `getWaitNFTAmount` loops over `INFT.totalSupply()`; `calculateLiquidity`
  (in `bridgeOut`'s hot path) calls it. A user spams tiny withdrawal NFTs → gas blows up → Manager can't route
  funds cross-chain. (`DepositHelper.sol:254-324`, `MainVault.sol:185`.)
- **Rebase-DoS underflow (Low-Med):** `newNetAsset = NAV - nftQueueUSDC*1e12` underflow-reverts if pending NFT USDC
  exceeds NAV → all rebases frozen; users can inflate `nftQueueUSDC` by mass-queueing. (`TiziDollar.sol:174`.)
- **int256(tokenAmount*tokenValue) sign-flip + `totalChainValue -=` underflow (Med):** a loss-strategy or a crafted
  bridge report can wrap/flip the NAV math. (`MainTokenStats.sol:328/330/343`.) External severity capped by the
  admin-signature on the NAV path (needs a malicious/buggy signed blob).
- **withdrawNFTs key-space mismatch (conditional):** written by `queueId`, read/deleted by `tokenId`; safe only
  while both counters advance in lockstep — an admin `setNFT` swap desyncs them. (`DepositHelper.sol:359-367` vs `485-524`.)

## Deprioritised (admin-trust / centralisation — real but not external findings)
Single `DEFAULT_ADMIN_ROLE` key is the root of trust for BOTH the NAV signature AND `updateYield`. `setHelper`/`setSTD`
(no timelock) → infinite mint; inflated signed NAV; malicious whitelisted strategy; `setPeer` → forged OFT mint;
`bridgeOut` domain/receiver decoupling. All require admin-key compromise/abuse → kill-gated (admin) per VERIFY.

## Feed-back to the engine (the deliverable)
- **New pattern class** `research/patterns/accounting/split-brain-accounting.md` (mechanism · 3 axes · tells · invariant · mitigations).
- **`hypothesize.py` CORE seed** "split-brain accounting" (CI-gated).
- **Honest detector outcome:** forged `det_split_accounting`, **test+tune killed it** (FP-flooded on interest-index
  recompute — same regex shape; missed Tizi's two-step overwrite). Demoted to the reasoning seed. (4th recurrence
  this build of "clean conceptual pattern = reasoning-tier, not T0".)

## Phase-0 LIVE-FIRST (post-dive) — CONFIRMED LIVE + novelty cross-checked
- **Deployed + live on Base:** TiziDollar TD = `0x469bbd88eEA8A2D9a5C6c82d9890Cf60962C27e6` (chain 8453, DefiLlama
  TVL-tracked), **totalSupply ≈ 122,119 TD (~$122k)**. The **deployed `updateYield` has the EXACT split-brain
  formula** line-for-line (`newNetAsset = calculateTotalChainValues() - nftAmount*1e12`, `:174`; `netAsset += / -=`,
  `:119/133`; `netAsset = newNetAsset`, `:198`). The finding is in LIVE code, not just the repo.
- **Audited by Beosin** (10 findings: 1 High / 2 Med / 5 Low / 2 Info). Beosin DID catch several of my SECONDARY
  findings: Tizi-08 "Negative Strategy Value" = my int256 sign-flip/underflow (Fixed); Tizi-05 "Linear Address Check
  Gas Exhaustion" = my unbounded-loop griefing (Ack); Tizi-07 "Signature Replay" (Fixed); Tizi-03 "Centralized Risk"
  = my admin-trust class. **My CENTERPIECE (async-snapshot rebase contamination → phantom POSITIVE yield from a
  liquid withdrawal) is NOT among the 10** (Tizi-01 "Yield Loss Handling" is the NEGATIVE-rebase loss-burn order, a
  different issue), and the split-brain formula survives in deployed code → **plausibly novel.**
- **HONEST CAVEAT (exploitability):** the attack needs a window between the Base `strategiesStats` snapshot and
  `updateYield`. If the keeper runs strategiesStats(Base)+updateYield ATOMICALLY, the Base-USDC component is fresh
  and only stale sub-chain NAV remains exploitable; if they are separate txns (the multi-bridge NAV assembly
  suggests so), the liquid-withdraw straddle is fully live. Needs an on-chain keeper-sequencing check to settle.
- **No public bug bounty** (DefiLlama "audits" link = the Beosin PDF only; no Immunefi).

## Current criticality — on-chain measured (the death.fun "real vs theoretical" discipline) → LOW / LATENT
Live reads on Base (2026-06-15), TD `0x469bbd88…`, helper `0xBfE36e36…`, vault `0x5772a02f…`:
- `rebaseNonce = 12` (the rebase IS used), `netAsset == totalSupply == 122,119 TD` (books currently consistent).
- **~99.9% of TD is staked** (stTD supply 120,535 ; sTD holds 121,992 TD) — phantom yield would dilute existing stakers.
- **DECISIVE: MainVault liquid USDC = `calculateLiquidity() = 1,750,742` = ~$1.75** (`nftQueueUSDC = 0`; ~all the
  ~$122k backing is deployed into off-Base strategies). The **buggy LIQUID path can move at most the vault's liquid
  USDC** — any larger withdrawal routes to the NFT path, which is **compensated (no bug)**. So the **max phantom
  yield exploitable RIGHT NOW ≈ $1.75.**
- **Verdict on criticality:** High **by class** (mints unbacked yield, breaks solvency) but **near-zero / LATENT in
  practice today** — the protocol keeps almost no liquid USDC on Base, so the uncompensated path can't move
  meaningful value. The exploitable magnitude == the liquid USDC buffer in MainVault. It becomes materially
  dangerous ONLY if Tizi ever holds a large liquid buffer on Base (e.g. right after a big deposit, before the
  manager deploys it) AND the snapshot→rebase has a window (likely, given async multi-bridge NAV assembly) — then a
  whale stTD holder front-runs `updateYield` with a large liquid withdrawal up to the buffer size.

## Verdict
A genuinely rich, novel mechanism, and the **async-snapshot rebase contamination (#1)** is a real, PoC-proven,
deployed-code accounting-integrity bug that Beosin's audit did **not** cover — the strongest finding of the dive.
Disposition: LIVE + plausibly-novel + PoC-backed, **but currently LOW/LATENT** (capped at ~$1.75 of liquid USDC) +
**no bounty program**. The right white-hat move is a calm **responsible goodwill heads-up** to the Tizi team (egor
sends) — framed honestly (real bug, PoC, but low current impact + the activation conditions), not a "critical"
alarm. The lasting win is the **engine gain**: a new pattern class + seed + the honest detector lesson + a reusable
cross-chain-accounting comprehension model.
