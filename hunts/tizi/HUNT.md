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

## Verdict
A genuinely rich, novel mechanism. The **async-snapshot rebase contamination (#1)** is a real, permissionless,
code-confirmed accounting-integrity bug — the strongest external finding of the dive. But Tizi is **REPO-ONLY**
(no confirmed mainnet deploy / no bounty in repo) → LIVE-FIRST: confirm deploy + an in-scope program on Base before
any disclosure. The lasting win is the **engine gain**: a new pattern class + seed + the honest detector lesson +
a reusable cross-chain-accounting comprehension model.
