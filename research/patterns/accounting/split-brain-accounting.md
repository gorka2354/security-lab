# Split-brain accounting (one quantity, multiple unreconciled writers)

> **Class:** accounting · **Tier:** T1 (a coarse detector) + T2/T3 (the exploit) · **First-hand:** Tizi (cross-chain yield stablecoin, 2026-06, this repo's deep-dive).

A single *logical* invariant quantity — total backing, net asset, circulating supply, an index — is mutated through **two or more independent code paths** that are never reconciled against each other. The paths differ along one of three axes:

| axis | path A | path B | the gap |
|---|---|---|---|
| **timing** | live, per user action | wholesale overwrite from an *off-chain-snapshotted* aggregate | flow between the snapshot block and the apply block is counted as "yield" |
| **auth/freshness** | a strong adapter (nonce+deadline+source bind) | a weak adapter writing the same state with no guard | the value is only as safe as the **weakest** writer |
| **inheritance** | the protocol's own `mint()/burn()` that updates the accumulator | an inherited bridge/OFT `_credit/_debit` that calls `ERC20._mint` directly and *bypasses* the accumulator | supply diverges from the accumulator on any cross-chain round-trip |

Because no single function holds the invariant, every audit lens that reads one function sees correct code; the bug lives in the **divergence between paths**, and the divergence is monetizable.

## 1. Mechanism
Pick a state var `X` meant to track a conserved quantity. If `X` is written by `X += f` / `X -= f` in one place **and** `X = g()` (a wholesale assignment from an external/aggregate/snapshot source) in another, then after the second write `X` equals `g()` and *forgets* every `+=/-=` that the first path applied since `g()` was sampled. A settlement that diffs `X_new = g()` against `X_old` (the live value) mints/burns the difference — which now includes **flow, not just true change**.

## 2. Real examples
- **Tizi `TiziDollar.netAsset` (first-hand, this dive).** `mint()`/`burn()` do `netAsset += / -= amount` (live, per deposit/withdraw). `updateYield()` does `newNetAsset = TokenStats.calculateTotalChainValues() - nftQueueUSDC*1e12` (an **off-chain-snapshotted** cross-chain NAV that includes `USDC.balanceOf(vault)` sampled when the admin last ran `strategiesStats`), then `addYield(newNetAsset - netAsset)` and `netAsset = newNetAsset`. A **liquid withdrawal** front-running the admin's `updateYield` does `netAsset -= w` while the NAV snapshot doesn't see the USDC leave → `delta += w` → **+w phantom yield minted to stTD while real backing simultaneously dropped by w**. The NFT-withdrawal path is *correctly* neutralised by a matching `nftQueueUSDC += w` term — only the liquid path lacks the compensator, which is exactly why the bug is surgical, not "centralisation". (`TiziDollar.sol:119/133/172-198`.)
- **Tizi NAV "weakest adapter" (first-hand).** `MainTokenStats.updateFromStructs` is reachable from `MainTokenLayerZero._lzReceive` (nonce + deadline + `targetContract==this`) **and** from `MainTokenAxelar._execute` (no nonce, no deadline, no source check) **and** from `execute()` (admin, no nonce/deadline). The freshness/replay guarantee of the whole NAV channel = the guarantee of its weakest writer (Axelar) → a captured admin-signed blob is replayable to re-pin a stale-favourable NAV right before `updateYield`.
- **Tizi OFT-decoupled supply (first-hand).** TD is a LayerZero OFT; `_credit/_debit` call OZ `ERC20._mint/_burn` directly, which **do not touch `netAsset`** (the protocol's own `mint()` is a different, private function). Bridge TD off Base and back → circulating supply moves, `netAsset` doesn't → the rebase sizes against a stale `netAsset`.
- **The classic cousins:** a vault whose `totalAssets()` reads `balanceOf(this)` (live) while shares are minted off a cached `pricePerShare` (snapshot) — donation/first-depositor is the degenerate one-actor case of the timing axis.

## 3. The "tell"
Grep / read for a single storage var that has BOTH write-shapes in the same contract:
- `X += …` or `X -= …` (the live accumulator), AND
- `X = SomeExternal(addr).someAggregate(…)` or `X = <snapshot/param>` (a wholesale overwrite), in a *different* function.
Then ask the three axis-questions: **(timing)** was the RHS sampled at an earlier block than this write, while path A ran in between? **(auth)** is `X` (or the data feeding `g()`) writable by more than one adapter with asymmetric guards? **(inheritance)** does the contract inherit a bridge/OFT/rebasing base whose `_mint/_burn/_update` bypasses `X`?

## 4. Detector idea (static) → TRIED, FAILED, demoted to a reasoning seed (honest calibration)
We forged `det_split_accounting`: flag a state var that is BOTH `X += / -=` (live accumulator) AND a wholesale
`X = <expr>` overwrite (excluding reset-to-0, long-form self-accumulation, and plain `set*`/`init*` setters).
**test+tune on real code killed it:** it FP-flooded (8-14 hits on Aave-fork clones mezo/kona, reserve, stakewise)
because an **interest-index recompute** (`liquidityIndex += accrued; ... liquidityIndex = newIndex`) is the SAME
regex shape as the bug, and it *missed* the live Tizi `netAsset` (the overwrite there is two-step:
`netAsset = newNetAsset` where `newNetAsset` came from an external call a line earlier — dataflow, not a single
statement). The discriminator (overwrite-from-a-STALE-OFF-CHAIN-SNAPSHOT vs legit recompute-from-current-state)
is genuinely **T2/T3** — it cannot be a clean regex. → **demoted to a `hypothesize.py` INVARIANT_MENU seed**
(CORE: split-brain reconciliation), NOT a recon detector. (4th time this pattern recurred this build:
caller-supplied-authority bare-param, ERC-1271 bare-param verifier, and now this — the clean *conceptual* pattern
is reasoning-tier; the T0 regex either floods or misses.)

## 5. Hypothesis / invariant (T2/T3)
- **async-snapshot:** for any rebase/settlement `X_new = snapshot(); mintOrBurn(X_new - X_old); X = X_new`, the snapshot block == the apply block, OR flow applied to `X` in between is explicitly subtracted (Tizi does this for the NFT queue but not the liquid path). Fuzz: interleave a deposit/withdraw between `snapshot()` and the settlement; assert minted-yield == true-change, not true-change ± flow.
- **weakest-adapter:** every adapter that can write a security-relevant aggregate enforces the SAME (nonce, deadline, source-bind) tuple; assert no adapter is a weaker writer of the same state.
- **bridge-decoupled supply:** `Σ supply across chains` is conserved AND the protocol's own backing-accumulator is updated on the bridge path too (or the accumulator is derived from `totalSupply()`, never tracked in parallel).

## 6. Mitigations to RECOGNIZE (don't FP)
- The snapshot and the overwrite happen in the **same tx/block** (no intervening flow) → safe.
- The accumulator is **derived** (`X = totalSupply()` / `balanceOf`) each time rather than tracked in parallel → no split brain.
- Every intervening flow has a **compensating term** in the settlement (Tizi's `nftQueueUSDC` is the *correct* template; the bug is only that the liquid path lacks the analogous term).
- All writers share one guarded entrypoint (single adapter, or a modifier that all paths route through).

> Sync to the Obsidian vault under Паттерны уязвимостей. Feeds `hypothesize.py` INVARIANT_MENU (CORE: split-brain reconciliation) + a candidate `det_split_accounting`.
