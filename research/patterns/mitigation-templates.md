# Mitigation templates — anti-FP recognition catalog

> **Purpose:** the recurring *correct-mitigation* shapes. When you see one, the matching bug class is
> already closed → stop, don't FP, don't spend PoC time. Distilled from this lab's clean-verdict
> deep-dives (2026-08 arc: punks/Stash, Firelight V2, Royco Day, Intuition MultiVault, GAIB sAID,
> mezo, native-credit, dtrinity, Tizi). The *bug* is almost always the **absence** of the template,
> or one path that lacks the compensator every other path has.

A recon `[!]` hit or a plausible economic hypothesis is only real if the corresponding template below
is **missing or asymmetric**. Grep for the template first; if present, downgrade to honest-negative.

| # | Bug class it closes | Correct-mitigation template (the "tell" that it's safe) | Seen in |
|---|---|---|---|
| 1 | **donation / first-depositor share inflation** | NAV read from a **bookkept state var** (`trackedAssets`/`totalAssets`/`totalUnderlying`), updated on deposit/withdraw — **NOT** `balanceOf(this)`/`address(this).balance`. A direct token donation doesn't move NAV. Often paired with a `reconcileAssetBalance` sweep of surplus. | GAIB sAID, Intuition MultiVault, native-credit |
| 2 | **first-depositor inflation (proportional-mint vaults)** | OZ **virtual shares/assets** offset + a **dead-shares seed mint** on first deposit + (belt-and-suspenders) an explicit **max-mint-dilution clamp** whose docstring names the attack. | Royco Day (`MAX_MINT_DILUTION_WAD`), dtrinity (OZ-v5), Firelight (offset0) |
| 3 | **double-mint / cap-bypass (issuance)** | A **monotonic settle-once flag** (`totalSettled==0` gate on recommit/cancel; `_epochToMinted[e]>0` revert) + a **cap chain** (`settled <= declared <= matchingCapacity <= computedCapacity`) + a per-actor running cap. | Firelight insurance, Intuition emissions |
| 4 | **funds routed to a blacklisted/non-whitelisted address** | The receiver-screen fires on **every fund-exit path** (redeem/withdraw/claim/payout/queue-fulfil/fee-collect), **redundantly** — an explicit `enforceNotBlacklisted(receiver)` **and** an ERC20 `_update` transfer hook — never only on entry or only on `msg.sender`. | Royco Day |
| 5 | **funds permanently locked (queue / stuck recipient)** | A stuck item can't head-of-line-block others (**try/catch or try-delegatecall** per item) **and** there's a **cancel-to-fresh-receiver escape hatch** (no `enabled`/`whenNotPaused` gate on the cancel path) so any stuck claim is recoverable. | Royco Day |
| 6 | **double-spend across two reservation systems on one balance** | `available = balance - locked` **recomputed live every call**, and the op **reverts on shortfall rather than dipping into `locked`** → `balance >= locked` holds at all times. | punks/Stash (auction-orders ⟂ signed-bids) |
| 7 | **payout reentrancy** | The replay/nonce marker is **burned BEFORE the external value-transfer** (CEI) → a re-entrant call hits the already-consumed marker and reverts. `nonReentrant` on the mutating exits. | punks/Stash, native-credit, GAIB |
| 8 | **split-brain accounting (snapshot vs live writer)** | Every intervening flow between a snapshot and its settlement has a **compensating term** (Tizi's `nftQueueUSDC` is the correct template) — OR the conserved var is **derived** (`= totalSupply()`), never tracked in parallel. The bug = one path (Tizi's *liquid* path) lacking the compensator every other path has. | Tizi (correct on NFT path), GAIB (queue lacks it) |
| 9 | **retroactive over/under-distribution on a rate/param change** | `setRate/setFee/setRewardRate/mint` call **`accrue()`/`sync()` FIRST**, at **every** principal-mutating site (open/adjust/close/refinance/liquidate), so the accumulator is current before the numerator moves. | mezo (interestNumerator ordering) |
| 10 | **signature replay / malleability / authority-confusion** | EIP-712 with **nonce + deadline + a used-marker set BEFORE the `ecrecover`**, `ECDSA.recover` (rejects malleable/`address(0)`), the hash **covers every economic field**, and the signer/authority is a **bound/stored** party — never a caller-supplied struct field or bare param. | native-credit, centrifuge, mezo |

## How to use this in triage
1. Form the hypothesis (e.g. "donation inflates share price").
2. Grep for the matching template (#1: is NAV `balanceOf` or a state var?).
3. **Template present and symmetric across all paths → honest-negative, log it, move on.**
4. **Template missing, or present on some paths but not one → that asymmetric path is the lead.** (Tizi: NFT path compensated, liquid path not. GAIB: remaining-holder NAV writes down, queued claim doesn't.)

## Meta-lesson (2026-08 arc)
Across every authorized/audited target this arc, recon `[!]` hits were consistently FP/known and the real
edge was reasoning-tier: the value of the engine is the `hypothesize` INVARIANT_MENU (what to PROVE) plus
*this* catalog (what to RECOGNIZE as already-proven), not more T0 regex detectors. A clean verdict backed
by "template N is present on all paths" is a first-class deliverable, not a null result.
