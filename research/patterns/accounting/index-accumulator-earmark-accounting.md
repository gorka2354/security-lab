# Pattern — index/accumulator "earmark & redemption" debt accounting (rebasing-index conservation)

**Tier:** T3 (reasoning / invariant-fuzz) — NOT statically detectable. The bug class is a **per-account-vs-global
conservation break** or a **rounding direction** error in a scaling-index debt system. You prove or refute it with a
multi-account invariant fuzz, never by reading.
**One line:** when a protocol spreads a global event (debt redemption, yield, fee) across many positions via a **shared
scaling index** (à la aToken `liquidityIndex`, stETH shares, or Alchemix V3's earmark/redemption `survival ratio`),
the danger is that `SUM(per-account view of X) != global X` after enough index updates — either users collectively claim
**more** than the pool holds (insolvency) or **less** (stuck/lost dust).

## 1. Mechanism
Positions store a checkpoint (`lastIndex`, `lastAccumulator`); a global op multiplies a running index by a ratio.
On `sync(account)`, the account's debt/earmark/collateral is rescaled by `survivalRatio(account.lastIndex, globalIndex)`.
This is O(1) per account for an O(N) global effect — elegant, but every rescale **rounds**, and the rounding of N
independent accounts must reconcile to the ONE global decrement.

Two failure modes:
1. **Conservation break.** `redeem` reduces a global (`totalDebt`, `_mytSharesDeposited`) by `D` once; each account
   later debits its share lazily. If `SUM(lazy per-account debits) > D` (or `<`), local and global drift apart. The
   *dangerous* direction is `SUM(local claims) > global pool` → the last exiters can't be paid (insolvency / bank-run).
2. **Epoch/telescoping errors.** When the index resets (an "epoch" on full wipe), accounts that straddle the boundary
   must split their math at the boundary, else redemptions get **double-counted** (over-redeem) or **dropped**
   (under-redeem). This is the subtlest part — Alchemix V3's `_computeUnrealizedAccount` has explicit pre/post-boundary
   split logic precisely for this.

## 2. The safe-rounding rule (how a CORRECT implementation defends)
Round every per-account adjustment in the **protocol-safe** direction so `SUM(local) <= global` always holds:
- debit user collateral / increase user debt → **round UP** (`mulDivUp`) — never under-charge.
- credit user / decrease user debt → **round DOWN** — never over-pay.
Net effect: tiny dust accrues to the protocol; the pool is never short. (User loses sub-wei dust — acknowledged, not a bug.)

## 3. Reference implementation (a CLEAN one — study it, don't expect a bug)
**Alchemix V3** (`AlchemistV3.sol`, scout-v3/Immunefi hunt 2026-06-09). Self-repaying loans: NFT positions, debt
"earmarked" toward redemption via Q128.128 packed `(epoch, index)` weights + a `_survivalAccumulator`.
- `_mytSharesDeposited` (global) and `Account.collateralBalance` (local) move together in `deposit`/`_subCollateralBalance`;
  `redeem` decrements the global once, sync debits each account lazily with **`mulDivUp`** (round up) → `SUM(local) <= global`
  = protocol-safe. Verified by hand: the rounding sits on the safe side (over-debit users by dust, never under).
- `_computeUnrealizedAccount` (1478) carries scar-tissue comments — "avoids amplifying index-scale ceil rounding",
  "avoids both over-redemption and under-redemption" with pre/post epoch-boundary split. i.e. this exact class was their
  battleground and is already hardened. **No demonstrable finding from static analysis.**

## 4. Hunt checklist (when you meet this pattern)
- [ ] Identify the global accumulator(s) and the per-account checkpoint. List every reader/writer of each.
- [ ] Write the conservation invariant: `SUM_accounts(debt) == totalDebt`, `SUM(earmarked) == cumulativeEarmarked`,
      `SUM(collateral) <= globalPoolShares`. Fuzz with M accounts × K interleaved (earmark, redeem, deposit, withdraw,
      liquidate) ops, asserting after each. This is what the team's OWN suite may NOT cover — Alchemix's invariant tests
      fuzz the MultiStrategy ALLOCATOR heavily but not the core debt/earmark conservation (a gap worth flagging to a team).
- [ ] Check the rounding DIRECTION on every per-account adjust (up for debits, down for credits). A single `mulDiv`
      (round-down) on a user debit = the insolvency direction → highest-severity candidate.
- [ ] Epoch boundaries: force a full wipe (index reset), then sync an account that straddles it; assert no double/under count.
- [ ] The index feeding collateral *value* (e.g. an ERC-4626 `convertToAssets` share price) is a SEPARATE attack surface
      (see [[../pricing/index-manipulation.md]] / oracle-manipulation) — manipulate it to force-liquidate a healthy
      position or dodge liquidation; needs the full strategy deploy to PoC.

## 5. Heuristic seed
recon won't catch this (it's reasoning-tier). The trigger to reach for this pattern: a debt/share system with a
`*Index`/`*Weight`/`*Accumulator`/`survivalRatio`/`earmark` global + a per-account `lastAccrued*` checkpoint +
`mulQ128`/`mulDiv` rescaling. Then go straight to the conservation fuzz.
