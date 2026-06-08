# Pattern 03 — Reward / claim accounting

**Tier:** T2/T3 — the smell (a `claim()` with a mutable marker) is T1; whether it's *exploitable* (can you claim twice,
claim after transfer, claim dust into a profit) is cross-state reasoning.
**One line:** a rewards system lets the same entitlement be **counted more than once, or counted after it should have
been zeroed** — via re-entry, NFT/position transfer between accrual and claim, or a marker updated too late / not at all.

## 1. Mechanism
The leak points, by frequency:
1. **Double-claim** — the "already-claimed" marker (`claimed[id]`, `lastClaimedWave`, `userRewardDebt`) is updated
   *after* the payout external call, or a second code path pays without touching it → claim twice for one epoch.
2. **Transfer-between-accrual-and-claim** — rewards accrue to a position/NFT; you claim, transfer it, the new owner
   claims the *same* accrued amount because accrual wasn't checkpointed on transfer.
3. **Queue/wave bookkeeping** — a per-wave queue where `dequeue` math is off by one → either a wave is paid twice or the
   current (still-accruing) wave is closed early.
4. **Dust / rounding** — `reward = mulDiv(share, pot, total)` rounds down; repeated tiny claims or a crafted `total`
   leave claimable dust the attacker harvests, or strand funds.
5. **Timing window** — claim immediately before *and* after a rate/checkpoint change to collect on both sides.

## 2. Real examples
- **Crypto Unicorns `LibRewards` (first-hand) — the CORRECT design to study, not a bug.** I chased a suspected
  double-claim: `getDequeueCount` deliberately dequeues **all-but-the-current** wave (current still accrues), and the
  ERC721 `_beforeTokenTransfer` hook **resets `forSale`/`currentOwner`** so a transfer can't carry stale accrual. Both
  the off-by-one and the transfer-replay paths were *closed*. → studying *why it's safe* is the lesson.
- **MasterChef-family classics:** `accRewardPerShare` + `userRewardDebt` is the canonical safe checkpoint; bugs appear in
  forks that update `rewardDebt` after a transfer hook, or forget it in an emergency-withdraw path.

## 3. The "tell"
- Find every `claim`/`harvest`/`collect` and the marker it reads (`claimed`, `lastClaimed*`, `rewardDebt`, dequeue index).
- **The $-question:** *is the marker written BEFORE any value leaves, and on EVERY path (incl. transfer hooks, emergency
  withdraw, batch)?* If a transfer/exit path skips the checkpoint → replay lead.
- Check `dequeue`/wave-close math for off-by-one (is the *current* accruing bucket included?).
- Check rounding direction of `reward = mulDiv(...)` — down strands; a manipulable `total` denominator amplifies dust.

## 4. Detector idea (static, T0/T1) — det_reward
- Flag a function named `claim|harvest|collect|redeem*reward` that makes a transfer **and** whose body lacks an
  assignment to a `claimed|rewardDebt|lastClaimed` marker (or makes the transfer *before* it). Emit as a **lead** — the
  marker may live in a called library (CU's lived in `LibRewards`), so this is FP-prone → verify the callee.
- **Honest limit:** transfer-replay and off-by-one are stateful → T2, not regex. det_reward only catches the
  missing/late-marker smell.

## 5. Hypothesis / invariant (T2/T3)
- **Hypothesis:** "for each entitlement, is there any sequence (claim → transfer → claim, or claim → re-enter) that pays
  it twice?" Enumerate every path that moves the position AND every path that pays.
- **Invariant to fuzz:** `Σ(all payouts for epoch e) ≤ budget(e)` AND `no address/id is paid twice for the same epoch`.
  Harness: random mint/accrue/transfer/claim sequences → assert total paid ≤ funded and per-id claim-count ≤ 1/epoch.

## 6. Mitigations to RECOGNIZE (avoid FP)
- **Checkpoint-on-transfer** (CU `_beforeTokenTransfer` reset; MasterChef `rewardDebt` updated in `_transfer`).
- **Marker-before-transfer** (CEI on the accounting marker, not just the token).
- **Dequeue-all-but-current** (the accruing bucket is never closed early) — CU's exact pattern.
- **Pull-based `accRewardPerShare`** with `rewardDebt` — replay-proof by construction; if you see it wired on every
  balance-changing path, the double-claim lead is dead.
