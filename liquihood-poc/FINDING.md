# Liquihood LendingPool — supplier accounting split-brain: 100% of collected interest is permanently unclaimable (High)

**Severity:** High (protocol-wide, permanent loss of the core promised feature — no attacker required, the bug
fires on ordinary use; PoC-proven). Not a third-party fund-drain: borrowers still pay real interest in full, but
that value becomes stuck in the contract forever, unclaimable by suppliers, the InsuranceFund, or the owner.
**Status:** Live on Robinhood Chain mainnet (chain id 4663), un-audited, 1-star repo, deployed 2026-07-11.
24 reserves configured, real seed liquidity present (501,000 USDG / 200 WETH / 5,000 AAPL-T / 5,000 TSLA-T /
10,000 HOOD-T / 5,000,000 DOGE / 500,000 MEME-1 + several zero-balance equity reserves), plus at least 3 small
reserves (`USDG`, `WETH`, `USDe` — duplicate-symbol test markets) with **real organic borrow+accrual activity**
already observed on-chain. Last supplier/borrower interaction ≈ 39 days before this triage (mid-July 2026) — the
deployment currently reads as **dormant** (soft-launch / pre-public-launch), so current disclosure urgency is
moderate, not urgent, but it must be fixed **before real users arrive**, because every depositor from day one is
silently shortchanged.
**Contract:** `LendingPool` — `0xD26F926CEBdd169D87c5a615C18A3A8AddbBdF6E` (Robinhood Chain, chain id 4663, RPC
`https://rpc.mainnet.chain.robinhood.com`). Owner/deployer `0x12b502D89f3aF07633a1A8D34C122C87e58a5eb3`.
Source: `github.com/Liquihood-dev/liquihood-contracts` (verified-matching bytecode: reserve list, owner, and
constructor wiring all confirmed live via `cast call`).
**Class:** split-brain accounting — one conserved value (a supplier's redeemable balance) has two unreconciled
writers: a linear, non-interest-bearing ledger (`userCollateral`) that gates every real operation, and an
index-scaled "interest-bearing receipt" (`LHToken`) that is computed correctly but never consulted anywhere.
**Disclosure intent:** private, goodwill (small hobby-scale repo, no bounty program). White-hat, read-only
analysis over public deployed code; PoC runs only against a local Foundry instance of the team's own source. No
funds or live state were touched.

---

## Finding — `withdraw()` / health-factor / borrow-capacity are all gated on `userCollateral`, a ledger that never grows with interest, while the actual interest-bearing token (`LHToken`) is orphaned

`LendingPool.supply()` tracks a depositor's stake in **two** places (`src/LendingPool.sol:157-179`):

```solidity
userCollateral[msg.sender][_asset] += _amount;      // line 173 — raw, linear, never grows
...
reserve.lhToken.mint(msg.sender, _amount);           // line 176 — correctly minted at the CURRENT index
```

`LHToken` (`src/LHToken.sol:78-136`) is a proper Aave-style scaled-balance interest receipt: `mint`/`burn`
convert at `liquidityIndex`, and `balanceOfUnderlying()`/`totalUnderlying()` correctly report principal +
accrued interest as the index grows via `_accrueInterest()` (`LendingPool.sol:428-453`, which really does call
`reserve.lhToken.updateIndex(newLiquidityIndex)` at line 449 on every supply/withdraw/borrow/repay).

The bug: **every function that decides how much a user may withdraw, or how healthy/borrow-capable their
position is, reads `userCollateral` — never `lhToken`:**

```solidity
// withdraw() — LendingPool.sol:193
require(userCollateral[msg.sender][_asset] >= _amount, "LP: insufficient collateral");
...
userCollateral[msg.sender][_asset] -= _amount;        // line 198
reserve.lhToken.burn(msg.sender, _amount);             // line 200 — burns the SAME face amount, not index-based

// _buildPositionArrays() — the sole source for HF / max-borrow / liquidation math — LendingPool.sol:538
cAmounts[i] = userCollateral[_user][userCols[i]];
```

`userCollateral` only ever moves by the exact raw `_amount` passed to `supply()`/`withdraw()` (or seized at
liquidation) — it **never increases**, no matter how much the `liquidityIndex` grows. Because `lhToken` is
never read by anything financial (confirmed by grep: `balanceOfUnderlying`/`scaledToUnderlying`/`totalUnderlying`
are defined but never called anywhere in the repo outside `LHToken.sol` itself), the interest-index machinery is
entirely decorative for redemption purposes.

Meanwhile `repay()` (`LendingPool.sol:249-273`) genuinely collects the full compounded debt
(`debtToken.balanceOf()` = principal + interest, via `borrowIndex`) from the borrower and pulls it into the
pool's real ERC-20 balance (line 261). That extra value has **no path back out**:
- Suppliers can never withdraw more than their original `userCollateral` principal.
- `InsuranceFund.depositReserves()` (`src/InsuranceFund.sol:62`) — the sole entrypoint for the documented
  10% reserve-factor income — is **never called** by `LendingPool` (grep-confirmed 0 hits).
- `LendingPool` has no owner-sweep / rescue function for its own token balances.

So 100% of every borrower's interest payment becomes stranded, unowned value in the contract, forever. Suppliers
earn the advertised APY on paper (`InterestRateModel.getSupplyRate()` computes a real non-zero rate) but realize
**0%** in practice. Worse, because `LHToken` is a freely transferable, "composable" ERC-20 per its own NatSpec,
anyone who acquires it secondhand (e.g. on a DEX, believing it is a redeemable yield receipt) receives a token
with **no possible redemption path whatsoever** — `withdraw()` is keyed to the original depositor's separate
`userCollateral` entry, completely independent of who currently holds the `LHToken`.

### Proof (`test/StrandedYield.t.sol`, forge 1/1 PASS, against the real cloned `src/`)

- LP supplies 100,000 USDG. Borrower posts 100 WETH ($300k) and borrows 80,000 USDG at 80% utilization.
- 365 days pass; the debt compounds for real (`DebtToken.balanceOf` grows to 80,520 USDG).
- Borrower repays in full — genuinely transfers 80,520 USDG into the pool.
- **Pool physically holds 100,520 USDG** after the repay.
- **LP's true index-based entitlement (`lhToken.balanceOfUnderlying`)**: 100,468 USDG (their 90%-after-reserve-
  factor share of the 520 interest).
- **LP's actual withdrawable balance (`userCollateral`, the only thing `withdraw()` honors)**: exactly
  **100,000 USDG** — flat, zero yield.
- LP withdraws the full 100,000 they're allowed; a further `withdraw(1)` reverts `"LP: insufficient collateral"`.
- LP is left holding 465.8 scaled `lhToken` — worth **468 USDG of real, permanently unredeemable value** — with
  no function anywhere to ever claim it.
- `InsuranceFund.balanceOf(USDG)` is **0** the entire time — the documented bad-debt backstop never received a
  cent of reserve-factor income.

```bash
git clone https://github.com/Liquihood-dev/liquihood-contracts && cd liquihood-contracts
git submodule update --init --recursive
# drop test/StrandedYield.t.sol (in this folder) into test/
forge test --match-path test/StrandedYield.t.sol -vv
# => 1 passed; prints the 100,520-held / 100,000-withdrawable / 468-stranded breakdown above
```

### Live confirmation (not just the PoC)

The bug is already manifesting on the deployed contract, not just in theory. A small "USDG" test reserve
(`0x1FaD69eaf1f4E9d9470787f51D458A93464833F6`, distinct from the main USDG market) shows, via a direct
`getReserveStats`/`reserves()` call against `https://rpc.mainnet.chain.robinhood.com`:

```
totalLiquidity = 2.000000000000000000e18
totalDebt      = 2.000000000161673484e18   <- already exceeds totalLiquidity, real accrued interest
lastUpdateTimestamp = 1784043392            (~39 days before the observed chain head)
```

i.e. real interest has already accrued past what the static `totalLiquidity` ledger tracks, on a real (if
small/dormant) deployment.

### Fix

Make `LHToken`'s scaled balance the actual source of truth: `withdraw()` should compute the caller's true
redeemable amount via `lhToken.balanceOfUnderlying(msg.sender)` (capped by `lhToken.balanceOf`, burning the
correct scaled amount), and `_buildPositionArrays()` should use the same index-adjusted value for HF/borrow-
capacity — not the static `userCollateral` ledger. Wire `_accrueInterest()` to actually forward the
reserve-factor share of newly accrued interest to `insuranceFund.depositReserves()` so the documented bad-debt
waterfall is real. (Simplest alternative: delete `LHToken`'s index/interest machinery entirely and be an honest
0%-yield linear-ledger pool — but that contradicts the advertised APY and the whole point of an interest-rate
model.)

---

*Researcher discloses, not the tool. Prepared for private, responsible disclosure to the Liquihood team; it
documents a fund-loss/mis-accounting bug in publicly deployed code and contains no exploit against live funds
(the PoC runs only against a local Foundry instance of the team's own cloned source).*
