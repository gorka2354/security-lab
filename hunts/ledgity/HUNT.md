# HUNT: Ledgity Yield (LedgityLabs/ledgity-v2-contracts) -- surfaced by scout v2

**First target from `scout.py --source defillama`** (deployed-but-unaudited: DefiLlama Yield,
audits=0, ~$3M TVL, multi-chain Base/Ethereum/Linea/Arbitrum/Sonic). RWA yield protocol: `LToken`
(rebasing yield-bearing deposit token) + `WrappedLToken` (non-rebasing ERC4626-style wrapper) +
`LDYStaking` + `InvestUpgradeable` (yield engine). Clone gitignored `hunts/_volume/ledgity`.
White-hat: read-only public code; disclosure (if pursued) via Ledgity's channel by the user.

## FINDING (candidate, Medium): WrappedLToken is undercollateralized -- daily-compound rate vs linear underlying accrual

**The full pipeline converged here:** scout v2 found the protocol; `recon` flagged the WrappedLToken
area (ungated `updateRateCheckpoint`, unchecked transfers, wrap/unwrap); `hypothesize` flagged the
`wrap <-> unwrap` round-trip; L4 found the accrual mismatch.

**Root cause:** `WrappedLToken.exchangeRate()` (WrappedLToken.sol:114-148) computes the wrapped->lToken
redemption rate by **daily-compounding** `baseRate` at the checkpointed APR:
```
for (i < fullDays) compoundedRate = compoundedRate * (RAY + apr/365) / RAY;   // DAILY COMPOUND
```
But the underlying `LToken` (which the wrapper actually holds) accrues a holder's balance **LINEARLY
within each APR period**: `InvestUpgradeable._calculatePeriodRewards` (line 284):
```
growth = elapsedYears * apr;   rewards = invested * growth / 100;            // LINEAR in time
```
(LToken auto-compounds only ACROSS APR checkpoints, not within a period.) Since daily-compound > linear
for any apr>0, the wrapper's redemption obligation grows faster than the lTokens it holds:
```
WrappedLToken.totalSupply * exchangeRate()/RAY   >   lToken.balanceOf(WrappedLToken)
```
-> the wrapper is **progressively undercollateralized**. `toRebasingAmount` has no balance cap, so
`_unwrap` (WrappedLToken.sol:247) pays the inflated rate first-come-first-served until `lToken.transfer`
reverts on the last unwrapper. **Early unwrappers over-redeem at the expense of late unwrappers (bank-run).**

**Amplifier:** `updateRateCheckpoint` (186) only re-bases when `lToken.getAPR()` CHANGES, and it sets
`baseRate = exchangeRate()` (the projected, already-over-stated rate -- never reconciled to the actual
balance). So a long stable-APR stretch makes `exchangeRate()` daily-compound over MONTHS vs the underlying's
linear accrual, and each checkpoint LOCKS the over-projection into `baseRate` (the drift compounds across
periods, monotonically).

**Severity = Medium (honest calibration):** the gap is the (daily-compound - linear) premium over the
inter-checkpoint window. ~0.5%/yr of the wrapper's TVL at 10% APR stable for a year; larger at higher APR
or longer stable periods, and it accumulates across periods. Not an instant drain -- a growing solvency
deficit borne by the last unwrappers. (Low if APR is re-checkpointed ~daily; Medium for realistic
weeks-to-months-stable RWA APR.)

**PoC plan (to nail magnitude / confirm no off-chain top-up):** Foundry -- deploy LToken + WrappedLToken,
set APR=10%, wrap from two users, `warp` 1 year (no APR change), assert
`totalSupply*exchangeRate()/RAY > lToken.balanceOf(wrapper)`; user A unwraps fully (over-redeems), user B's
unwrap reverts / is short. (scaffold.py can seed the harness.)

**Recommendation:** make the wrapper balance-backed (wstETH pattern): redemption = `wrappedAmount *
lToken.balanceOf(this) / totalSupply` (an ERC4626 `totalAssets = balanceOf`), so it can never owe more
than it holds. Drop the parallel APR-compound `exchangeRate` entirely.

## Other leads (triaged)
- `LToken.processBigQueuedRequest:1002` reentrancy -> **FP/by-design**: `onlyFund whenNotPaused`; request
  deleted from queue BEFORE the transfer (dev comment + slither-disable) -> not attacker-reachable, CEI-safe.
- `WrappedLToken:232/268`, `LTokenHedera:*` unchecked ERC20 transfer -> hygiene (use SafeERC20); LToken is
  their own token (returns true) but `underlying()` may be USDT-like -> verify on the underlying path.
- `GenericERC20:37` ungated mint, `sonic/*` ungated/initialize -> FP (test token / thin per-chain re-deploy variants).

## Outcome -- scout v2 VALIDATED: first surviving finding-candidate of the project
8 prior targets (all reviewed/contest) -> 0 findings. The FIRST scout-v2 (deployed-but-unaudited) target
yielded a real, verification-surviving Medium. Confirms the session diagnosis: **target quality (under-
reviewed code) is the bottleneck, not tooling.** Ledger -> `real` (the project's first). Next: build the
Foundry PoC + (user) check Ledgity's disclosure/bounty channel.
