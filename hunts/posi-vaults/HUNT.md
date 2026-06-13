# HUNT: PositionExchange auto-compound vaults  (PositionExchange/position-vaults)

- **Date:** 2026-06-11  (the session's last run -- a current/under-reviewed BSC target)
- **Repo:** https://github.com/PositionExchange/position-vaults (BNBPosiVault / BUSDPosiVault /
  POSIAutoCompoundVault; BSC; ~989 LoC; 10 stars; no license; Solidity 0.6.x).
- **What:** auto-compound vaults that stake POSI via `IPosiStakingManager` and re-compound. Synthetix-style
  reward accounting (rewardPerToken / userInfo.rewardPerTokenPaid).
- **Verdict:** **real code bugs found** by the L4 read (recon-32 only surfaced the access/unchecked-ERC20 noise;
  the logic bugs came from reading the share + reward math). Severity gated on LIVE-FIRST (deployment unconfirmed).

## Findings

### F1 (clear, Low) -- `balanceOf(user)` ignores its parameter
```solidity
function balanceOf(address user) public view returns (uint256) {
    return userInfo[msg.sender].amount;   // <- returns the CALLER's balance, not `user`'s
}
```
`balanceOf(other)` returns the caller's amount. Masked in state-changing paths (deposit/withdraw/harvest all
pass `msg.sender`), so no direct fund loss -- but every external integrator / `earned(other)` view is wrong.

### F2 (strong lead, needs PoC + live-check) -- reward formula multiplies stored rewards by balance
```solidity
function earned(address account) public view returns (uint256) {
    return balanceOf(account).mul(
        rewardPerToken().sub(userInfo[account].rewardPerTokenPaid).div(1e18)
        .add(userInfo[account].rewards)        // <- ADDED INSIDE the .mul(balance)
    );
}
```
Synthetix adds `rewards` OUTSIDE the multiply: `balance*(rPT-paid)/1e18 + rewards`. Here it's
`balance*((rPT-paid)/1e18 + rewards)` = `balance*delta + balance*rewards`. Since `updateReward` stores
`earned(account)` back into `rewards` (every 8h lockup tick), after the 2nd update `earned ~ balance^2*delta`
-> reward INFLATION -> drain / harvest-insolvency. **Caveat:** a live vault would be visibly broken by this, so
it is likely **deprecated/unused** -- confirm deployment + TVL + write a Foundry PoC before treating it as a
real live finding.

### F3 (accounting smell) -- deposit/withdraw vs totalSupply drift
`deposit` credits `userInfo.amount += stakeAmount` (the post-RFI-fee whole balance) but `totalSupply += amount`;
`withdraw` sends `amountLeft = posi.balanceOf(this)` and reduces the user by `amountLeft` while `totalSupply -=
amount`. -> `sum(userInfo.amount) != totalSupply`, and `rewardPerToken = rewards/totalSupply` vs
`earned = amount*rPT` use the two inconsistent quantities. Compounds F2.

## Discipline notes
- recon-32 [!] = mostly FP/noise here (the ungated leads are user-facing deposit/withdraw/harvest; the unchecked
  -ERC20 leads are moot since POSI/BNB/BUSD revert on failure). The real bugs were L4-read logic bugs, not
  pattern hits -- a reminder that recon AIMS, the read FINDS.
- LIVE-FIRST: deployment/TVL NOT confirmed (no addresses in the repo; POSI has a rough history -> these vaults
  may be deprecated). Severity is gated on that -> ledger F2 = `todo` (PoC + live-check), F1 = `real` (clear but Low).
- White-hat: read-only. If confirmed live + in-scope, egor confirms + discloses (PositionExchange has no public
  bounty visible -> responsible disclosure direct).

## Phase-0 LIVE-FIRST verdict (2026-06-13) -- DEAD TARGET, closed (wontfix)

On-chain check (BSC) of the staking it auto-compounds + the deployed vaults:
- **Emissions OFF:** PosiStakingManager(V1) `0x0C54...db0B` `positionPerBlock() = 0`. No POSI is minted -> no reward
  accrual -> `rewardPerToken()` never grows -> F2's quadratic inflation has nothing to inflate.
- **Single pool (pid=1, what the vaults compound) is empty:** lpToken=POSI, but staking holds **0 POSI**;
  `lastRewardBlock = 25,063,962` (~2022) i.e. no interaction for years; allocPoint 7/827.
- **Deployed vaults are empty:** BNBPosiVault `0x75Ec2073...5bD6` + BUSDPosiVault `0x0385665a...0f38` both have
  `totalSupply()=0`, single-pool stake 0, only `1e14` (0.0001) POSI dust. Zero TVL, zero users.
- **POSI itself** is -99.98% from ATH (ATL Feb-2026), swap "under maintenance", protocol migrated to
  PosiStakingManagerV2 `0xb02de8...b2d1`. BSC farming is abandoned.
- **Repo->live attribution UNPROVEN:** the cleanest-F2 contract (POSIAutoCompoundVault) is **not deployed**
  (no on-chain match); the deployed BNB/BUSD vaults expose a **different ABI** (`rewardPerTokenStored()` absent)
  and the repo's BNB/BUSD files ship a **testnet** config -> the code carrying F2 is not the live bytecode.

**Verdict:** F2 (quadratic reward inflation) + F1 (balanceOf ignores param) are **real code bugs** (math
re-confirmed against source this session), but the target is dead: no emissions, no TVL, no users, and no proven
link from the buggy repo code to live bytecode -> **ZERO live impact -> not a finding.** Ledger F1+F2 -> `wontfix`.
Lesson reinforced: the LIVE-FIRST caveat in the original note was correct -- "an obviously-broken live vault" was
the tell; one cheap on-chain pass (emissions + pool TVL + vault totalSupply) settles it before any PoC effort.
