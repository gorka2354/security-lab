# RealT RMM Marketplace V2 — `withdrawReg()` permanently bricked by an unauthorized burn on the sync path (locked REG collateral becomes unreclaimable)

**Target:** RealT RMM Marketplace V2 (Aave-V3 fork + bespoke REUSD subsidy/migration module), **deployed and live on Gnosis Chain (chainid 100)**.
**Vulnerable contract:** `REUSDPoolManager` (proxy `0x371a02F425CFA011969085fF6ec4F8e53bD77360`, implementation `0x094d7d8b1493df137241410de979ae54c2d08876`).
**Component:** `contracts/wrapper/token/reusd/REUSDPoolManager.sol` — `_syncReusdBalance()` (private), reached from `withdrawReg()`, `borrowReusd()`, `repayReusdWithStable()`, and the admin `syncReusdBalance()`.
**Class:** dead-control / self-DoS — an unconditional, unauthorized token `burn()` on the critical path.
**Verdict:** **CONFIRMED** — Foundry PoC (3/3) against the **live deployed contracts** on a Gnosis fork; no transaction broadcast, all reads on public state.
**Severity:** **Medium** — persistent DoS of the only self-serve path to reclaim user-locked REG collateral (~1,616.9 REG held in the manager today), and a hard blocker for the PHASE2/PHASE3 (`borrowReusd`/`repayReusdWithStable`) lifecycle. No third-party theft; no permissionless loss of principal. Recovery requires a privileged action.

---

## Mechanism

`_syncReusdBalance()` burns whatever REUSD the REUSD aToken (`aREUSD`) currently holds, and it is the **unconditional first statement** of every user-facing REUSD entrypoint:

```solidity
// REUSDPoolManager.sol
/// @dev Burns any REUSD currently held by the REUSD aToken.
function _syncReusdBalance() private {
    DataTypes.ReserveData memory reusdReserveData = _pool.getReserveData(_reusd);
    uint256 reusdBalance = IERC20(_reusd).balanceOf(reusdReserveData.aTokenAddress);
    if (reusdBalance == 0) {
        return;
    }
    IERC20Mintable(_reusd).burn(reusdReserveData.aTokenAddress, reusdBalance);  // <-- needs a role the manager lacks
}

function withdrawReg() external whenNotPaused nonReentrant {
    _syncReusdBalance();                                     // <-- reverts here, before any user logic
    DataTypes.ReserveData memory reusdReserveData = _pool.getReserveData(_reusd);
    uint256 reusdDebt = IERC20(reusdReserveData.variableDebtTokenAddress).balanceOf(msg.sender);
    if (reusdDebt > 0) revert UserHasReusdDebt();
    uint256 regAmount = _userInfo[msg.sender].regLock;
    if (regAmount == 0) revert ZeroAmount();
    _userInfo[msg.sender].regLock = 0;
    _reg.safeTransfer(msg.sender, regAmount);               // <-- the REG the user is entitled to; never reached
    emit RegWithdrawn(msg.sender, regAmount);
}
```

`REUSD.burn()` is role-gated (`Reusdv2.sol`):

```solidity
// Reusdv2.sol
function burn(address from, uint256 amount) external {
    if (!hasRole(GOVERNANCE_ROLE, msg.sender) && !hasRole(BRIDGE_ROLE, msg.sender)) revert PERMISSION_ERROR(); // 0x03104826
    _burn(from, amount);
}
```

**The manager holds neither `GOVERNANCE_ROLE` nor `BRIDGE_ROLE` on the REUSD token.** So whenever `aREUSD` holds any REUSD, `_syncReusdBalance()` reverts with `PERMISSION_ERROR` (`0x03104826`) — and takes `withdrawReg()`, `borrowReusd()` and `repayReusdWithStable()` down with it, because the burn is their first line.

### Why this bites — and who

- `aREUSD` has held a nonzero REUSD balance (**0.5 REUSD**) continuously **since block 46,016,118 (~115 days)** — so the sync burn is armed right now.
- `withdrawReg()` is the **only self-serve path** for a user to reclaim the REG they locked as collateral in the subsidy program. Its own precondition is `reusdDebt == 0` (you may reclaim REG once you've fully repaid your REUSD debt).
- Every current REG-locker still carries REUSD debt, so today they each revert `UserHasReusdDebt` first — the deprivation is **prospective**: the **first user to finish repaying their REUSD debt** becomes withdraw-eligible and is then permanently unable to reclaim their REG, because the sync burn reverts before the eligibility check.
- **~1,616.9 REG** of user collateral currently sits in the manager (`REG.balanceOf(0x371a…) = 1616.919…e18`).
- It is also a **denial-of-availability for PHASE2/PHASE3**: `borrowReusd()` and `repayReusdWithStable()` sync first too, so those lifecycle steps are bricked on the same condition.

### Griefability

Because `_syncReusdBalance()` only checks `reusdBalance == 0`, **anyone** can (re-)arm the brick by transferring **1 wei of REUSD** to the `aREUSD` aToken. Even if an admin clears the balance, a single dust transfer re-bricks every synced entrypoint — a permanent, near-free griefing vector.

---

## Proof of Concept

`test/ReusdWithdrawRegDoS.t.sol` — interface-only fork of Gnosis mainnet at block `47956260`, against the **live** deployed contracts. **3/3 pass**, no transaction broadcast:

1. `test_withdrawReg_is_bricked_by_unauthorized_sync_burn` — a fresh, withdraw-eligible user (locked REG, zero REUSD debt) calls `withdrawReg()` → reverts `0x03104826` (`PERMISSION_ERROR`), while `aREUSD` holds 0.5 REUSD.
2. `test_root_cause_is_the_sync_burn` — neutralise **only** the burn (zero the aREUSD REUSD balance, nothing else) and the identical call now succeeds and delivers the user's 50 REG. Isolates `_syncReusdBalance()` as the sole blocker.
3. `test_one_wei_of_reusd_dust_rearms_the_brick` — 1 wei of REUSD in `aREUSD` reverts the call again → permanent griefing.

The user's `regLock` is seeded with `vm.store` at `keccak256(abi.encode(user, 362))` (the `_userInfo` mapping slot, verified live against a real locker before writing the test; each test re-asserts the readback via `getUserLockedReg`, so a wrong slot fails loudly).

```
Ran 3 tests for test/ReusdWithdrawRegDoS.t.sol:ReusdWithdrawRegDoS
[PASS] test_one_wei_of_reusd_dust_rearms_the_brick() (gas: 242255)
[PASS] test_root_cause_is_the_sync_burn() (gas: 316508)
[PASS] test_withdrawReg_is_bricked_by_unauthorized_sync_burn() (gas: 84556)
  aREUSD REUSD balance (wei): 500000000000000000
Suite result: ok. 3 passed; 0 failed; 0 skipped
```

Run: `forge install foundry-rs/forge-std --no-git` then `forge test -vv` (needs a Gnosis archive RPC that serves block 47,956,260; the public `rpc.gnosischain.com` worked at time of writing).

---

## Impact

- **Persistent DoS** of `withdrawReg()` — the sole self-serve mechanism to reclaim locked REG — for every user who becomes eligible (zero REUSD debt) while `aREUSD` holds any REUSD. ~1,616.9 REG of collateral is exposed.
- **DoA** for the PHASE2/PHASE3 REUSD flows (`borrowReusd`, `repayReusdWithStable`) under the same condition.
- **Permanent, ~free griefing**: 1 wei of REUSD dust re-arms it.
- Not a theft of principal and not a permissionless drain; funds are stuck, not stolen — hence Medium, meeting the DoS-of-a-core-lifecycle-function bar rather than High.

## Root cause & fix

`_syncReusdBalance()` performs a privileged side-effect (`REUSD.burn`) that the manager is not authorized to make, on the hot path of user functions that must not depend on it. Any of:

1. **Grant the manager the burn authority** on the REUSD token (`GOVERNANCE_ROLE` or `BRIDGE_ROLE`) so the sync burn succeeds. *(Simplest; but re-examine whether the manager should hold mint/burn power at all — that broadens its blast radius.)*
2. **Make the sync non-reverting** — wrap the burn in `try/catch`, or skip it when the manager lacks the role, so a failed housekeeping burn never blocks a user reclaiming their own collateral.
3. **Remove the burn from the user path** — do the REUSD-aToken reconciliation in a separate, admin/keeper-only routine, and let `withdrawReg()` depend only on the user's own `regLock`/debt state.

Option (2) or (3) is preferred: user collateral recovery should never be coupled to a protocol housekeeping side-effect.

## Scope / authorization

- **Live** on Gnosis (chainid 100). No open bug-bounty or audit-contest program matches RealT/RMM (checked Sherlock/Code4rena/Cantina/Immunefi via `programs.py`) → this is a **courtesy responsible disclosure**, no bounty.
- White-hat: the PoC forks public state and broadcasts nothing; no live contract, state, or funds were touched.
