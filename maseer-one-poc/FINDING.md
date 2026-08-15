# Maseer `MaseerOne.redeem()` — burns full principal for a zero claim when redemption spread is 100% (missing post-spread guard)

**Severity:** Low (admin-gated; high impact-if-triggered, low likelihood)
**Status:** Live on Ethereum mainnet. Code-confirmed by reading verified source. Not currently exploitable (parameters healthy).
**Contract:** `MaseerOne` (wstGBP / Maseer institutional RWA token) — `0x57C3571f10767E49C9d7b60feb6c67804783B7aE` (chain 1), verified source.
**Class:** Input-validation gap — a value is validated BEFORE a transform but consumed AFTER it (same class as a checked-in-one-branch / used-in-another gap).
**Disclosure intent:** goodwill hardening report to the Maseer team. White-hat, read-only analysis over public deployed code. No funds or live state were touched.

---

## Summary

`MaseerOne.redeem(amt)` validates the **raw** oracle price (`_read() != 0`) but never re-validates the **post-spread** redemption price returned by `_burncost()`. When the redemption spread `bpsout` is set to its maximum permitted value `10000` (100%), `_burncost()` returns **exactly 0**, so the redemption `_claim` is 0 — yet the caller's full `amt` of tokens is **burned unconditionally**, with **no revert**. Anyone who calls `redeem()` in that state silently loses their entire principal for nothing.

The protocol's own sibling oracle (`WsgemFraxlendDualOracle._compose`) explicitly guards this exact case (`if (burn_ == 0 || mint_ == 0) revert InvalidQuote();`), and the `IWsgem` interface docs note that `burncost()` "can be zero whenever the redemption spread is set to 100%." So the missing guard in `MaseerOne.redeem()` is a real oversight, not an intentional design choice.

## Affected code (verified source)

`MaseerOne.sol` (Solidity ^0.8.28):

```solidity
function redeem(uint256 amt) external burnlive pass(msg.sender) returns (uint256 _id) {
    if (amt < WAD) revert DustThreshold(WAD);

    uint256 _unit = _read();                 // 217: raw NAV, Pip(pip).read()
    if (_unit == 0) revert InvalidPrice();    // 220: checks the RAW price ONLY

    _unit = _burncost(_unit);                 // 223: Act(act).burncost(price) — CAN be 0
    uint256 _claim = _wmul(amt, _unit);       // 226: _claim == 0 when _unit == 0
    totalPending += _claim;                   // 229: += 0
    _id = redemptionCount++;
    uint96 _time = uint96(block.timestamp + _cooldown());
    redemptions[_id] = Redemption({ amount: _claim, redeemer: msg.sender, date: _time }); // amount: 0
    _burn(msg.sender, amt);                   // 245: FULL balance burned regardless of _claim
    emit ContractRedemption(_id, _time, msg.sender, _claim);
    if (_time == block.timestamp) { exit(_id); } // 251: exit() then transfers 0 out
}
```

The spread math (`MaseerGate.sol`):

```solidity
function burncost(uint256 _price) external view returns (uint256) {
    return _adjustBurnPrice(_price, bpsout());
}
function _adjustBurnPrice(uint256 _price, uint256 _bps) internal pure returns (uint256) {
    return _divup((_price * (10_000 - _bps)), 10_000);   // _bps == 10000  =>  0
}
function setBpsout(uint256 bpsout_) external auth {
    if (bpsout_ > 10000) revert UnrecognizedParam(bytes32(bpsout_));  // 10000 is ALLOWED
    _setBpsout(bpsout_);
}
```

`bpsout = 10000` is an accepted value (`> 10000` reverts, `== 10000` does not) → `_adjustBurnPrice` returns 0 → `_burncost(_read())` returns 0 → `_claim = 0`, but `_burn(msg.sender, amt)` still burns the caller's full `amt`.

## Impact

- **What:** silent, total loss of principal for any address that calls `redeem()` while `bpsout == 10000`. The transaction succeeds; the tokens are burned; the recorded/paid claim is 0. No error, no revert, no event distinguishable from a normal redemption other than `_claim == 0`.
- **Scope:** every non-banned holder that redeems in that window.

## Exploitability & likelihood (honest framing)

- The dangerous state requires the `auth` role on `MaseerGate` (`act`) to call `setBpsout(10000)`. That role is currently a **3-of-5 Gnosis Safe** — i.e., this is **not** outsider-triggerable and **not** a third-party drain. It is a misconfiguration / user-protection gap, weaponizable only by (or through a compromise of) the trusted operator.
- Current live value is healthy: `bpsout = 25` (0.25%), so the bug is **latent, not active**.
- The protocol already has a *correct* way to stop redemptions — `setHaltBurn()` (and the `burnlive` modifier). Reaching the harmful state via `bpsout = 10000` is therefore a misconfiguration, never a normal operational step. This is why the likelihood is Low.
- Impact-if-triggered is high (silent principal loss), so the defense-in-depth value of the fix is real even though the base rate is low.

## Recommended fix (one line, matches the sibling contract)

Re-validate the price **after** applying the spread, exactly as `WsgemFraxlendDualOracle._compose` already does:

```solidity
_unit = _burncost(_unit);
if (_unit == 0) revert InvalidPrice();   // ADD: reject a 100%-spread redemption instead of burning for 0
```

(Equivalently, guard `_claim != 0` after line 226.) This turns a silent principal-burn into a clean revert, so a user who tries to redeem at a 100% spread is protected rather than zeroed.

## Reproduction sketch (deterministic; no fork harness needed to see it)

The logic is fully deterministic and visible in verified source, so the trace above IS the proof. To demonstrate on a mainnet fork if desired:
1. Fork Ethereum mainnet at a recent block.
2. As the `auth` role (impersonate the `act` Gate's ward / the 3-of-5 Safe), call `MaseerGate.setBpsout(10000)`.
3. As any holder with `>= 1 WAD` of MaseerOne and past `openBurn`, call `MaseerOne.redeem(balance)`.
4. Observe: the call succeeds, `redemptions[id].amount == 0`, holder balance decreased by the full `amt`, no revert. (With the fix applied, step 3 reverts `InvalidPrice()`.)

## Notes on the rest of the surface (context, not findings)

The wider Maseer stack is a **permissioned, fully-trusted-operator RWA** design (a single no-timelock `MaseerProxy` set — `pip`/`act`/`adm`/`cop` — governed by the 3-of-5 Safe; `issue()` unbounded mint, `smelt(address,uint256)` arbitrary-holder burn). Those are the intended trust boundary of an institutional RWA, disclosed by design — not defects. Separately: `MaseerPrice.read()` has no on-chain NAV-staleness check (last price is used indefinitely if the pusher stops) — a design-disclosed informational point, not part of this finding. The `Arb-Capital/wsgem-fraxlend` oracle repo that the DefiLlama listing links is a clean, pre-launch stub (its FraxLend pair is not yet deployed); the live surface is this Maseer codebase.

---

*Researcher discloses, not the tool. This report is prepared for private, responsible disclosure to the Maseer team; it documents a defense-in-depth gap in publicly deployed, verified code and contains no exploit against live funds.*
