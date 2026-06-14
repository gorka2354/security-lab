# death.fun (DeathFun, Abstract) — `increaseBet` lets a player inflate on-chain `betAmount` for free (signature replay + no `msg.value` check)

**Severity:** Medium — **High if the backend sizes cash-out payouts from the on-chain `betAmount`** (then it is a direct house drain). On-chain it is a confirmed broken invariant (the recorded bet decouples from escrowed ETH); the monetary impact is realized off-chain.
**Component:** `DeathFun.increaseBet(uint256,uint256,uint256,bytes)` (Abstract 2741; deployed impl `0x2c133230cfca00b9bf78c46dae03a97019d96551`, proxy `0x27EDd16eE56958fddCBA08947f12C43DDeC2B20C`, ~20.79 ETH held).
**Status:** deployed + live; verified source matches the deployed impl; no external audit found; no public bug bounty.

## Summary
`increaseBet` raises a game's recorded `betAmount` by a backend-signed `amount`, but (a) it never checks that
`msg.value == amount` (the player can send **0 ETH**), and (b) the admin signature binds only
`(prefix, gameId, amount, deadline)` — **no `msg.sender`, no `msg.value`, no nonce, no `address(this)`/chainid, and
there is no consumed-signature or status guard**. So a single backend authorization can be **replayed any number
of times until the deadline**, each call adding `amount` to `betAmount` while escrowing nothing. The on-chain
`betAmount` becomes an attacker-controlled number, fully decoupled from the ETH actually held.

## Affected code
```solidity
function increaseBet(uint256 onChainGameId, uint256 amount, uint256 deadline, bytes calldata serverSignature)
    external payable
{
    if (block.timestamp > deadline) revert SignatureExpired();
    bytes32 messageHash = keccak256(
        abi.encode(string.concat(messagePrefix, ":increaseBet"), onChainGameId, amount, deadline)
    );                                  // <-- no msg.sender, no msg.value, no nonce in the signed message
    _verifyAnyAdminSignature(messageHash, serverSignature);
    Game storage game = games[onChainGameId];
    if (game.player != msg.sender) revert NotAuthorized();
    game.betAmount += amount;           // <-- adds the SIGNED amount; msg.value is never checked; no replay guard
}
```

## Root cause
The signed message authorizes "increase game G by `amount` until `deadline`" but the contract neither (1) requires
the player to actually escrow that `amount` (`msg.value` is ignored) nor (2) consumes the authorization (no nonce /
used-signature map / one-shot guard). Both are needed for `betAmount` to mean "ETH the player has staked".

## Impact
- **On-chain (proven):** `betAmount` can be inflated to any value for 0 extra ETH. In the PoC, replaying one `+5 ETH`
  authorization 10× leaves `betAmount = 51 ETH` while the contract escrows only the original `1 ETH`.
- **Monetary (conditional):** `payoutAmount` in `cashOut` is itself admin-signed, so there is **no pure on-chain
  drain** by an external attacker. **But if the backend computes the cash-out `payoutAmount` from the on-chain
  `betAmount`** (or trusts `BetIncrease` events as proof of stake), a player inflates `betAmount` for free, the
  backend signs an over-sized payout, and the house is drained from the shared ~20.79 ETH pool. Even if the backend
  is careful, the bug corrupts on-chain accounting/analytics and the provable-fairness record.

## PoC (Foundry, verbatim repro of the deployed logic)
`invariant-lab/src/DeathFunRepro.sol` (createGame + increaseBet + the signature verifier copied line-for-line) +
`invariant-lab/test/DeathFunIncreaseBetPoC.t.sol` — `forge test --match-contract DeathFunIncreaseBetPoC -vv`:
```
test_increaseBet_freeReplayInflation:
  ETH actually escrowed : 1.000000000000000000
  on-chain betAmount    : 51.000000000000000000     (one +5 ETH authorization replayed 10x, msg.value=0 each)
test_increaseBet_ignoresMsgValue:
  betAmount += 3 ETH while msg.value == 0; contract balance unchanged
```

## Recommendation
Make `betAmount` mean escrowed ETH, and make each authorization one-shot:
1. **Enforce escrow:** `require(msg.value == amount, "bet not funded")` in `increaseBet` (and confirm `createGame`
   already binds `msg.value`, which it does).
2. **Kill replay:** include `msg.sender`, `address(this)`, `block.chainid`, and a per-game/per-signer **nonce** in the
   signed message, and store a consumed-signature / nonce marker so an authorization cannot be reused.
3. Backend hardening (defense-in-depth): never size a payout from on-chain `betAmount` / `BetIncrease` events; reconcile
   against actual deposited value.

## Provenance & disclosure
Found via an Abstract-ecosystem triage sweep, then a manual L4 read + Foundry PoC. No Immunefi/bug-bounty program was
found for death.fun -> responsible **direct disclosure** to the team (white-hat, before any public mention). The
on-chain half is demonstrably broken today; please confirm whether the backend's payout sizing trusts on-chain
`betAmount` (that determines whether this is High/drain or Medium/accounting-corruption).
