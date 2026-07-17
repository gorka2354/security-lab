# HUNT: death.fun (DeathFun, Abstract) -- fan-out DIG -> deep L4 -> FINDING (2026-06-15)

- **Surfaced by the Abstract fan-out triage** (luck-games zone, the GameFi/gambling focus). Live gambling dapp on Abstract
  (zkSync, chain 2741): proxy `0x27EDd16eE56958fddCBA08947f12C43DDeC2B20C`, impl
  `0x2c133230cfca00b9bf78c46dae03a97019d96551`, holds ~**20.79 ETH**, gameCounter ~4.65M, 323 events/5k blocks.
- Original greenfield (forkdrift: no base), no audit evidence, no Immunefi/bounty.
- **deployed impl == verified source** (fetch_source via Etherscan-v2; the `increaseBet` selector 0x0b669290 is
  in the deployed runtime). The bug is LIVE.

## FINDING -- `increaseBet` free `betAmount` inflation (signature replay + no `msg.value` check)
**Severity: Medium (High if the backend sizes payouts from on-chain `betAmount`).**
`increaseBet` adds a backend-signed `amount` to `game.betAmount` but never checks `msg.value`, and the signature
binds only `(prefix, gameId, amount, deadline)` -- no `msg.sender`/`msg.value`/nonce/`address(this)`/chainid and no
consumed-signature guard. So one authorization is **replayable until deadline**, each call inflating `betAmount`
for 0 ETH. `cashOut`'s `payoutAmount` is itself admin-signed -> **no pure on-chain drain by an external attacker**;
the drain is realized only if the off-chain backend trusts on-chain `betAmount` to size the cash-out.

**PoC -- DONE, passes:** `invariant-lab/src/DeathFunRepro.sol` (verbatim createGame+increaseBet+verifier) +
`invariant-lab/test/DeathFunIncreaseBetPoC.t.sol`. One `+5 ETH` authorization replayed 10x with `msg.value=0`
-> `betAmount = 51 ETH` while escrow stays `1 ETH`. Disclosure:
`hunts/death-fun/DISCLOSURE-increasebet-free-inflation.md`.

## Other (triaged, lower)
- `payReferral` -- any admin sends arbitrary contract ETH to any recipient (centralization / backend-key = drain;
  out of scope, declared trust root).
- No `address(this)`/chainid in any signed message -> cross-deployment signature replay (forward-looking risk if a
  redeploy reuses prefix "DeathFun" + the same signer 0x937C...).

## Callability check (2026-06-14) -> NOT exploitable in the live custodial model -> downgraded
On-chain reality (Etherscan-v2 txlist): the contract IS live + busy (**3021 createGame in 6000 recent txns**),
but it is **CUSTODIAL** -- every `createGame` comes from ONE backend relayer `0xd4b0eb0d` (fixed 0.001 ETH bet),
`markGameAsLost` from admin signer `0x937c`. So the on-chain `game.player` is the **RELAYER, not the real
(off-chain) user**. `increaseBet` gates on `game.player == msg.sender` -> a real user is never the on-chain
player -> **cannot call `increaseBet` on their game**. And `increaseBet` is **dormant** (0/6000 recent txns;
last used ~block 45M). `cashOut` payout is admin-signed (no on-chain inflation). => the broken invariant is REAL
in code but **NON-exploitable by an external attacker in this architecture**.

NB: my earlier "game stopped / contract quiet" was a **FALSE event-scan 0** (getLogs range-limit returned 0 while
the contract had ~100 txns/20min). Fixed: `activity.py` now uses Etherscan-v2 **txlist** as the authoritative
liveness signal, overriding an event-based false-DORMANT.

## Verdict: REAL code bug, INFORMATIONAL (non-callable in the live custodial model) -> ledger wontfix
PoC-backed broken invariant, but the custodial relayer architecture (on-chain player == backend) + the dormant
feature make it non-exploitable today. Disclose only as a **courtesy** (fix `increaseBet` before any
non-custodial relaunch), not as a Medium/High live finding. No bounty. calibrate -> withdrawn; ledger -> wontfix.
**Lessons captured -> activity.py / VERIFY:** (1) liveness via **txlist** not getLogs (events false-0); (2)
**per-function callability** (is the bug fn actually called?); (3) **custodial-caller check** (is the on-chain
actor a backend relayer, not the user?). See [[fanout-triage-workflow-validated]].
