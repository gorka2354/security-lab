# HUNT: death.fun (DeathFun, Abstract) -- fan-out DIG -> deep L4 -> FINDING (2026-06-15)

- **Surfaced by the Abstract fan-out triage** (luck-games zone, egor's edge). Live gambling dapp on Abstract
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

## Verdict: REAL on-chain broken invariant; drain backend-conditional -> disclosure-worthy
The cleanest result of the fan-out sessions: a verified, live, PoC-backed broken invariant on a funded contract,
found via the Abstract sweep (freshness + the gaming niche = the lever, re-confirmed). Severity calibrated HONESTLY
(Medium/High-conditional, not a guaranteed drain -- the payout is admin-signed). No bounty -> egor discloses direct.
See [[fanout-triage-workflow-validated]].
