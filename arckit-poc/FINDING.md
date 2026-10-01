# ArcLend (ArcKit, Arc 5042) -- public poke() compresses the 256-slot TWAP ring -> borrow DoS

Found 2026-10-01 (wave 15). Severity: **Low** (griefing / liveness; no theft). Status: drafted, not sent.

## Target
- ArcLend `0xBF0aD5CAE94A9e4aBeAeFC7cA5816B7f28983793`, ArcTwapOracle `0xedf33dA5bED98b5BAbDa4D71F55962CF74462491`
  (Arc mainnet, chain 5042; RPC https://5042.rpc.thirdweb.com). Repo https://github.com/RLProtocol/arckit.
- Verified source == repo HEAD (fetched to hunts/_volume/arckit-deployed). `oracle()` -> 0xedf3..2491, `RING()` = 256.
- threat.py 2026-10-01: LIVE + ACTIVE + FUNDED, 66 USDC, deployed ~2 days ago, 5 markets. No audit, no bounty.

## Bug
`ArcTwapOracle.poke` (ArcTwapOracle.sol:42-58) is permissionless and appends one observation per second to a
256-slot ring. `twapTick` (:69-94) counts only the observations still in the ring, so `covered` = now - oldest
kept observation. `ArcLend._borrowPrice` (ArcLend.sol:506-511) pokes, then reverts `OracleNotReady` when
`covered < MIN_TWAP_COVERAGE` (20 min, :39). Once 256 observations fit inside 20 minutes -- pokes closer than
1200 / 256 = 4.69 s -- every `borrow` and every `withdrawCollateral` with open debt reverts, for as long as the
pokes keep coming.

- Attacker: anyone, calling `ArcTwapOracle.poke(poolId)` (or `ArcLend.poke(id)`) about every 4 s.
  Cost: `eth_estimateGas` of `poke` on the live oracle = ~48.5k gas; at the observed 20 gwei (native USDC, 18 dec)
  ~0.001 USDC per poke, ~19k pokes/day ~ **$19/day** per market (all 5 markets' rings are already full: count 256).
- No attacker needed: each `borrow` pokes too, so a busy market (a borrow or keeper poke every < 4.69 s) locks
  itself out of new borrows. Their own keeper pokes every 10 min (ARCLEND.md:61-62), which hides the issue today.
- Side effect: `liquidate` (ArcLend.sol:308-311) prices at the TWAP with no coverage check; a compressed ring turns
  the documented 30-minute TWAP into a ~17-minute one, cutting the time a manipulator must hold a distorted price.
- Repay and deposit still work; a borrower can repay everything and then withdraw. No funds are lost.
- Not in ARCLEND.md "Known limitations" (:94-100).

## Proof
`arckit-poc/` (Foundry, the DEPLOYED oracle source + a mock StateView): `forge test -vv` -> 4/4
- baseline: a once-a-minute keeper gives full 1800 s coverage;
- 256 pokes 4 s apart -> coverage 1020 s < 1200 s (OracleNotReady), still blocked after another hour of pokes;
- ordinary load of one borrow per 4 s trips the check at the 253rd borrow;
- compressed ring: a tick held 1020 s becomes the whole "30-min" TWAP used by public liquidation.

## Fix
Rate-limit observations instead of trusting the caller: write a new slot only if
`now >= _obs[h].ts + MIN_SPACING` (else overwrite the newest), with `MIN_SPACING * RING` comfortably above the
30-min window (e.g. 15 s -> 64 min). Optionally make `twapTick` report the oldest timestamp so consumers can tell
"thin history" from "compressed history".
