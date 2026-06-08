# invariant-lab — the T2/T3 reasoning layer

Foundry invariant **templates**, one per vulnerability class, that encode the §5 invariant of each
[`research/patterns/`](../research/patterns) study. This is the layer recon.py **cannot** reach: recon surfaces a
*smell* (T0/T1); a fuzzed invariant proves whether the *property* actually holds (T2/T3) — where the real bugs live.

## Layout
```
src/Staking.sol · test/StakingInvariant.t.sol   worked example (planted rounding bug, Buggy/Fixed pair)
test/templates/<class>/<Name>.t.sol             the per-class template library (this contribution)
../toolkit/scaffold.py                           auto-generates the per-target Handler boilerplate (the tedious 80%)
```
`scaffold.py` writes the Handler/targetSelector wiring for a concrete contract; **the templates here supply the
reasoning** — the actual invariant + the adversarial action that breaks it. Use both: scaffold the handler, drop in
the matching template's invariant.

## Template convention (green-by-default, self-validating)
Every template is **one file** with three parts:
1. **A minimal mock with a `buggy` toggle** — `buggy=true` is the anti-pattern, `buggy=false` is the mitigation.
2. **A `*Invariant` contract** wired against the **FIXED** mock → it **passes** (this is the copy-me skeleton).
3. **A `*SelfCheck`** with deterministic `test_buggy_*` / `test_fixed_*` proving the bug is **real** on the buggy mock
   and absent on the fixed one — so the invariant is provably non-trivial (the "find our own mistakes" guard).

Self-validate the invariant itself: flip the `setUp()` toggle to `true` and run `forge test --mc <Name>Invariant` — it
must **FAIL** with a counterexample. Flip back to `false` (committed state = green). Every template below was verified
both ways.

## The library (6 patterns)
| Class | Template | Invariant / property | Buggy ⇄ Fixed |
|---|---|---|---|
| accounting | [ShareInflation](test/templates/accounting/ShareInflation.t.sol) | a meaningful deposit never rounds to 0 shares | balance-based, no offset ⇄ internal accounting + virtual offset |
| accounting | [DoubleClaim](test/templates/accounting/DoubleClaim.t.sol) | paid ≤ accrued per actor | marker never consumed ⇄ zeroed before transfer |
| pricing | [SpotPrice](test/templates/pricing/SpotPrice.t.sol) | price unmovable within one swap tx | raw spot ⇄ rate-limited (truncatedReserves) |
| pricing | [IndexInflation](test/templates/pricing/IndexInflation.t.sol) | index move per accrual bounded | divide by dust supply ⇄ min-liquidity floor |
| liquidation | [Liquidation](test/templates/liquidation/Liquidation.t.sol) | only unhealthy positions liquidatable | no health gate ⇄ health < 100% required |
| signatures | [Replay](test/templates/signatures/Replay.t.sol) | sig valid on chain A invalid on B | cached domain separator ⇄ recompute on chainId change |

Each maps back to a `research/patterns/` file (§5) and to the `recon.py` detector that surfaces the smell — the smell
finds candidates, the invariant decides.

## Run
```sh
forge test                              # whole lab (256 runs x 100 depth per invariant)
forge test --mc ShareInflation -vv      # one template (invariant + self-check)
forge fmt                               # templates are fmt-clean
```
**Note on conventions:** the templates are green-by-default. The original `StakingInvariant.t.sol` keeps the older
demo style where `BuggyStakingTest` fails on purpose (the teaching artifact), so a full `forge test` shows that one
intentional failure. New templates do not add red — they prove the bug via the deterministic self-check instead.

## Adding a class
Copy the closest template into `test/templates/<class>/`, swap the mock for your target, keep the invariant + a
self-check that flips the bug. If the self-check can't make the buggy mock fail, the invariant is wrong — fix it
before trusting a green run on real code.
