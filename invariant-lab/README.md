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

### Multi-engine scaffold (`scaffold.py --engine`)
The scaffolder emits more than a Foundry harness now (Recon-Fuzz pattern — one harness, many engines):

| `--engine` | Output | Runs under |
|---|---|---|
| `foundry` (default) | one `<C>Invariants.t.sol` (Handler + targetSelector + 5 invariant stubs) | Foundry |
| `chimera` | `Setup/Properties/TargetFunctions/CryticTester/CryticToFoundry.sol` + `echidna.yaml` + `medusa.json` | **Foundry + Echidna + Medusa** |
| `halmos` | `<C>Symbolic.t.sol` — symbolic `check_*` (prove an invariant on ALL inputs, not samples) | Halmos |
| `all` | chimera + halmos | all |

```sh
python ../toolkit/scaffold.py src/Staking.sol StakingRewards --engine chimera --out test/recon
```
The `chimera` handlers are **engine-portable** (no forge-std `vm`/`bound`; `msg.sender` is one of the fuzzer-configured
actors), so the *same* `property_*` invariants run under all three engines — Echidna shrinks counterexamples best,
Medusa is fastest on big codebases, Foundry debugs the repro (`CryticToFoundry` wraps each `property_*` in an
`invariant_*`). Generated Solidity is `forge build`-clean (verified). **Engine availability:** `forge` is local;
`echidna`/`medusa`/`halmos` need Linux/CI/WSL (on this Windows box halmos can't build `safe-pysha3` without MSVC — same
"canonical home is Linux/CI" caveat as Slither). The scaffold *generation* is engine-independent — author here, run on CI.

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
**Conventions:** everything is green-by-default and `forge fmt`-clean — a full `forge test` is all-green (the worked
example and every template prove their bug via a deterministic self-check + a flip-to-fail invariant, never a committed
red test). `forge test --mc ShareInflationReal` additionally needs the OZ dep (see the real-code wire below).

## Real-code wire — `test/real/ShareInflationReal.t.sol`
The first template run against **production code, not a mock**: OpenZeppelin's actual `ERC4626` (v5.1.0) — the base
Kiln's `Vault` and thousands of live vaults inherit. Setup (the OZ dep is gitignored like forge-std):
```sh
forge install OpenZeppelin/openzeppelin-contracts@v5.1.0
forge test --mc ShareInflationReal -vv
```
**What it found (a real, non-obvious result):**
- Deterministic checks PASS — OZ's virtual shares make the donation attack **unprofitable** (offset 0: the victim is not
  zeroed and the attacker can't recoup the donation; offset 6: the victim gets near-fair shares).
- The fuzzed `meaningfulDepositNeverRoundsToZero` invariant **FAILS** on offset 0 with **no seed** — under a large enough
  donation the fuzzer still grieves a meaningful deposit to 0 shares. So OZ's offset is **economic, not absolute**
  protection: it makes the attack lose money, but doesn't stop a deep-pocketed griefer. The committed test **seeds dead
  shares** (the standard fix; cf. Kiln's configurable offset up to 23) → the invariant holds. Remove the seed to watch it fail.

This is exactly why a self-validating invariant beats a green checkmark: run on real code it taught us a property the
mock's "fixed" path (internal accounting, donation-immune) was hiding.

## Adding a class
Copy the closest template into `test/templates/<class>/`, swap the mock for your target, keep the invariant + a
self-check that flips the bug. If the self-check can't make the buggy mock fail, the invariant is wrong — fix it
before trusting a green run on real code.
