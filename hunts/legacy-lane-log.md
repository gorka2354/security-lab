# legacy.py lane — run log + meta-learning (2026-06)

The deprecated-but-funded lane (`toolkit/legacy.py`), built from the Thetanuts $2.1M lesson. Runs so far:

| Date | Target | Mode | Result |
|---|---|---|---|
| 06-24 | Indexed Finance (deployer `0x236ecc...`) | from-deployer | 43 contracts, all EMPTY (drained in the 2021 hack) |
| 06-24 | Yearn iEarn v1 (5 vaults) | check | 4 ACTIVE, 1 LEGACY-FUNDED (yUSD) |
| 06-25 | yUSD `0x4b5bfd52...` deep read | — | EIP-1167 -> canonical Yearn V2 Vault.vy (audited) -> NO FINDING |
| 06-26 | Charm Finance (deployer `0x9f2aa07f...`) | from-deployer | 13 contracts, all EMPTY (wound down, users exited) |

## Meta-learning: deprecated-AND-still-funded is RARE
When a protocol winds down, users withdraw -> old contracts go to ~0. That's why Thetanuts (\$2.1M left in a
long-abandoned vault) was newsworthy: it's an anomaly, not the norm. The lane is CORRECT to return "empty" on
wound-down protocols -- the value is real but sparse.

**Strategy implication:** one-at-a-time deep scans are low-EV for this class (too rare). To catch a
Thetanuts-style leftover, run a BROAD CHEAP SWEEP across many factories/deployers and let the rare
funded-dormant survivor surface -- don't hand-pick and deep-dive. (Backlog: a `legacy.py sweep <list>` that
ranks by residual value across N targets; feed it from-factory enumerations of many wound-down protocols.)

## Broad sweep #1 (2026-06-26) — `sweep --file wound-down-index-vaults.txt`
21 old contracts across 6 wound-down/migrated protocols (PieDAO, PowerPool, Harvest, Set/IndexCoop, Yearn
iEarn, Indexed). Result: **17 ACTIVE-FUNDED, 4 LEGACY-FUNDED** (ranked by residual value). The 4:
- `0x4b5bfd52...` yUSD — control; already resolved = audited Yearn V2.
- `0xb2b93357...` PowerPool PIPT(old) — deep-read -> **Balancer v1 BPool fork** (Solidity 0.6.12), admin fns
  gated by `_checkController()`. **NO FINDING** (audited fork, proper gating).
- `0xf9e5f902...` Harvest fDAI pool (1172d dormant) — a reward pool, not share-math; low EV.
- `0xE1f9A3EE...` Harvest fUSDC pool — supply≈0 (dust) -> effectively EMPTY, a rank artifact.

**Pattern confirmed:** the dormant-funded survivors are forks of AUDITED code (Yearn, Balancer) -- the
protocols that wound down used standard codebases. A bespoke-vulnerable leftover like Thetanuts is the rare
exception, not the rule. Caveat: `totalSupply` is shares, not $ value -- a real backing check is still needed.

**Engine fix from this read (FP -> precision, the loop):** recon's INLINE_AUTH didn't recognize
`_checkController()` (Balancer/PowerPool BPool) -> 5 false access-control flags. Added fix#34
(`_check(Controller|Manager|Admin|Operator|Gov*)\(`), scoped to NOT suppress input-validators (`_checkAmount`).

## Lane status
Built + validated end-to-end (from-deployer / from-factory / check), 2 live FP-calibrations baked in
(EIP-7702 skip, age-based dormancy). Correct on every run. No live target found yet -- expected, given the
class is rare. Ready for a broad sweep when we assemble a candidate factory/deployer list.
