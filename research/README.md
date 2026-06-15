# Bug-Pattern Library — the research engine behind the toolkit

Deep, example-rich studies of vulnerability classes — **especially the ones static recon CANNOT catch**.
Each pattern feeds three outputs: a **detector** (if static-catchable), a **hypothesis/invariant** (if it needs
reasoning), and a **writeup** (skill + reputation). Study the pattern + its real examples first; build the tool second.

## Why this exists (the detection gap — proven by data)
- **OWASP SC02:2026 top classes = Business-Logic Vulnerabilities + Price-Oracle Manipulation.** Price manipulation
  alone = **17.3% of major exploits Jan-2023…May-2025, >$165.8M**.
- Business-logic flaws = *the rules themselves are unsafe* — the code "does what it says", but what it says permits an
  exploitable outcome. **No runtime error, no access-control trip, no static signature.**
- The gap, in numbers: **frontier LLMs detect business-logic bugs ~31% of the time vs ~78% for senior human auditors.**
  Fuzzers (Echidna/Medusa) help on invariants — **but generating the RIGHT invariant still needs a human's model of
  what the protocol enforces.** → That human-derived-invariant + adversarial-reasoning layer is exactly our edge
  (`hypothesize.py` "their invariants as data" + L3 invariant fuzzing + Claude-as-verifier).

## Detectability tiers (where each pattern lands → which tool)
| Tier | What | Tool that catches it |
|---|---|---|
| **T0** regex signature | missing modifier, raw `ecrecover`, unchecked ERC20 return, `tx.origin` | `recon.py` detectors ✅ |
| **T1** AST / dataflow | some reentrancy, transitive gating, lib-auth | Slither + `analyze.py`; recon fix#15-19 |
| **T2** cross-component / state-invariant | shared-state breaks an invariant (supply≤backing, sharePrice unmanipulable) | `hypothesize.py` + `scaffold.py` L3 fuzz |
| **T3** economic / business-logic | the incentive/rule itself is exploitable; needs adversarial sequence | **human/Claude reasoning + adversarial sim** (the frontier) |

recon lives at T0/T1 (and floods FPs above that — the whole session proved it). **The money + the skill-growth are at
T2/T3.** This library's job: turn T2/T3 patterns into (a) the few extra T1 detectors that ARE catchable, and (b)
sharp, reusable HYPOTHESES + INVARIANTS for the T2/T3 reasoning layer.

## Method per pattern (the template)
Every pattern follows **[TEMPLATE.md](TEMPLATE.md)** — copy it, don't free-form. Six fixed sections so a missing one is
*visibly* missing (that's how we catch our own blind spots):
1. **Mechanism** — how the rule breaks, precisely.
2. **Real examples** — post-mortems + our own first-hand session finds (we read the code).
3. **The "tell"** — what to grep / read / ask to spot it.
4. **Detector idea (static, T0/T1)** — a concrete regex/AST rule, or "not statically catchable → T2/T3".
5. **Hypothesis / invariant (T2/T3)** — the property to assert + how to fuzz/reason it.
6. **Mitigations to RECOGNIZE** — so we don't FP on safe code (the session's #1 lesson: most flags are mitigated).

## Layout — split by class, so the system is extensible
One file = one pattern, one screen. Folders = the vuln class (= the future detector module it feeds). Add a pattern by
dropping a `TEMPLATE.md` copy into the right class folder; add a class by adding a folder. Nothing is "overloaded".
```
research/
  TEMPLATE.md                     pattern skeleton (copy this)
  patterns/
    accounting/  erc4626-inflation · reward-accounting     → det_erc4626, invariant: sharePrice/claim conservation
    pricing/     oracle-manipulation · index-manipulation  → det_oracle,  invariant: 1-block price move bounded
    liquidation/ liquidation-math                          → invariant: no bad-debt / no self-profit liquidation
    signatures/  cross-chain-and-aa                        → det_sig / det_l2_footgun, invariant: no replay
```

## Index (6 classes + the DeFiHackLabs mining synthesis)
| ✓ | Class | Pattern | Tier | Hook |
|---|---|---|---|---|
| ✅ | accounting | [erc4626-inflation](patterns/accounting/erc4626-inflation.md) | T2 | donation/first-depositor + vault-as-oracle. *dStake (first-hand), Venus, Inertia.* |
| ✅ | accounting | [reward-accounting](patterns/accounting/reward-accounting.md) | T2/T3 | wave/queue double-claim, dust, timing. *CU LibRewards = the correct design (first-hand).* |
| ✅ | accounting | [split-brain-accounting](patterns/accounting/split-brain-accounting.md) | T2/T3 | one conserved var, ≥2 unreconciled writers (live `+=` vs off-chain-snapshot overwrite · weakest bridge-adapter · OFT bypasses the backing accumulator). *Tizi netAsset: liquid-withdrawal front-run mints phantom yield (first-hand deep-dive). Tried a detector → FP-flooded on interest-index recompute → reasoning seed.* |
| ✅ | pricing | [oracle-manipulation](patterns/pricing/oracle-manipulation.md) | T2/T3 | spot-vs-TWAP, AMM-reserve, read-only-reentrancy. *Likwid truncatedReserves = the mitigation.* |
| ✅ | pricing | [index-manipulation](patterns/pricing/index-manipulation.md) | T2/T3 | Aave-fork `liquidityIndex` inflation on empty markets. *dTRINITY $257k (first-hand).* |
| ✅ | liquidation | [liquidation-math](patterns/liquidation/liquidation-math.md) | T2/T3 | bad-debt socialization, self-liquidation, threshold, rounding direction. *TermMax/CU (first-hand).* |
| ✅ | signatures | [cross-chain-and-aa](patterns/signatures/cross-chain-and-aa.md) | T1/T2 | mutable-chainId replay (zkMarkets); extcodesize/EIP-1271 on zkSync. *det_l2_footgun.* |
| ✅ | **mining** | [**defihacklabs-pattern-mining**](patterns/defihacklabs-pattern-mining.md) | T0-T3 | **751 real hacks → 53 patterns** (cross-year taxonomy + invariant-seeds + detector-backlog). *spot-oracle/token-reserve-manip/donation/business-logic dominate every year.* |

### Harvest status — the T1-catchable slice is wired into `recon.py` (38 detectors, 351 tests, leads-not-verdicts)
| Pattern | Detector (recon.py) | What it flags |
|---|---|---|
| erc4626-inflation | `det_erc4626` **+fix#20** | no offset/dead-shares; **enriched** when `totalAssets()` is balance-based (dStake flavor). |
| oracle-manipulation | `det_oracle` **+ spot sub-check** | value/price fn that divides **spot** reserves; recognizes TWAP/clamped → no flag. |
| **spot-AMM-as-oracle** (DeFiHackLabs #1) | **`det_spot_oracle`** | borrow/collateral/reward priced from `getReserves`/`pricePerShare`/`get_virtual_price`/`slot0` w/ no TWAP; skips AMM-core swap fns (tuned on real DEX). |
| **self-transfer inflation** (LPC/SSS/GPU) | **`det_self_transfer`** | custom transfer writes BOTH balances from pre-captured locals (no from==to guard) → self-send overwrites the debit. Catches direct-cache (GPU) + tuple-via-helper (LPC) variants; skips OZ `+=` / in-place SafeMath. *TP-confirmed on BY/LPC/GPU on-chain source.* |
| **pair-reserve mutation** (reflection/BSC) | **`det_pair_reserve_mutation`** | unprivileged burn-of-pair-balance, or reflection-token `pair.sync()/skim()`, crashes the DEX reserve → constant-product overvalues the attacker's tokens. Skips DEX router/pair periphery sync (no reflection markers) + owner-gated. |
| **unprotected init** (class E) | **`det_unprotected_init`** | external/public `initialize`/`init` granting ownership/role with no `initializer`/`only*`/manual-`initialized` guard → front-run / re-init seize (DaoMaker/Telcoin/Pike). 0 FP on 16 real proxy protocols. |
| **caller-supplied authority** (class E, #1 2026) | **`det_caller_supplied_authority`** | `transferFrom(order.maker,…)` where the source is a **`calldata`** struct field, unbound to msg.sender / no signature. `calldata` gate excludes the Aave-lib `memory`-struct FP. *T0 covers the inline-RFQ shape only; helper/Safe-module/bridge variants are reasoning-tier.* |
| reward-formula (posi class) | **`det_reward_formula`** | reward accumulator added **inside** `.mul(balance)` (Synthetix mis-bracket) → ~balance² inflation. |
| reward-accounting | `det_reward` | payout transfers with no claimed/rewardDebt marker (or marker **after** transfer); skips keeper-gated. |
| index-manipulation | `det_index` | Aave-fork `liquidityIndex`/`cumulateToLiquidityIndex` with no min-liquidity/cap guard. |
| liquidation-math | `det_liquidation` | surfaces liquidation entrypoints; [!] if no self-liq guard or seize rounds **up**. |
| cross-chain-and-aa | `det_domain` + `det_l2_footgun` | cached EIP-712 separator (no fork-recompute) + extcodesize/`isContract` AA footguns. |
| **signature gaps** (class F) | **`det_signature`** | raw ecrecover missing address(0)/deadline + a nonce **declared-but-never-consumed** (still replayable); ERC-1271 `isValidSignature` on a calldata-struct verifier = attacker yes-contract (MureDistribution). *Bare-param verifier = permit shape → reasoning-tier.* |

**T2/T3 slice (NOT regex — the reasoning layer) ✅ harvested → [`invariant-lab/test/templates/`](../invariant-lab):** a
self-validating Foundry invariant template per class (mock with a `buggy` toggle → fuzzed invariant passes on fixed,
provably fails on buggy). 6 templates, all verified both ways. recon surfaces the *smell*; the invariant decides.

**Backlog (not yet written):** interest/fee rounding (mulDivUp/Down asymmetry — Monolith soft-spot) · init/upgrade/storage
(front-run init, uninitialized impl, storage-collision, transitive proxy).

> Sync the transferable lessons into the Obsidian "Крипто безопасность" vault (heuristics + pattern notes) — that's the public/study face; this dir is the toolkit-feeding face.
