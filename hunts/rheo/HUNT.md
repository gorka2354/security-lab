# DEEP HUNT: Rheo (formerly Size) — credit marketplace, fixed-rate lending

**Committed multi-session deep audit.** Target locked 2026-06-07. Clone (gitignored):
`hunts/_volume/rheo` (+ `hunts/_volume/vlv`). This file is the engagement anchor.

## Scope (Cantina bounty)
- **rheo-xyz/rheo-solidity** — in-scope commit `b7714a2cdec77bb85a11ea80eef81a31c5f912f6` (**5526 LOC**)
- **rheo-xyz/very-liquid-vaults** — commit `e356a70cffe5912618488ff79562db7ce48633b4` (973 LOC)
- Ethereum only. Payout: **Critical $50k / High $5k** / Med-Low variable. $10 deposit, legal-age/non-sanctioned.
- **OUT OF SCOPE (= our "is it known" filter):** known issues in README + the 11 past audits;
  anything covered by tests; centralization/integration risk (USDC/Aave/Chainlink).
- Flexible clause: a fund-risk bug in an unlisted component MAY still qualify.
- NOTE: HEAD is 2026-05-13 (PR#25 arbitrum); **must align findings to scoped commit b7714a2**.

## Architecture (from README + structure)
- UUPS proxy; **single entrypoint `Size.sol`**; logic in external libraries called via
  `delegatecall` with one `State storage`. Every user fn = **FREI-PI**:
  `validateX(params); executeX(params); validateInvariant(params);`
- **Multicall** (+ all user fns `payable` to wrap ether; `deposit` uses `address(this).balance`).
- Deposit tokens 1:1: USDC->szaUSDC, WETH->szWETH (mint on deposit / burn on withdraw).
- Roles: ADMIN, PAUSER_ROLE, KEEPER_ROLE, BORROW_RATE_UPDATER_ROLE (all trusted).
- **Oracles:** Chainlink ETH/USDC price feed (18dec) + Variable-Pool-Borrow-Rate feed
  (off-chain Aave rate, admin-settable, stale-interval guard) + **Uniswap TWAP fallback**.
- Money flow: deposit -> limit/market orders (buy/sell credit) -> debt+credit positions ->
  liquidate / selfLiquidate / compensate / liquidateWithReplacement -> withdraw.
- Factory: shared liquidity across markets + holds access control (v1.7) with per-market fallback.
- Maths: Solady FixedPointMathLib, explicit mulDivUp/Down, **rounding favors the maker** (passive party).

## Hunting focus — the FRESH PERIPHERY (where 11 audits are thinnest)
Core lending is hammered (11 audits + Echidna/Medusa/Halmos/Slither). EV is in recent,
intricate features (audit-drift). Priority order:
1. **Copy-trading / collections / curators / rate-providers (v1.6.1->v1.8).** README flags
   subtleties: "copy address can change curves in a single multicall, bypassing the
   borrow<loan check" (a real-looking gap); O(C x R) gas DoS; an RP can brick subscribed
   users' market orders (borrowAPR >= lendAPR). -> matching/precedence/DoS/self-arb bugs.
2. **Authorization / delegation (v1.7 `setAuthorization`).** Long risk list (deposit/withdraw/
   sellCredit/setVault on behalf of). -> scope-confusion: does an authorized action stay
   within intended bounds? can an operator exceed granted scope, or persist after revoke?
3. **Custom vaults / ERC4626 adapters (v1.8 NonTransferrableRebasingTokenVault).** dust shares,
   `SUM(balanceOf) <= totalSupply` (NOT ==), per-vault isolation, adapter strategy pattern. ->
   accounting/rounding/donation, cross-vault contamination, share/asset drift.
4. **Oracle adapters (src/oracle/v1.5.1 .. v1.8 + TWAP fallback).** version drift; the
   "find the consumer + can upstream freeze?" lesson; TWAP manipulation window.
5. **Liquidation math** (liquidate / selfLiquidate / compensate / liquidateWithReplacement) —
   rounding direction, CR edges, partial liquidations, the "1 wei dust" multicall note.

## Core invariants to fuzz (Phase 3)
- Solvency: `SUM(balanceOf) <= totalSupply()` (vault); protocol assets >= liabilities.
- Debt: every open debt position stays collateralized per its CR (or is liquidatable).
- Accounting: credit/debt conservation across match/compensate/liquidate.
- Extend their `test/invariants/PropertiesSpecifications.sol` (don't repeat what's covered).

## Build / tooling notes
- deps in `lib/` (submodules: OZ, solady, solmate, aave-v3-core, chainlink, uniswap v3-core/
  periphery, pendle, ERC-7540, chimera, properties, halmos). `forge build` needs them populated.
- Fuzzers present: `echidna.yaml`, `medusa.json`, `medusa-differential.json`, Halmos, Slither.
- `deprecated/` = out of scope. `audits/` = read for the known-issues baseline.

## Known-issues baseline (from audits — OUT OF SCOPE, do NOT re-find)
Most relevant = **Cantina 2025-06-14 (v1.8-rc)** — it audited EXACTLY our focus areas:
- **[Crit] 3.1.1** `setVault` no-op on zero balance in `_transferFrom` -> asset theft: with
  `sharesOf>0 & balanceOf==0`, shares get "copied" to a higher-share-price vault. (NonTransferrableRebasingTokenVault)
- **[High] 3.2.1** AaveAdapter precision loss -> withdraw reverts + cross-vault transfer DoS.
- [Med] 3.3.2 **ERC4626 vault reentrancy** can drain protocol liquidity. 3.3.3 removed/compromised
  vault locks users out. 3.3.4 wrong borrow-APR validation in **LiquidateWithReplacement**.
  3.3.5 can't migrate from ERC4626 vault w/ fees/slippage.
- [Low] 3.4.1 wrong `totalSupply` in ERC4626Adapter; 3.4.2 adapter `balanceOf` wrong for
  mismatched vaults; 3.4.3 arbitrageable APR in **CopyLimitOrders**; 3.4.4 SetUserConfiguration event/state mismatch.
- [Info] 3.5.2 a rate provider can block subscribers' market ops; 3.5.3 vaultDust stuck.
- **Omniscia 2025-06-23** (adapters): AAR/ERC/NTR Minors (underlying-token correlation, liquidity
  eval, adapter-ID 1:1 breach, insecure adapter removal) — addressed.
- **Hashlock 2025-06-23**: [M-01] ERC4626Adapter#withdraw unlimited allowance window; [M-02]
  fullWithdraw share-redemption block; [L-01] setVault forfeitOldShares.
- README known-limitations: oracle-wrong-price -> state unguaranteed; trusted roles; no rebasing/FoT.
- (2024 audits v1.0-1.5: superseded by the above; read on-demand via `toolkit/pdftext.py`.)

## STRATEGY REFINEMENT (after reading audits)
The periphery we targeted was **heavily scrubbed in June 2025** (Cantina/Omniscia/Hashlock
found a Crit + High + many Meds, all fixed). So the freshest, least-audited surface =
**the DRIFT SINCE those audits**: v1.8.1 -> arbitrum deploy -> `b7714a2` ("batch shutdown
script"). Sharpened Phase-2 plan:
1. **`diffscan b7714a2` vs the ~June-2025 audited commit** — new/changed code there is virtually un-audited.
2. **Verify the Crit/High FIXES are complete** (incomplete-fix bugs are classic) — esp. the
   `_transferFrom` zero-value no-op + setVault: are ALL shares/balance-divergence paths closed?
3. **Hunt SIBLINGS of the known bugs**: other adapter-accounting (`balanceOf`/`totalSupply`)
   paths, other reentrancy entrypoints, other `sharesOf` vs `balanceOf` mismatches.
4. Understand the "batch shutdown" mechanism (new, named in the in-scope commit).

## Phase tracker
- [x] **Phase 0 — scope & setup**: scope locked, repos cloned, structure mapped, **aligned to b7714a2**,
      **audits read -> known-issues baseline** (above).
  - [ ] remaining: `forge build` + run their test/Echidna suite (needed for Phase 3 PoCs).
- [ ] **Phase 1 — map the machine**: architecture + roles + money-flow + invariant list (vault note).
- [ ] **Phase 2 — hunt the periphery**: read every fn in the 5 focus areas; recon/diffscan; hypotheses.
- [ ] **Phase 3 — prove/kill**: PoCs + invariant fuzzing on top hypotheses.
- [ ] **Phase 4 — disclose/record**: confirmed -> Cantina; FP/known -> ledger + lesson.

## Triage log — Phase 2 (vault / adapter / authorization / shutdown)
**Verdict: these subsystems are SOUND at b7714a2.** Deep-read, traced, not assumed.

| Area | What was verified | Verdict |
|---|---|---|
| **setVault** (home of the audit Critical) | now does a REAL `fullWithdraw`(old)->`deposit`(new) migration, or `forfeit` (`_setSharesOf 0`); no longer copies `vaultOf` on a no-op transfer | **fix complete** |
| **ERC4626Adapter** accounting | every fn moves `sharesOf[user]` by exactly the ERC4626 shares minted/burned; `SUM(sharesOf)==vault.balanceOf(tokenVault)`; `SUM(balanceOf)<=totalSupply` via round-down `convertToAssets` | **solvent/correct** |
| **AaveAdapter** accounting | Aave scaled-balance; double-round-down => dust favors the protocol; `fullWithdraw` sidesteps the precision-DoS (High 3.2.1) by zeroing shares without the revert-check | **solvent/correct** |
| **reentrancy** (Med 3.3.2) | adapters are `onlyOwner`(=tokenVault); all tokenVault fns `nonReentrant` (+ `nonReentrantView` on balanceOf/totalSupply) | **blocked** |
| **trust boundary** vault<->adapter | `setSharesOf`/`requestApprove` = `onlyAdapter`; `requestAaveWithdraw` = `onlyAdapterId(AAVE)` | **gated** |
| **OnBehalfOf delegation** (Size:420/443/460) | `validateX` checks `sizeFactory.isAuthorized(msg.sender, onBehalfOf, Action.X)` per action | **FP (FREI-PI auth)** |
| **marketShutdown** (freshest, post-audit) | no-op validation BUT `onlyRoleOrSizeFactoryHasRole(DEFAULT_ADMIN_ROLE)`; admin emergency wind-down | **admin-gated, sound** |
| `transferFrom` unchecked return (vault:227) | `IAdapter.transferFrom` returns void -> nothing to check | **FP (det_unchecked L1 limit)** |

**No novel bug in these areas.** 11 audits + Echidna/Medusa/Halmos/Slither hammered exactly
here, and the post-audit drift fixes hold. Deep value = full understanding of the vault/adapter
accounting + verified-complete Critical fix.

### Frontier (not yet deep-read — next session)
- **copy-trading / collections MATCHING engine** (focus #1) — most complex; audit found the most
  Low/Info here (3.4.3 arbitrage APR, 3.5.2 RP-DoS). Highest remaining EV, intricate.
- liquidation math (Liquidate / LiquidateWithReplacement / compensate); oracle adapters v1.5.1..v1.8.
