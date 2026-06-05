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

## Phase tracker
- [x] **Phase 0 — scope & setup**: scope locked (Cantina), both repos cloned, structure mapped, HUNT.md.
  - [ ] remaining: align to commit b7714a2; `forge build` + run their test/Echidna suite; read audits/ -> known-issues list.
- [ ] **Phase 1 — map the machine**: architecture + roles + money-flow + invariant list (vault note).
- [ ] **Phase 2 — hunt the periphery**: read every fn in the 5 focus areas; recon/diffscan; hypotheses.
- [ ] **Phase 3 — prove/kill**: PoCs + invariant fuzzing on top hypotheses.
- [ ] **Phase 4 — disclose/record**: confirmed -> Cantina; FP/known -> ledger + lesson.

## Triage log
_(verdicts go here as we work — every lead, FP or real, with why)_
