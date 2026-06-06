# HEAD-TO-TOE HUNT: Malda (malda-protocol/malda-lending)

Chosen by deep-research for the ideal profile: **less-known + ~9 months of POST-AUDIT
commits** (max unverified code), tractable, novel architecture. Clone (gitignored)
`hunts/_volume/malda`. Alternative on deck: **Cap** (`cap-labs-dev/cap-contracts`, 195 .sol).

## Why this target
- **Post-audit drift (the key criterion):** audited by Veridise (Jan-Mar 2025) + Sherlock
  (2025-07); HEAD = 2026-04 with commits every month 2025-10..2026-04. ~9 months of code the
  audits never saw. (Search even noted post-audit PR fixes to EverclearBridge.)
- **Tractable:** 163 entry points / 31 files (vs Aavegotchi's 263). A full sweep is feasible.
- **Novel + our wheelhouse:** Compound-fork lending + CROSS-CHAIN (bridges Across/CCTP, a zk
  sequencer delivering proofs) -> bridge/messaging bug classes we know + zk-verification (fresh).
- Multiple audits -> a solid known-issues baseline (`audit/` folder).

## Architecture (from scope.py map)
- **Compound fork:** `Operator/Operator.sol` (=Comptroller, 25 fns), `mToken/*` (=cTokens:
  mErc20, mToken, mTokenConfiguration). Known classes: comptroller checks, interest accrual,
  liquidation, oracle, first-depositor/empty-market, cToken reentrancy.
- **Cross-chain (the fresh surface):** `mToken/host/mErc20Host.sol` (15), `mToken/extension/
  mTokenGateway.sol` (16) - cross-chain deposits/borrows reconciled via zk-proof + a SEQUENCER;
  `rebalancer/Rebalancer.sol` (14) + bridges `AcrossBridge`, `CCTPBridge`.
- **Oracle:** `MixedPriceOracleV3` AND `V4` (versioned -> V4 is post-V3 drift). Chainlink-style.
- Roles: onlyAdmin / onlyRebalancer / onlyOperator / onlySpokePool / onlyFirewall* / onlyMigrator.

## Coverage-driven plan (head-to-toe)
- [x] **scope.py map**: 163 entry points / 31 files -> `Coverage: 0/163` (the checklist).
- [ ] **Known-issues baseline:** read `audit/` (Veridise + Sherlock) via `toolkit/pdftext.py`.
- [ ] **diffscan the drift:** diff HEAD vs the ~2025-07 audited commit -> the post-audit code is
      the priority (unverified). Deepen the clone first.
- [ ] **Sweep every entry point** (163), prioritized: post-audit-drift first, then cross-chain/
      bridge/oracle-V4/sequencer-trust, then the Compound core. Verdict each -> ledger -> 100%.
- [ ] **Fuzz the core invariants** (solvency: total borrows <= total collateral value; supply/
      exchange-rate; cross-chain accounting) once a build is stood up.

## Focus hypotheses (where post-audit + novel = highest EV)
1. **Cross-chain accounting** (`mErc20Host`/`mTokenGateway` + sequencer): does a cross-chain
   deposit/borrow reconcile EXACTLY? can a proof be replayed / a message double-spent / the
   sequencer-trust be abused? (the zk + bridge surface the audits had least time on).
2. **Bridge rebalancer** (Across/CCTP): arbitrary-call / fund-routing on the rebalance path?
3. **Oracle V4** (the newer version): the 3-guard checklist (staleness/price>0/decimals) +
   any divergence from V3 that the V3 audit wouldn't cover.
4. **Compound-fork classics** on the post-audit diff: liquidation/interest/comptroller changes.

## Triage log
_(verdicts as we sweep - every entry point, FP or real, with why)_
