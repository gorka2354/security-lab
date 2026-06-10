# HUNT: Mezo MUSD  (mezo-org/musd)

- **Date:** 2026-06-10
- **Source:** scout `--source defillama` (Mezo Borrow, CDP, TVL ~$6M, audits=0 per DefiLlama -> WRONG, see triage)
- **Repo:** https://github.com/mezo-org/musd  (`solidity/contracts/`, 71 .sol, Solidity 0.8.24, OZ-upgradeable)
- **What:** BTC-collateralized CDP stablecoin on the Mezo network. Based on **Threshold USD (a Liquity fork)**
  + Mezo additions: fixed-rate borrow interest, refinancing, PCV fee management, EIP-712 delegation.
- **Verdict:** **NO demonstrable finding.** Audited Liquity-derivative; the custom layer is well-built.
  1 recon precision fix (fix#33) + 1 fuzzing-residual recorded.

## Phase 0-1 SOURCE/REACH
Fresh-contest well dry (contest_monitor: only Morpho-Midnight + dreUSD live, both already hunted). DefiLlama
hits mostly closed-source/exotic-chain; Immunefi = blue-chips. Picked Mezo MUSD: fresh, deployed, our zone
(CDP/borrow/stablecoin), and a Liquity-lineage fork (good forkdrift test). CORE reachable via the public repo.

## Phase 2 TRIAGE  (forkdrift)
- `forkdrift fingerprint` -> **LIKELY FORK of Liquity** (6 sigs: trovemanager, borroweroperations,
  _redistributedebtandcoll, sortedtroves, _movependingtrovereward, getentiredebtandcoll). Confirmed by
  contract names (ActivePool/DefaultPool/GasPool/HintHelpers/LiquityBase/StabilityPool) + repo CLAUDE.md.
- **Audit status:** forkdrift said "no audit evidence -> greenfield". **WRONG** -- the audit lives in a SIBLING
  repo `mezo-org/audits` (`2025-04-15 - Cantina - mUSD.pdf`). **forkdrift blindspot: audit-evidence detection
  is repo-local; cross-repo org audit dirs aren't seen.** -> Re-routed as AUDITED: skip the Liquity core, hunt
  (1) the Mezo-custom DRIFT, (2) post-audit drift (repo lives to 2026-05, audit was 2025-04).
- **Custom DRIFT (the high-EV surface, not in vanilla Liquity):** InterestRateManager + InterestRateMath
  (borrow interest -- Liquity is interest-free!), BorrowerOperationsSignatures (EIP-712), GovernableVariables,
  PCV, MUSDSavingsRate.

## Phase 3 DETECT  (recon 22 dets + hypothesize)
77 leads. All [!] resolved to FP/by-design (below). hypothesize: round-trip pairs (open/close, add/remove,
deposit/withdraw) + the "accrue-before-param-change" invariant flagged on the interest mechanism. Their own
echidna suite declares 4 invariants incl `echidna_sum_of_debt`.

## Phase 4-5 L4 READ + VERIFY
- **InterestRateManager (custom interest)** -- `interestNumerator = SUM(principal*rate)`; `updateSystemInterest()`
  mints `elapsed*numerator/D` to PCV (simple interest). **accrue-before-change ordering respected**: every
  principal-change site (`_refinance` BO:1021, TroveManager touch paths) calls `updateSystemAndTroveInterest`
  FIRST, settling the old period at the old numerator. Refinance fee/principal/numerator accounting consistent
  (increaseTroveDebt adds fee to numerator at oldRate; oldPrincipal read post-fee -> removePrincipal removes
  exactly what was added). Permissionless `updateSystemInterest()` over-frequent-call rounding only loses DUST
  to the protocol (interest goes to PCV, not the caller) -> gate F, no economic gain. **Sound.**
- **BorrowerOperationsSignatures (EIP-712 delegation)** -- `_verifySignature`: deadline enforced (block.timestamp
  <= deadline), nonce consumed (`nonces[borrower]++`), signer==borrower, per-action TYPEHASH (no cross-action
  replay), OZ `EIP712Upgradeable` (recomputes domain separator on chainid -> no cross-chain replay), OZ `ECDSA`
  (malleability-safe). All funds-out paths (withdrawColl/withdrawMUSD/adjust/openTrove) BIND `recipient` in the
  signature + pass the SIGNED recipient (not msg.sender) + `properRecipient` blocks pool addresses. The
  `abi.encodePacked(typeHash, abi.encode(fixed-fields), nonce, deadline)` looks off but is equivalent to
  `abi.encode(...)` here (all middle fields fixed-size -> no packed-collision ambiguity). **Well-built.**
- **recon [!] FPs:** TroveManager x13 = Liquity inline `_requireCallerIsBorrowerOperations()` (recon missed it);
  BO:189 addColl = self-scoped user op; PCV:270 distributeMUSD = permissionless-by-design distribution;
  TM:646 = interest-accrual passthrough.

## Phase 7 RECORD
- **recon precision fix#33** (self-improvement loop): added `_?require\w*Caller\w*\s*\(` to `INLINE_AUTH` ->
  Liquity/Threshold `_requireCallerIs<X>()` inline caller-auth now recognized. Killed ~13 TroveManager FPs;
  genuinely-ungated setter still flagged (no over-suppression). +3 golden tests (215 total, green). Transfers to
  EVERY Liquity/Threshold fork.
- **Ledger:** 6 verdicts (5 fp/known + 1 todo).
- **Fuzzing-residual -> CHECKED LIVE (2026-06-10):** aggregate `mint-to-PCV` vs SUM(per-trove charged interest)
  reconciliation. Ran MUSD's own `echidna_sum_of_debt` (+ troves_order, trove_properties, BTC_balances) under
  **echidna 2.3.2 in the new WSL lane** -> **all 4 PASSING** at 30k tests (cov 65,727; compiled in 18.5s). A
  clean shallow run (their config is 500k) is a positive signal, not a proof; it strengthens the no-finding
  verdict. The WSL lane (toolkit/WSL-LANE.md) makes this re-runnable at full depth.
- **medusa 1.5.1** is installed + its engine runs (compiles MUSD via crytic-compile), but their `EchidnaTest`
  harness is **echidna-tuned** -> reverts on medusa's deploy model even with deployer/sender/balance matched.
  A harness-portability gap (not an engine bug) -- exactly the case `scaffold.py --engine chimera` solves
  (one portable harness + echidna.yaml + medusa.json for both engines).

## Lessons (-> engine)
1. **forkdrift audit-detection is repo-local** -- misses a sibling `<org>/audits` repo (Mezo, and likely others).
   Backlog: have forkdrift/scout check the org's `audits` repo before declaring "greenfield/under-reviewed".
2. **Liquity/Threshold `_requireCallerIs*`** is a recurring fork-CDP FP source -> fix#33 (done).
3. Re-confirms the standing diagnosis: reachable space is dominated by audited deploys; this was audited+clean.
