# HUNT — ZKFair (CDK zk-validium) — 2026-06-24

**Why:** first live test of the new trust-anchor + secrets lanes (Taiko/Raiko class) on a niche zk-L2.
**Scope status:** NO confirmed bug-bounty program found (org has `zkfair-audits`, not a bounty). Treated as a
LEARNING run — read public source + static detectors only; nothing live touched; no disclosure drafted.
**Verdict: CLEAN / KNOWN — no finding.** Value was in detector validation + two precision calibrations.

## Reach
- Org repos (reachable, github.com): `zkfair-cdk-validium-contracts` (L1, 31 .sol, 511 commits),
  `zkfair-transaction-mining-contract`, `zkfair-staking-contracts`, `zkfair-audits`.
- Cloned full (for secrets history): `hunts/_volume/zkfair-contracts`.

## Triage (Phase 2)
- It is a **fork of Polygon CDK-validium-contracts** (CDKValidium.sol / PolygonZkEVMBridge.sol /
  CDKDataCommittee.sol / FflonkVerifier.sol) — audited canon. Per the audited-fork rule, the verifier +
  trusted-aggregator core is intentional/known design; real EV would be in ZKFair's DRIFT vs canon (not run
  deeply here — this was a lane-validation pass, not a full audit).

## Detector results
- **det_trust_anchor:** 1 raw hit -> `verifiers/FflonkVerifier.sol:162 verifyProof`. **KILLED (FP, gate B/C).**
  FflonkVerifier is an auto-generated zk-SNARK verifier; its single key is the PUBLIC verifying key (trusted
  setup, toxic waste destroyed) — NOT a leakable signing key. A SNARK proof can't be forged by "leaking a
  key", unlike SGX. -> calibrated the detector to suppress pure zk-SNARK verifiers (SNARK tokens present +
  no TEE/signature tokens). Post-fix: 0 trust-anchor leads on ZKFair; real Taiko SgxVerifier still 4.
- **secrets:** 5 hits, all `test/test-vectors/helpers.json` (in git history, removed from HEAD). Sequential
  fake keys (...1234/...9876). **Downgraded (test-fixture path).** Proves the history-scan works on real code;
  no live leak. -> calibrated secrets to downgrade test/fixture/test-vector paths.

## Lessons -> engine (the self-improvement loop)
1. det_trust_anchor: **zk-SNARK verifier != TEE verifier** (public verifying key vs leakable signing key).
   Discriminator added; pattern §6 updated.
2. secrets: **test-vector / fixture key material is not a leak** — downgrade test paths (recon _TESTRE parallel).
Both shipped with regression tests (suite 368 passed).

## LIVE-FIRST / activity (asked: is there value at stake?)
- DefiLlama API (authoritative): chain TVL ~**$77.4k** now (~$89k 6mo ago) — slow decline, near-abandoned.
- Verdict: tiny value + NO confirmed bounty -> EV ~0 for a paid hunt. Methodology/learning pass only.

## Drift hunt — gas-token decimal scaling (the custom mod, Phase 4/5)
ZKFair's distinctive drift vs Polygon CDK: a non-18 ERC20 gas token (USDC 6dec) <-> L2 native (18dec) via
`gasTokenDecimalDiffFactor` (=1e12), added in `ecc10ef` to `PolygonZkEVMBridge.sol`.
- bridgeAsset (source-side): L1->L2 `leafAmount *= factor`; L2->L1 `leafAmount /= factor` + `==0 -> AmountTooSmall`.
- claimAsset (dest-side): uses the leaf `amount` AS-IS (`call{value: amount}` / mint) — NO re-scale.
- **VERDICT: no finding.** Round-trip is balanced (X USDC -> X*1e12 native -> X USDC); claim doesn't re-scale,
  so no over-withdraw / no locked!=minted break. Only leak = **dust truncation** on L2->L1 (< 1e12 wei native,
  <$1e-6) -> gate F (dust). Non-finding, and EV ~0 on a dead chain anyway.

## Engine-gap insights (the real value of this pass)
1. **recon has NO detector for decimal-scaling truncation** — `x /= decimalFactor` is a LONE division (not
   divide-before-multiply, so det_precision misses it) that loses dust and, in some bridge/wrapper shapes,
   can break a locked==minted invariant. Candidate: `det_decimal_scale` (flag `*=`/`/=` by a *DecimalDiff/
   decimals factor in a bridge/mint/claim path; ask the round-trip invariant). BACKLOG.
2. **forkdrift BASES lacks Polygon CDK** — `fingerprint` didn't recognize an obvious CDK fork (CDKValidium/
   PolygonZkEVMBridge/CDKDataCommittee/FflonkVerifier). Add a CDK signature to BASES. BACKLOG.

## Status: PARKED (dead chain, no bounty). Real value captured = 2 engine-gap backlog items above.
