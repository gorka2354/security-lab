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

## Next (if pursued as a real hunt)
- forkdrift.py diff ZKFair vs Polygon CDK canon -> hunt only the custom mods (the audited core is moot).
- Greenfield-ish, egor's edge: `zkfair-transaction-mining-contract` + `zkfair-staking-contracts`.
- Confirm a bounty exists before any disclosure.
