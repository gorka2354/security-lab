# Pattern — off-chain trust anchor (verifier trusts a single off-chain signer/measurement)

**Tier:** T3 (trust-model / business-logic). The *smell* is T1 (a verifier with one configurable signer),
but the *exploit* lives in the off-chain key custody + the missing on-chain quorum.
**One line:** a verifier accepts proofs from any party matching ONE configured key/measurement, so whoever
obtains that key (leak, CI, backup) forges valid proofs and the contract treats them as canonical.

## 1. Mechanism
- An on-chain verifier (`SgxVerifier`, zk verifier, oracle signer set, ERC-1271 signer, bridge attestor)
  trusts a single root: a stored `MrSigner`/`MrEnclave`, a verifying key, or one signer address.
- Registration/attestation accepts ANY instance whose measurement/signature matches that root. No threshold,
  no M-of-N quorum, no revocation, no key rotation bounding the blast radius.
- Off-chain, that root key sits in a repo / CI secret / backup. Exposure -> attacker forges a valid
  attestation -> registers a "legitimate" instance -> signs arbitrary state -> contract accepts it.
- Greppable: `MrSigner`, `MrEnclave`, `registerInstance`, `addInstances`, `verifyProof`, `attestation`,
  `trustedSigner`, `setVerifier`, single-`ecrecover` against one stored address.

## 2. Real examples
- **Taiko / Raiko, 2026-06-22, ~$1.7M (first-hand study).** `enclave-key.pem` committed to public
  `taikoxyz/raiko`; L1 trusted any enclave matching the stored `MrSigner` -> forged prover registration ->
  forged bridge withdrawals. See `research/taiko-sgx-keyleak-study.md`.
- General class: forged cross-chain proofs = >$340M of 2026 bridge hacks.

## 3. The "tell"
- Find every verifier/attestor: grep `verifyProof|attestation|MrSigner|MrEnclave|trustedSigner|registerInstance`.
- For each, ask the $-question: **"what is the single root of trust, and what is the blast radius if it
  leaks?"** Is there an M-of-N quorum? a revocation path? rotation? a timelock on changing the anchor?
- Pair it with the OFF-CHAIN check: is that key anywhere in the repo / git history / CI? (-> secrets lane).

## 4. Detector — det_trust_anchor (IMPLEMENTED, recon #39)
- Flags a verify/register/attest fn whose body touches a trust-anchor term (MrSigner/MrEnclave/enclave/
  attestation/sgx/trustedSigner-Key-Instance-Prover/verifyingKey/instanceId) when the file has NO quorum
  constant (threshold/quorum/signaturesRequired/minSigners/M-of-N). Quorum present -> suppressed.
- **Revocation does NOT downgrade** (the Taiko calibration): `deleteInstances` existed and the chain was
  still drained, because a reactive revoke can't stop a forged registration before it's noticed. Stays `[!]`
  whenever quorum is missing; revocation only annotates the note.
- Suppression gates read **comment-stripped code** so a stray `// TODO add quorum` can't hide a real bug.
- **Validated on real `taikoxyz/taiko-mono`:** 4 `[!]` on SgxVerifier (registerInstance/verifyProof = the
  exploited fns), 0 on the 7 sibling ZK/compose verifiers. **Honest limit:** a *lead*, not a verdict — T0
  can't see the off-chain key leak; pair with the secrets lane + the §3 custody question.

## 5. Hypothesis / invariant (T2/T3)
- **Hypothesis (hypothesize.py):** "this verifier's authority reduces to a single key/measurement with no
  quorum/revocation -> key exposure = full forgery. Where does that key live off-chain?"
- **Invariant to fuzz:** no single registered instance/signer can finalize a state root that moves vault
  value without an independent second prover agreeing (model M-of-N; assert a lone forged attestation is
  rejected).

## 6. Mitigations to RECOGNIZE (avoid FP)
- M-of-N multi-prover quorum (no single instance finalizes) — the ONLY real kill; lead is dead.
- Reactive revocation alone is NOT a kill (Taiko had `deleteInstances`, drained anyway) — it can't stop a
  forged registration before an operator notices. Downgrade only if revocation is paired with a quorum.
- Key never in repo (HSM / sealed enclave provisioning) — kills layer A; verify before assuming.
