# Taiko bridge exploit — leaked SGX key (studied 2026-06-24)

**Incident:** 2026-06-22, Taiko (Ethereum L2). ~$1.7M drained from the ERC20 bridge vault via forged
withdrawals; Taiko halted block production; TAIKO token -20%+. Class = forged cross-chain proofs
(>$340M of bridge hacks in 2026 share it).

**Root cause (BlockSec):** the SGX enclave signing key (`enclave-key.pem`, RSA-3072) for **Raiko**
(Taiko's multi-prover stack) was committed to the PUBLIC repo `taikoxyz/raiko`. With the leaked key an
attacker generated a valid SGX attestation, registered a malicious prover instance as "legitimate" on L1,
signed fraudulent L2 state attestations, and the on-chain verifier accepted forged bridge messages -> fake
withdrawals on Ethereum with no matching `MessageSent` event on L2.

## Two layers (the whole lesson is here)
| Layer | What | Where it lives | In our scope? |
|---|---|---|---|
| **A. Opsec / repo hygiene** | `enclave-key.pem` in public git | git history of `taikoxyz/raiko` (OFF-CHAIN) | **No** — no secret scanner in toolkit |
| **B. On-chain trust-model** | `SgxVerifier`-style: accepts a proof from ANY instance whose SGX measurement == a stored `MrSigner`; root of trust = ONE key; no threshold/quorum/revocation bounding blast radius | L1 contract (ON-CHAIN) | **Partly** — L4 trust read, not recon |

Leak (A) is catastrophic ONLY because contract (B) anchored all verification on a single key with no
quorum. Remove either layer and there is no exploit.

## Could OUR engine have caught it? — honest verdict
- **Layer A (leaked .pem): NO.** Grepped all of `toolkit/` — no secret/entropy/git-history scan, no
  `.pem`/`BEGIN PRIVATE KEY`/keystore/mnemonic detector. Out of scope by design (we are a source-logic
  hunter, not gitleaks). A clean miss today.
- **Layer B (on-chain trust anchor): NOT by detectors, but by L4 read = YES, as a hypothesis.**
  - `recon.py` (38 detectors) would NOT flag it: there is no detector for "verifier trusts a single
    configurable signer/measurement with no quorum." `det_signature` (ecrecover) / `det_access` are
    adjacent but not this.
  - Phase 4 L4-READ, **Spec-Auditor + Attacker** mindset, asks the right question: *"what is the root of
    trust for this proof, and what happens if that key leaks?"* -> surfaces the hypothesis. T3 trust-model
    bug; reasoning finds it, not regex.
  - LIVE-FIRST / activity gate would PASS (live bridge, high TVL) -> it would reach the deep read.

### The hypothesis the engine SHOULD have produced
> `SgxVerifier` accepts any prover instance whose SGX measurement == the stored `MrSigner`. Root of trust =
> one signing key. If that key is ever exposed (repo, CI, backup) an attacker forges a valid attestation ->
> registers a malicious instance -> signs arbitrary state roots -> the bridge accepts forged withdrawals.
> No on-chain threshold / multi-prover quorum / revocation bounds the blast radius.
> WHO: anyone holding the key. WHAT: forged withdrawal. HOW MUCH: the whole vault (~$1.7M realized).

## Engine upgrades (turn this miss into detectors — the self-improvement loop)
1. **`secrets` lane — DONE (`toolkit/secrets.py`, wired into Phase 1 REACH).** Pure-python (no dep; folds in
   gitleaks if present). Scans the working tree AND **git history** (`git log -G<prefilter>` so git only emits
   matching commits — cheap on a monorepo). Triggers: PEM private-key blocks, `*.pem/.key/.p12`, `enclave-key`,
   keystore JSON, AWS keys, secret-assigned literals, hex-key-near-context. Verified: catches a key committed
   then **removed from HEAD** (the Taiko scenario). Calibrations from real code: skip `*.example/sample/template`
   (the Anvil test key in `taiko-mono/.env.example` was a FP); skip env-indirection/placeholders; a bare bytes32
   hash with no key-context is not a key. NOTE: needs a FULL clone (`--depth 1` has no history).
2. **New pattern `off-chain trust anchor`** (see `patterns/trust-anchor/off-chain-signer-authority.md`):
   for ANY verifier (SGX / zk / oracle / multisig) the L4 read MUST ask — single root key? threshold/
   quorum? revocation? rotation? `det` idea: flag a verifier contract with one configurable signer/
   measurement and no quorum.
3. Wire it to existing `det_signature` + the centralization read.

## Validation (2026-06-24) — det_trust_anchor vs the REAL taiko-mono
Implemented `det_trust_anchor` (recon #39) and ran it on the actual `taikoxyz/taiko-mono`
(`packages/protocol/contracts/layer1/verifiers/`), not just our fixture:
- **It fires on the real `SgxVerifier.sol`: 4 `[!]` leads — on `registerInstance` (L113) and `verifyProof`
  (L127), the exact functions the attacker abused**, plus `addInstances`/`_addInstances`.
- **Precision:** across all 8 layer1 verifiers (Risc0 / SP1 / Compose / SgxAndZk / AnyTwo / Any / IProof /
  Sgx) it produced **4 leads total, ALL in SgxVerifier.sol** — 0 on the ZK verifiers and the M-of-N compose
  verifiers. The quorum-suppression + anchor-vocabulary scoping holds on real code.
- **Calibration lesson the real code taught us:** Taiko HAD an on-chain revocation path (`deleteInstances`)
  and was drained anyway. So revocation must NOT downgrade severity — a reactive revoke can't stop a forged
  registration before an operator notices. Only an M-of-N **quorum** (absent) bounds a leaked key. Detector
  now stays `[!]` whenever quorum is missing, regardless of revocation (revocation only annotates the note).

## Sources
- thirdweb blog — Taiko Bridge Exploit explained
- spotedcrypto / cryptotimes / coindesk / nftplazas — $1.7M, SGX key leak, June 2026
