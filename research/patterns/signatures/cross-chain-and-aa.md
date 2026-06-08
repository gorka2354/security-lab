# Pattern 06 — Cross-chain replay & account-abstraction footguns

**Tier:** T1/T2 — several pieces ARE regex-catchable (cached domain separator, `extcodesize`-as-EOA, `ecrecover` with no
nonce); whether a signature actually *replays* is light cross-state reasoning.
**One line:** a signed message is **valid in a context the signer didn't intend** — replayed on another chain (mutable
`chainId` in the domain separator), reused (missing nonce/deadline), or rejected/forged because the code assumes
**EOAs only** on an account-abstraction chain (`extcodesize`, raw `ecrecover` without EIP-1271).

## 1. Mechanism
1. **Mutable-chainId domain separator** — `DOMAIN_SEPARATOR` is cached in the constructor with `block.chainid`. After a
   fork (or on a sibling deployment) the real `chainid` differs but the cached separator doesn't → signatures replay
   across chains. (OZ EIP-712 recomputes when `block.chainid` changed — forks that hard-code it lose this.)
2. **Missing nonce / deadline** — a signed action with no consumed nonce or no expiry → replay on the *same* chain.
3. **`extcodesize`/`.code.length` as an "is-EOA" gate** — on zkSync Era (and any AA chain) **smart-contract wallets are
   the norm**; the check wrongly rejects them, or (during constructor, size==0) wrongly treats a contract as an EOA.
4. **Raw `ecrecover` only** — rejects valid **EIP-1271 contract signatures** (AA wallets sign via `isValidSignature`), or
   accepts a malleable/`address(0)` recovery if the result isn't checked.

## 2. Real examples
- **zkMarkets (first-hand) — mutable-chainId domain separator.** The EIP-712 separator path didn't re-bind to the live
  `chainid`, opening cross-chain replay of signed orders. (Studied as the canonical case for this class.)
- **zkSync Era footguns (first-hand, `det_l2_footgun`):** `extcodesize`-as-EOA and `ecrecover`-only signature checks
  break under native AA — wallets are contracts, so EOA assumptions and ecrecover-only verification are unsafe.
- **Class at large:** the post-fork (ETH/ETC, every L2 fork) replay of cached-separator permits is a recurring incident.

## 3. The "tell"
- Grep `DOMAIN_SEPARATOR`, `_domainSeparatorV4`, `keccak256(abi.encode(...EIP712Domain...))` → is `block.chainid` **read
  live / re-checked**, or cached once in the constructor?
- Grep every `ecrecover(` → is there a **nonce consumed**, a **deadline checked**, a **`signer != address(0)`** guard, and
  an **EIP-1271 fallback** for contract signers?
- Grep `extcodesize`, `.code.length`, custom `isContract` used as an **auth/EOA gate** (`det_l2_footgun` already flags these).
- **The $-question:** *is this signature bound to (this chain, this nonce, this deadline), and can a contract wallet
  produce/consume it?* Any "no" → lead.

## 4. Detector idea (static, T0/T1) — det_sig (+ existing det_l2_footgun)
- **det_l2_footgun (have it):** flags `extcodesize`/`.code.length`/custom `isContract` — keep as the AA-EOA tell.
- **det_sig (new):** flag (a) a `DOMAIN_SEPARATOR` assigned in a `constructor`/`immutable` with `block.chainid` and **no
  `block.chainid`-changed recompute path**; (b) an `ecrecover` whose function has **no `nonce`/`deadline`** in scope.
  Emit as leads. T1.
- **Honest limit:** "does it actually replay" depends on whether the same contract/signer exists on another chain → T2
  context. Regex finds the *unsafe construction*, not the live cross-chain twin.

## 5. Hypothesis / invariant (T2/T3)
- **Hypothesis:** "for each signed action — is it bound to chain + nonce + deadline, and is the signer model EOA-only on
  an AA chain?" Enumerate every `ecrecover`/`isValidSignature` site.
- **Invariants:**
  - **No cross-chain replay:** a signature valid under chainId A is **invalid** under chainId B (fuzz by recomputing the
    digest with a different `block.chainid` and asserting rejection).
  - **No reuse:** a consumed nonce makes the same signature revert on second use.
  - **AA-compatible:** a contract wallet's EIP-1271 signature is accepted where an EOA's would be.

## 6. Mitigations to RECOGNIZE (avoid FP)
- **OZ `EIP712`** (recomputes the separator when `block.chainid` changes) — if you see `_domainSeparatorV4()` with the
  cached-vs-live `chainid` branch, the replay lead is dead.
- **Nonce + deadline** in the signed struct, nonce consumed on use.
- **EIP-1271 fallback** (`SignatureChecker.isValidSignatureNow`) alongside `ecrecover`, and `signer != address(0)` checked.
- **No `extcodesize`-as-EOA** — on AA chains the code uses signature-based auth, not code-size heuristics.
