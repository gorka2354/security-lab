# Bridge / cross-chain sector — hunt playbook (2026-06-26)

**Tier:** mixed, but skewed T2/T3. A FEW classes are T0/T1 regex-catchable (unprotected init, arbitrary-call,
decimals-mismatch); MOST of the value lives where a single-file regex is BLIND — proof/signature verification,
cross-chain replay, the trusted set, and **off-chain key custody** (Taiko's leaked SGX key). Bridges reward a
playbook + invariants + our trust-anchor/secrets lanes over regex density.
**Why a sector note:** bridges are the single largest loss category in crypto — **>$2.8B**: Ronin $624M,
BNB Bridge $586M, Wormhole $326M, Multichain $231M, Nomad $190M, Harmony $100M, Orbit $80M, Taiko $1.7M (2026).
Recurring, well-shaped classes -> high EV IF you read the right layer.

## 1. Bug taxonomy — the recurring classes ($ + where the bug lives)
- **A. Message / proof verification (#1 class).** The verifier accepts a forged message. Shapes: a Merkle root
  that defaults to 0/`true` so any proof passes (**Nomad $190M** -> our `det_mapping_default`); a signature
  check that can be bypassed / a stale guardian set (**Wormhole $326M**, deprecated verify path on an
  uninitialized impl); IAVL/light-client proof forgery (**BNB $586M**); a leaked signer/enclave key forging
  attestations (**Taiko $1.7M** -> `det_trust_anchor` + `secrets.py`). Mostly T2/T3 (read the verifier).
- **B. Replay / chain-id confusion.** A signed message valid on chain X replayed on Y (no chainId in the signed
  payload, or a cached EIP-712 domain separator -> our `det_domain`); the same deposit proof claimed twice (no
  spent-nonce/leaf marker). T2 (cross-chain; needs 2-chain reasoning).
- **C. Mint-authority on destination.** The destination `mint()` isn't bound to a *verified, unspent* message
  -> infinite mint / mint without a matching lock. The lock==mint invariant breaks. T3.
- **D. Arbitrary-call / caller-supplied authority (aggregators).** The router does `target.call(data)` with
  caller-controlled target+data -> route to `token.transferFrom(victim,...)` and drain approvals (**Li.Fi /
  Socket ~$600k+**) -> our `det_arbcall` + `det_caller_supplied_authority`. T1 lead -> T3 confirm.
- **E. Token-semantics mismatch.** Lock X but credit the requested amount (fee-on-transfer/deflationary ->
  over-credit, our `det_feeontransfer`); decimals scaling on a non-18 token (the ZKFair gas-token `/= factor`
  we read — lone division, dust/round-trip); rebasing tokens breaking the lock accounting. T2/T3.
- **F. Trusted set / relayer / key custody.** M-of-N guardian/validator set with a weak threshold or a single
  relayer (**Ronin $624M** — 5/9 keys, the attacker got 5 via opsec); a single off-chain signer/enclave key
  (Taiko). The on-chain smell (single anchor / low quorum) -> `det_trust_anchor`; the off-chain leak ->
  `secrets.py`. Both layers needed.
- **G. Init / upgrade.** Unprotected `initialize` on the bridge proxy (front-run / re-init -> seize) -> our
  `det_unprotected_init`; an uninitialized/`selfdestruct`-able implementation behind the proxy (Wormhole-uninit
  class) -> `det_upgrade` / `det_danger`. T0/T1.
- **H. Liquidity accounting / finalization / reentrancy.** Withdraw before finality / optimistic-window gamed;
  reentrancy on the release path double-spends a deposit (`det_reentrancy`/`det_flashloan`); lock-and-mint vs
  burn-and-release invariant drift. T2/T3.

## 2. Our engine — COVERED vs GAP (honest)
- **Covered (lead-tier):** A-Nomad (`det_mapping_default`), A-Taiko + F (`det_trust_anchor` + `secrets.py`),
  B-replay smell (`det_domain`), D (`det_arbcall` + `det_caller_supplied_authority`), E-FoT (`det_feeontransfer`),
  G (`det_unprotected_init` + `det_upgrade`), H-reentrancy (`det_reentrancy`/`det_flashloan`).
- **GAP — detector or L4/invariant (where regex is BLIND):**
  - **C mint-authority:** a destination `mint`/`_credit` not gated on a *verified, unspent message id* ->
    candidate `det_bridge_mint` (mint reachable without a `require(verified[msgId] && !spent[msgId])`); but the
    real proof is cross-file -> mostly L4/invariant.
  - **B double-claim:** a deposit/withdrawal leaf/nonce consumed without a spent-marker write (cousin of
    `det_reward`'s late-marker; extend to bridge claim paths).
  - **E decimals-scale: DONE — `det_decimal_scale` (#41).** The lone `*=`/`/=` a decimals-diff factor that
    `det_precision` misses (not divide-before-multiply). Validated on the real ZKFair bridge (flags both
    `leafAmount /= gasTokenDecimalDiffFactor` L253 + `*=` L262).
  - **A proof-verification depth:** Merkle/light-client/zk proof soundness is NOT regex-able -> pure L4 read +
    the invariant below. (zk-SNARK verifier != leakable-key class — see `det_trust_anchor` SNARK gate.)

## 3. Invariants to fuzz (bridges are invariant-shaped — this is the real depth)
- **conservation:** total locked on source == total minted on destination, always (mint only against a
  verified+unspent message; release only against a burn).
- **no replay:** a given (messageId / depositNonce / leaf) can finalize AT MOST once, on the intended chain.
- **proof soundness:** a message NOT in the source's committed root cannot be claimed (forge a non-member ->
  must revert). Default/empty-root must reject, never accept (the Nomad invariant).
- **authority bound:** every state-moving message is signed/proved by the *current* trusted set above the
  threshold; a single key (leaked) cannot finalize (the quorum invariant — Taiko/Ronin).

## 4. Sourcing fresh bridge targets
- `scout.py --source defillama` then filter category **Bridge / Cross Chain** (or names: bridge/portal/
  teleport/relay/gateway/messenger). Resolve the CORE (the messenger/verifier), not the wrapped token.
- New L2s ship a canonical bridge (CDK/OP-Stack/Orbit forks) -> `forkdrift` vs the canon, hunt the DRIFT
  (the gas-token / decimals / DA mods, like ZKFair). `legacy.py` for deprecated bridge contracts still funded.
- LayerZero/CCIP/Hyperlane/Axelar INTEGRATIONS (the app's `_lzReceive`/`_ccipReceive` handler) are richer than
  the audited messaging core -> hunt the integration's source/authority checks, not the protocol.

## 5. Hunt lens (apply to any bridge/messenger target)
1. **What is the root of trust for a message?** A proof against a committed root, or a signer set, or one key?
   -> is the default/empty case rejected (Nomad)? is the set above-threshold and the key un-leakable (Taiko)?
2. **Is every claim replay-safe?** chainId in the signed payload; a spent-marker per messageId/leaf/nonce.
3. **Is mint bound to a verified+unspent message?** lock==mint conservation; can you mint without a lock?
4. **Token semantics:** FoT/rebase/decimals — does credited == actually received/locked?
5. **The router:** any `target.call(data)` with caller-controlled target -> approval-drain (`det_arbcall`).
6. **Off-chain layer (don't skip — Taiko):** run `secrets.py` over the repo+history; who/what is the relayer/
   sequencer/guardian, and what happens if its key leaks?
