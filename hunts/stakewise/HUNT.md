# HUNT: stakewise (stakewise/v3-core) — liquid staking ETH/GNO, osToken CDP

Top-ranked by the volume engine (score 123). Open-source, **Immunefi in-scope**
($100k+). Clone in gitignored `hunts/_volume/stakewise` (this note is the record).

osToken = an over-collateralized token (like osETH) minted against vault shares;
the Keeper is an oracle-quorum that signs reward roots & validator data.

## Triage log — verdict: CLEAN (all high-signal leads by-design)

| Lead | Detector | Verdict | Why (verified by reading) |
|---|---|---|---|
| `updateStateAndDepositAndMintOsToken` ×4 (Eth*Vault) | supply | **FP** | thin public wrapper -> `VaultOsToken._mintOsToken`; mint is **LTV-bounded**: after mint `if (userMaxOsTokenShares < position.shares) revert LowLtv()`, and `_checkOsTokenPosition` re-checks LTV when collateral leaves (exit queue / donate). Proper over-collateralized CDP. |
| `PriceFeed.sol` `latestAnswer` / `latestRoundData` | oracle | **FP** | derived feed = `osTokenVaultController.convertToAssets(1e18)` — a **pure on-chain osToken/ETH rate**, NOT a Chainlink feed. Stamping `block.timestamp` is correct (no upstream to freeze); `price>0` guaranteed (osToken only accrues). Same class as the stakelink underlying adapter (closed yesterday). |
| `KeeperRewards.updateRewards` | sibling/access | **FP** | public submit, but gated by `_verifySignatures(rewardsMinOracles, keccak256(root,nonce,…), sigs)` + nonce (anti-replay) + `canUpdateRewards()` rate-limit + `avgRewardPerSecond <= _maxAvgRewardPerSecond` (anti-inflation). |
| `KeeperValidators.updateExitSignatures` / `registerValidators` | sibling/access | **FP** | same: `_verifySignatures(validatorsMinOracles,…,nonce,deadline)` + deadline + vault-registry check. |
| reentrancy: vault `deposit` / `createVault` / `donateAssets` | reentrancy | **likely FP** (not deep-verified) | trusted-asset (WETH/GNO) deposit + factory patterns; consistent with the rest. Lower priority; noted not closed. |

**Pattern:** stakewise — like stakelink/Infrared/YO — is a mature, audited protocol
where every high-signal lead is by-design: signature-gated keepers, LTV-bounded CDP
mint, on-chain rate feeds, self-scoped public functions. **No bug.** Realistic and
expected for audited, in-scope code. The transferred oracle lesson (find the upstream:
freezable Chainlink vs pure on-chain rate?) closed the PriceFeed lead in seconds.

## Tool improvement triggered (11th precision fix)
The Keeper functions are gated by `_verifySignatures` ~line 93 — DEEPER than the old
280-char inline-auth body-peek, so they flagged as ungated (FP). Fix: `det_access` /
`det_sibling` now scan the FULL function body for strong inline auth (signature
verification, role/owner checks, msg.sender comparison) via a shared `INLINE_AUTH`
regex, while keeping a bare-`msg.sender` check in the top 280 chars (a guard lives
there; avoids masking a real ungated setter that only `emit`s msg.sender at the end).
Validated: keeper funcs now correctly suppressed, no regression (strictly more auth
suppressed than before).

## Not pursued further
No reportable issue. osToken CDP + Keeper are the trust-critical parts and both are
soundly gated. Ledger records the supply/oracle leads as `fp` so they won't resurface;
the keeper leads are now auto-suppressed by the detector fix (no ledger entry needed).
