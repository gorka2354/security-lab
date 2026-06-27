# June 2026 hack study — coverage map (self-improvement loop)

Studied 3 recent (June 2026) EVM hacks; checked each against our 44 detectors.

| Hack | Date | Loss | Root-cause pattern | Coverage |
|---|---|---|---|---|
| **Lixir Finance** (permit drain) | Jun 2026 | ~$12k multi-token | `permit` checked `ecrecover != address(0)` but NEVER `== owner` -> any well-formed sig recovering to a nonzero addr forges any holder's allowance | **GAP -> NEW** `det_signature` sub-check 1b (ecrecover result not bound to owner/signer) |
| **Little Boy Plus (LBP)** | Jun 17 2026 | 610 BNB | flashloan stages LP credit -> `LBPHashrate` reward accounting reads spot AMM/LP -> inflates the VIRTUAL `balanceOf = raw + pendingRewards` -> sell | **COVERED** by `det_spot_oracle` (fires LBPHashrate.sol:448,:870 — spot-fed reward valuation, no TWAP, flashloan-manip) |
| **Taiko Bridge** | Jun 21-22 2026 | ~$1.7M | forged SGX proof registers a malicious prover; single trust anchor, no quorum/revocation | **COVERED** by `det_trust_anchor` (built from exactly this Taiko/Raiko 2026 class) |

## Takeaways
- The engine is current: 2 of 3 fresh hacks were already caught by existing detectors (`det_spot_oracle` = the #1
  DeFiHackLabs class; `det_trust_anchor`). 1 gap (Lixir) -> closed with a precise, FP-tuned sub-check.
- **New sub-pattern added:** `det_signature` 1b — raw `ecrecover` + `address(0)` guard but no `== owner/signer`
  binding = forgeable auth. det_signature previously treated an address(0) check as "guarded" and missed it.
- Residual (noted, not built): LBP's `balanceOf = raw + pendingRewards` (a token whose reported balance exceeds
  its minted backing) is a distinct "virtual-balanceOf" tell; det_spot_oracle already catches the root
  (manipulable source), so a dedicated detector is low-priority.

PoCs: DeFiHackLabs src/test/2026-06/{LixirPermitDrain,LBP}_exp.sol (cloned to hunts/_volume/dfhl-2026-06/).
