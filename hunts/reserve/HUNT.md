# HUNT: reserve (reserve-protocol/protocol) — RToken (basket-backed stablecoins)

Ranked #1 of the 2026-06-07 fresh batch (score 405) — but that was a **false
outlier**. Two triage lessons, no bug. Open EVM, mature (multiple audits), in-scope.

## Why the score was inflated (both transferable)
1. **Dual implementation**: the repo ships `contracts/p0/` (Prototype-0 reference
   impl, NOT deployed) alongside `contracts/p1/` (production). Every contract is
   duplicated -> ~2x the leads. p0 is spec/test scaffolding; only p1 is real.
2. **Inline auth-helper not recognized**: Reserve gates governance setters with an
   inline call `requireGovernanceOnly();` (a `private governance {}` no-op, where
   `modifier governance { require(main.hasRole(OWNER, _msgSender())); }`), NOT an
   `onlyX` modifier on the function. The detector (regex L1) didn't see it -> all
   ~40 governance setters flagged as ungated. FP.

## Verified (read, not assumed)
- `BasketHandler.setPrimeBasket` -> `_setPrimeBasket` -> `requireGovernanceOnly()`. Gated.
- `RToken.mint` -> `require(_msgSender() == address(backingManager))`. Only the
  BackingManager mints (against issuance) -> supply integrity intact.
- All `set*` governance setters: `requireGovernanceOnly()`. Gated.

## Tool improvement (12th precision fix)
`INLINE_AUTH` now recognizes the `requireGovernanceOnly()` / `require*Only()` /
`check*Only()` inline-auth-call pattern, and `det_mint` uses `INLINE_AUTH` (so
`_msgSender() == ...` gates are seen). Result on `p1`: ACCESS 90->19, sibling 55->17,
supply 5->2; `RToken.mint` + governance setters correctly suppressed.

Residual FP: the PUBLIC `setPrimeBasket` wrapper still flags — its body just delegates
to the gated internal `_setPrimeBasket`. Following that call is call-graph analysis
(L2/Slither), out of L1 scope. Recorded as `fp` in the ledger.

## Disposition
No issue. reserve is mature/heavily-audited (not the "fresh, lightly-audited" target
we want); it topped the rank only via FP inflation, now corrected. Lesson: a high
volume score can be a TOOL artifact (dual impl + unrecognized auth pattern), not signal.
