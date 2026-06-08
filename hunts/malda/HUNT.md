# HEAD-TO-TOE HUNT: Malda (malda-protocol/malda-lending)

Chosen by deep-research for the ideal profile: **less-known + ~9 months of POST-AUDIT
commits** (max unverified code), tractable, novel architecture. Clone (gitignored)
`hunts/_volume/malda`. Alternative on deck: **Cap** (`cap-labs-dev/cap-contracts`, 195 .sol).

## Why this target
- **Post-audit drift (the key criterion):** audited by Veridise (Jan-Mar 2025) + Sherlock
  (2025-07); HEAD = 2026-04 with commits every month 2025-10..2026-04. ~9 months of code the
  audits never saw. (Search even noted post-audit PR fixes to EverclearBridge.)
- **Tractable:** 163 entry points / 31 files (vs Aavegotchi's 263). A full sweep is feasible.
- **Novel + our wheelhouse:** Compound-fork lending + CROSS-CHAIN (bridges Across/CCTP, a zk
  sequencer delivering proofs) -> bridge/messaging bug classes we know + zk-verification (fresh).
- Multiple audits -> a solid known-issues baseline (`audit/` folder).

## Architecture (from scope.py map)
- **Compound fork:** `Operator/Operator.sol` (=Comptroller, 25 fns), `mToken/*` (=cTokens:
  mErc20, mToken, mTokenConfiguration). Known classes: comptroller checks, interest accrual,
  liquidation, oracle, first-depositor/empty-market, cToken reentrancy.
- **Cross-chain (the fresh surface):** `mToken/host/mErc20Host.sol` (15), `mToken/extension/
  mTokenGateway.sol` (16) - cross-chain deposits/borrows reconciled via zk-proof + a SEQUENCER;
  `rebalancer/Rebalancer.sol` (14) + bridges `AcrossBridge`, `CCTPBridge`.
- **Oracle:** `MixedPriceOracleV3` AND `V4` (versioned -> V4 is post-V3 drift). Chainlink-style.
- Roles: onlyAdmin / onlyRebalancer / onlyOperator / onlySpokePool / onlyFirewall* / onlyMigrator.

## Coverage-driven plan (head-to-toe)
- [x] **scope.py map**: 163 entry points / 31 files -> `Coverage: 0/163` (the checklist).
- [ ] **Known-issues baseline:** read `audit/` (Veridise + Sherlock) via `toolkit/pdftext.py`.
- [ ] **diffscan the drift:** diff HEAD vs the ~2025-07 audited commit -> the post-audit code is
      the priority (unverified). Deepen the clone first.
- [ ] **Sweep every entry point** (163), prioritized: post-audit-drift first, then cross-chain/
      bridge/oracle-V4/sequencer-trust, then the Compound core. Verdict each -> ledger -> 100%.
- [ ] **Fuzz the core invariants** (solvency: total borrows <= total collateral value; supply/
      exchange-rate; cross-chain accounting) once a build is stood up.

## Focus hypotheses (where post-audit + novel = highest EV)
1. **Cross-chain accounting** (`mErc20Host`/`mTokenGateway` + sequencer): does a cross-chain
   deposit/borrow reconcile EXACTLY? can a proof be replayed / a message double-spent / the
   sequencer-trust be abused? (the zk + bridge surface the audits had least time on).
2. **Bridge rebalancer** (Across/CCTP): arbitrary-call / fund-routing on the rebalance path?
3. **Oracle V4** (the newer version): the 3-guard checklist (staleness/price>0/decimals) +
   any divergence from V3 that the V3 audit wouldn't cover.
4. **Compound-fork classics** on the post-audit diff: liquidation/interest/comptroller changes.

## 🔴 FINDING (candidate, HIGH) — LZUnifiedBridge.lzCompose drains the bridge to an attacker-chosen `market`
**Status: PoC CONFIRMS the vulnerable logic** (`malda-lz-poc/test/LzComposeDrain.t.sol`, passing -
attacker drains the bridge 1000->0 to an attacker-chosen fake market). Mechanism verified by reading +
PoC. Final step before submission = an INTEGRATION PoC on Malda's actual contracts (mock LZ endpoint).
**RESPONSIBLE DISCLOSURE via Malda's program only - do NOT publish.** This is POST-AUDIT code (see below).

**Location:** `src/rebalancer/bridges/LZUnifiedBridge.sol::lzCompose` (L154-193) ->
`src/rebalancer/bridges/helpers/BaseOftMessageExecutor.sol::_fallbackToUnderlying` (L116-131).

**Post-audit:** `LZUnifiedBridge.sol` is NEW since the Sherlock audit base (`c60d6c3`, 2025-09-15) -
added in commit `00e0fb5` "unified bridge for LZ" (#149). The audits never saw it.

**Root cause:** in the LayerZero compose RECEIVE path, `market` is decoded from the compose
`message` (L167 `abi.decode(message,(address))`), which is set by whoever initiated the OFT send -
i.e. **attacker-controlled**. lzCompose's only checks are `msg.sender==ENDPOINT` (L165) and
`from==bridgeContract` (L176) - these constrain the OFT/underlying, **NOT `market`**. The delegatecalled
executor then runs `_fallbackToUnderlying`, which does
`IERC20(underlying).safeTransfer(market, IERC20(underlying).balanceOf(address(this)))` -
**transfers the bridge's ENTIRE underlying balance to the attacker-chosen `market`, with no
`isMarket`/legitimacy check** (verified: market validation exists only in the `onlyRebalancer` SEND
path, not here).

**Attack:**
1. Deploy a fake `market` contract whose `.underlying()` returns a real supported `U`
   (one with `bridgeContracts[U]` == the bridge's OFT).
2. Send a tiny OFT transfer of `U` to the bridge with `composeMsg = abi.encode(fakeMarket)`.
3. The LZ endpoint calls `bridge.lzCompose(from=OFT_U, message=fakeMarket)`; checks pass
   (endpoint ok; `from==bridgeContracts[U]`).
4. `_fallbackToUnderlying(fakeMarket, U, OFT_U)` -> `safeTransfer(fakeMarket, wholeBalance)` ->
   **the bridge's entire `U` balance is sent to the attacker.**
   Worse: FRONT-RUN a legit rebalance's compose - in LZ v2 `lzReceive` (funds arrive at the bridge)
   and `lzCompose` (funds forwarded) are SEPARATE txs, so rebalance funds SIT in the bridge in
   between and can be stolen. `processUncomposedMessages` confirms funds can sit uncomposed.

**Impact:** drain of any underlying held/in-transit/uncomposed in the bridge (protocol rebalancing
liquidity). HIGH.

**Fix:** validate `market` is a real protocol market (e.g. `operator.isMarket(market)`) before any
transfer; and/or bind the compose to the exact delivered amount + sender rather than the whole balance.

**Next:** Foundry PoC (mock LZ endpoint + OFT) reproducing the drain -> then disclose via Malda
(Sherlock/Immunefi or security@malda). Tooling win: diffscan(post-audit) + the arbitrary-call
detector surfaced this; recon FP note -> det should learn `_onlyXxx()` inline-auth (14th fix:
`updateAllowedChain` was a FP, gated by `_onlyAdminOrRole`).

## Triage log
_(verdicts as we sweep - every entry point, FP or real, with why)_
- `mErc20Host` cross-chain mint/repay/liquidate (proof path): **SOUND** - replay prevented via
  accumulated-amount + processed cap (`mintAmount <= accAmountIn - inPerChain`), routing validated
  (`dstChainId==block.chainid`, `market==address(this)`, `allowedChains[chainId]`). Audited + unchanged.
- `mErc20Host.updateAllowedChain` [recon UNGATED] -> **FP** (gated `_onlyAdminOrRole(CHAINS_MANAGER)`).
- **`LZUnifiedBridge.lzCompose` -> HIGH finding (above), CONFIRMED as a REGRESSION (see below).**

### Rest of the post-audit drift swept (verdicts)
- **`EverclearBridgeV2.sendMsg`** [recon reentrancy, post-audit] -> **FP**: `onlyRebalancer` (trusted caller),
  validates `receiver == _market`, and EverclearBridgeV2 has **no permissionless receive hook** (Everclear
  is intent-based, no compose callback). Active bridge, sound vs this class.
- **`AcrossBridge.handleV3AcrossMessage`** (active, audited): the receive analog of lzCompose, but it
  **DOES** `require(isMarketWhitelisted(market))` before transfer -> SOUND. **This is the reference that
  proves the LZ bug is a regression: every other bridge validates `market`; only LZUnifiedBridge dropped it.**
- **`Migrator.migrateAllPositions`** [recon UNGATED] -> **FP**: self-scoped (acts on `msg.sender`'s own
  Mendi positions); existed at audit.
- **Oracle V4 (`MixedPriceOracleV4`)** [recon oracle] -> **low/FP**: existed at audit; has per-symbol
  staleness + dual-feed checks. Not post-audit drift.
- delegatecalls / `tx.origin` (firewall) flags -> within the bridge/firewall design (gated paths); no new lead.

**Drift sweep conclusion:** the ONE real finding is `LZUnifiedBridge.lzCompose` (HIGH, regression of the
market-allow-list check the active bridges have; currently behind the inactive LZ bridge -> fix-before-
activation). The active bridges (Across/Everclear) and the audited core are sound.
