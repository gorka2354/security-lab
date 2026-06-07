# [High] LZUnifiedBridge.lzCompose lets anyone drain the bridge's token balance to an attacker-chosen `market`

> DRAFT for responsible disclosure to Malda (Sherlock / Immunefi / security@malda.xyz).
> Reviewer: confirm details, then submit via the official channel only. Do NOT publish.

## Summary
`LZUnifiedBridge.lzCompose` (the LayerZero compose receive hook) takes the target `market`
from the **attacker-controlled compose message** and never validates that it is a legitimate
protocol market. It then `delegatecall`s the executor, whose `_fallbackToUnderlying` transfers
the bridge's **entire** underlying token balance to that `market`. An attacker can therefore
drain any funds the bridge holds (rebalancing liquidity in transit / uncomposed) to an address
they control.

## Affected code
- Repo: `malda-protocol/malda-lending`
- `src/rebalancer/bridges/LZUnifiedBridge.sol` — `lzCompose(...)` (≈ L154-193)
- `src/rebalancer/bridges/helpers/BaseOftMessageExecutor.sol` — `_fallbackToUnderlying(...)` (≈ L116-131)
- Introduced in commit `00e0fb5` ("unified bridge for LZ", PR #149) — **AFTER** the Veridise (Jan 2025)
  and Sherlock (Sep/Oct 2025) audits (not present in the audited base `c60d6c3`). This is unaudited code.

## Vulnerability detail
In `lzCompose`:
```solidity
require(msg.sender == ENDPOINT, LZBridge_OnlyEndpoint());      // (1) only the LZ endpoint
address market = abi.decode(message, (address));              // (2) market from the compose payload
address underlying = ImTokenMinimal(market).underlying();     // (3) via the attacker's market
address bridgeContract = bridgeContracts[underlying];
if (bridgeContract == address(0)) bridgeContract = underlying;
require(from == bridgeContract, LZBridge_BadFrom());          // (4) constrains the OFT/underlying, NOT market
...
oftExecutor.delegatecall(executeCompose.selector, market, underlying, bridgeContract); // (5)
```
The `message` is the LayerZero compose payload, set by whoever initiated the OFT send — i.e.
**attacker-controlled**. Checks (1) and (4) constrain the *endpoint* and the *OFT/underlying*,
but nothing constrains `market`. The delegatecalled executor then runs:
```solidity
function _fallbackToUnderlying(address market, address underlying, address bridgeContract) internal {
    if (bridgeContract == underlying) {
        uint256 bal = IERC20(underlying).balanceOf(address(this)); // address(this) == the bridge (delegatecall)
        IERC20(underlying).safeTransfer(market, bal);              // <-- ENTIRE balance to attacker market
        return;
    }
    ... // else branch: wrap bridgeContract -> underlying, then the same safeTransfer(market, uBal)
}
```
There is **no `isMarket(market)` / legitimacy check** anywhere on this path (market validation
exists only in the `onlyRebalancer` SEND path, `sendMsg`, not here). The full balance is sent to
the attacker-chosen `market`.

## Attack scenario
1. Attacker deploys a contract `FakeMarket` whose `underlying()` returns a real supported token `U`
   (one for which `bridgeContracts[U]` equals the bridge's OFT for `U`).
2. Attacker sends a minimal OFT transfer of `U` to the bridge with `composeMsg = abi.encode(FakeMarket)`.
3. The LayerZero endpoint calls `bridge.lzCompose(from = OFT_U, message = FakeMarket)`. Checks pass:
   `msg.sender == ENDPOINT`; `from == bridgeContracts[U]`.
4. `executeCompose -> _fallbackToUnderlying(FakeMarket, U, OFT_U)` transfers the bridge's **entire**
   `U` balance to `FakeMarket` (the attacker).
5. **Amplification:** in LayerZero V2, `lzReceive` (funds arrive at the bridge) and `lzCompose`
   (funds forwarded) are separate transactions, so rebalancing funds SIT in the bridge in between.
   An attacker can front-run a legitimate rebalance's compose to steal the in-transit liquidity.
   `processUncomposedMessages` confirms funds can also sit uncomposed.

## Impact
**Critical-by-design** (direct, permissionless theft of any underlying the bridge holds / has in
transit / left uncomposed — the protocol's cross-chain rebalancing liquidity), **gated on the LZ
bridge being the active, funded rebalancing path.**

### Exploitability / deployment status (please confirm internally)
Per the repo and docs, the LZUnifiedBridge does **not appear to be the active production bridge**:
- `script/deployment/mainnet/DeployCoreRelease.s.sol` deploys **AcrossBridge + EverclearBridge**;
  `LZUnifiedBridge` has only a **standalone** `DeployLZBridge.sol` and is **not in the core release**.
- Docs: rebalancing is "bridged using intent-based bridges like **Across and Everclear**"; "at launch,
  Malda integrates **Across**" — no LayerZero bridge mentioned. Contract Addresses page = "coming soon".
- `LZUnifiedBridge.sol` is a single post-audit commit (`00e0fb5`, 2026-01-28), not in the audited base.

So this is most likely **a Critical bug to fix BEFORE the LZ bridge is deployed/whitelisted/funded**,
rather than funds at risk right now. If the LZ bridge *is* already deployed and holds/routes funds,
it is a live Critical. **The Malda team can confirm the exact on-chain status** (we could not, from
public sources). Either way it warrants prompt remediation before any LZ-bridge activation.

## Proof of Concept
Two passing Foundry tests in `malda-lz-poc/` (both reproduce the drain: bridge 1000 -> 0, attacker
fake-market 0 -> 1000):
- `test/RealExecutorDrain.t.sol` — drives Malda's **actual** `BaseOftMessageExecutor` source (copied
  verbatim; only heavy imports stubbed) through a faithful `lzCompose` harness.
- `test/LzComposeDrain.t.sol` — self-contained logic reproduction with line-mapped comments.
```
forge test --root malda-lz-poc -vv
# [PASS] test_real_executor_drains_bridge  -> "CONFIRMED with REAL BaseOftMessageExecutor source"
```

## Recommendation
- **Validate `market`** before any transfer, e.g. `require(operator.isMarket(market))` (or the bridge's
  own allow-list), so funds can only be forwarded to a legitimate market.
- Prefer binding the compose to the **exact delivered amount and original sender** encoded in the OFT
  message, rather than sweeping `balanceOf(address(this))` to a caller-supplied address.
- Consider a `nonReentrant`/pull pattern and not trusting `market.underlying()` (an external call to a
  caller-controlled contract) before the `from` check.

## Notes
Found via post-audit `diffscan` (HEAD vs audited base `c60d6c3`) + manual verification. The audited
cross-chain proof path (`mErc20Host` mint/repay/liquidate) was reviewed and is sound (replay-safe
accumulated-amount accounting); this issue is specifically in the **post-audit** LZ bridge.
