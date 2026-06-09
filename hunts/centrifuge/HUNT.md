# HUNT: Centrifuge Protocol v3.1 (Opex25 audit scope)

Dual-engine run on a real, under-reviewed RWA protocol (164 prod .sol): cross-chain hub/spoke,
adapters (Axelar / LayerZero / Wormhole), transfer-restriction hooks, MakerDAO-dss **ward-model**
auth. Mid-contest (Opex25). Skill-practice. Clone in `cache/cand-centrifuge/...`. Recon:
`hunts/_volume/centrifuge-recon.md`; hypotheses: `hunts/_volume/centrifuge-hypo.md`.

## The headline: the ward-model FP flood -> 2 precision fixes
recon's access detectors fired ~30 `[!]` across Hub/Holdings/Accounting/Gateway/adapters -- ALL
the MakerDAO/Centrifuge ward pattern (`modifier auth { require(wards[msg.sender]==1) }`, applied as
`external auth`) which we didn't recognize. The dual engines surfaced it; the value was hardening:

- **fix#27 `det_access`/`det_sibling`/`det_mint` -- ward-model + its idioms:**
  - `auth` / `authOrHook` / `onlyWards` / `isManager(poolId)` / `authOrManager` / `isAuthorized`
    custom auth MODIFIERS (`WARD_MOD`) now count as gates.
  - inline predicate gate `_isManager(poolId);` (Hub) added to `INLINE_AUTH`.
  - a mint override delegating to `super.mint(...)` (ShareToken -> parent ERC20.mint has `auth`)
    recognized as GATED (thin super-delegator, fix#25 family).
  - Effect: the ~30-lead access flood collapsed; Hub/Holdings/Accounting/BalanceSheet FPs gone.
- **fix#28 `det_arbcall` -- self/caller call is not an arbitrary-target drain:**
  `Gateway.withBatch` does `msg.sender.call{value}(data)` (a callback-to-caller batching pattern,
  like a Uniswap-V4 unlock), and `address refund` is a refund param, NOT the call target. The drain
  class needs `<attackerAddr>.call(<data>)`. det_arbcall now strips `msg.sender`/`address(this)`
  low-level calls before flagging -> Gateway FP gone (the ARBITRARY section went to `(none)`).

Regression tests 112 -> 119; both fixes verified on the live Centrifuge tree.

## Triage of what REMAINED after the noise cleared (signal/noise jumped)
| Lead | Verdict |
|---|---|
| `AsyncVault.mint:135` (PUBLIC mint) | **FP** -- ERC-7540 async: gated by `_validateController(controller)`; mints user's already-requested shares via the gated asyncManager (a `_validate*` idiom we don't yet recognize) |
| `Gateway.withBatch:230` reentrancy / arbitrary-call | **refuted** -- callback-to-caller batching; `callbackValue <= msg.value` (no ETH drain); the `_batcher==0` lock forces `lockCallback()` |
| `BalanceSheet.revoke:172` etc. sibling | **FP** -- `isManager(poolId)` modifier (now recognized, fix#27) |
| `Spoke.updateContract:159`, `NAVManager:155`, `BatchRequestManager:448/562` sibling-inconsistent | **TODO / park** -- ungated next to `auth` siblings; multi-line signatures + receiving-side auth not yet read. Candidates for a deeper pass (or another unrecognized gate idiom) |
| `SignatureLib.ecrecover:28` (no nonce/deadline) | TODO -- verify replay protection at the caller |
| unchecked transfers (BalanceSheet/Spoke/Escrow/Recoverable), initialize (Hub/Holdings) | hygiene / diamond-init by-design |

## Outcome -- no confirmed finding (audited mid-contest), but a big precision jump
The whole Maker/Centrifuge ward-model class (extremely common: Maker, Centrifuge, Liquity-forks,
many RWA protocols) was an FP blind spot; fix#27/#28 closed it. The remaining `Spoke.updateContract`
/ sibling-inconsistent leads are parked for a deeper read -- they're the genuine signal now that the
ward noise is gone.

**Lesson:** on a ward-model protocol the FIRST pass is mostly the auth-pattern FP; recognizing the
pattern is what makes the real leads visible. The system now reads ward-model code cleanly.
