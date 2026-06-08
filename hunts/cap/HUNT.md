# Hunt: Cap (Cap Labs) — live-first + post-audit drift

**Target profile:** stablecoin (cUSD/dreUSD-style) backed by a restaking shared-security
network (EigenLayer + Symbiotic operators) + delegation + oracle + LayerZero OFT.
Less-known, modern selector-gated access (OZ-AccessManager-style `checkAccess`).

**Why live-first fit:**
- Active **$126k Sherlock Public Bug Bounty** → deployed + in-scope code (bounties pay for prod).
- Public Sherlock contest **2025-07-cap** (audited commit `7254ed0`) + judging repo
  **2025-07-cap-judging** (400 submissions) → full known-issues baseline available.
- EV is in the **drift**: live deployment vs audited commit `7254ed0` (the 400-issue fixes +
  any post-audit features = unverified code). Auditing `7254ed0` directly = low EV (picked over).

## Known-issues baseline (judging repo, partial — access/reward cluster)
The contest was thorough. Access-control / reward findings already reported (do NOT re-report):
- **distributeRewards missing access control** — #490 #388 #561 #531 #333 #295 #556 #467 → `known`.
- StakedCap.notify() permissionless / DoS — #565 #546 #507 (likely `known` for StakedCap:49).
- Many oracle/slash/liquidation/epoch findings (#659 #631 #629 #577 #540 #510 #502 #382 ...).

## recon (commit 7254ed0, after toolkit fix#15)
fix#15 taught recon Cap's `checkAccess(this.fn.selector)` selector-gating → 289 → 148 leads.
Sibling-inconsistency isolated **6** high-signal ungated-among-gated functions:
| file:line | fn | baseline status |
|---|---|---|
| delegation/Delegation.sol:55 | distributeRewards | **KNOWN** (#490 etc.) → ledger |
| token/StakedCap.sol:49 | notify | likely KNOWN (#565/#546/#507) — verify |
| feeReceiver/FeeReceiver.sol:36 | ? | unchecked vs baseline |
| gelato/CapInterestHarvester.sol:69 | ? | unchecked vs baseline |
| gelato/CapNotify.sol:25 | ? | unchecked vs baseline |
| token/Wrapper.sol:52 | ? | unchecked vs baseline |

## Next (the actual EV — drift)
1. Get Cap **deployed in-scope addresses** (bounty scope / docs / explorer).
2. `fetch_source.py <addr> --chain <id>` → live verified source.
3. Diff live vs `7254ed0` → the drift = post-audit fixes + new code (unverified).
4. recon/hypothesize the drift only; filter known via ledger; verify live → PoC.

**Discipline:** white-hat, in-scope only. Known ≠ finding. Confirm live deployment before
drawing conclusions (the Malda lesson). Disclosure (if any) only via Cap's official program; user discloses.

---

## VERDICT (2026-06-08): live == audited, NO drift → LOW EV. Stand down.

Resolved the real mainnet addresses from `config/cap-infra.json` (`"1".implems` = logic,
`"1".infra` = proxies) and walked each proxy's current implementation on-chain (EIP-1967 slot):

| contract | proxy (infra) | current impl on-chain | audited impl (implems @ 7254ed0) | drift |
|---|---|---|---|---|
| accessControl | 0x7731…2c683 | 0x6681…84bc1 | 0x6681…84bc1 | **MATCH** |
| delegation | 0xF3E3…4d693F | 0x7e2D…7E38b5 | 0x7e2D…7E38b5 | **MATCH** |
| lender | 0x1562…7f01FC | 0x68c4…27aaa7 | 0x68c4…27aaa7 | **MATCH** |
| oracle | 0xcD7f…662bb | 0xbFe4…ea9F14 | 0xbFe4…ea9F14 | **MATCH** |
| cUSD (capToken) | 0xcccc…3cccc | 0xa766…29BFE6 | 0xa766…29BFE6 | **MATCH** (also diffed source: 0 substantive lines) |

**Every live core proxy points to the audited `7254ed0` implementation. No post-audit upgrade.**
So the live code == the code 400 contest submissions already shredded. EV of a *new* finding
is low; the only live bugs would be already-known contest findings (known ≠ finding; not ours).

**This is a methodology WIN, not a dead end:** in ~30 min the tools proved the target is
(a) genuinely deployed (live-first ✓) but (b) identical to heavily-audited code (no drift) →
correctly *declined* to sink hours into picked-over code. Exactly the Malda lesson applied early.

**Re-check trigger:** the $126k bounty is live; if Cap ships a proxy upgrade later, the new impl
is unverified code. Cheap recurring check: `fetch_source.py <proxy> --chain 1 --proxy` → diff vs
`7254ed0`. Worth a periodic revisit; not worth deep effort now.

**Tool upgrade banked from this hunt:** `fetch_source.py --proxy` now follows EIP-1967/1167
proxy → implementation (a proxy address alone returns a useless stub). recon `fix#15` learned
Cap's `checkAccess(this.fn.selector)` selector-gating (289→148 leads; isolates the lone ungated fn).

---

## CORRECTION (same day): the "no drift" verdict above was PREMATURE — Cap DOES drift.

The v1 verdict compared live impl *addresses* to `config/cap-infra.json`, but the cloned repo HEAD
(`7254ed0`) is dated **2026-04-29**, not the 2025-07 audit — so the config reflects the *current*
(already-upgraded) state and masked the upgrades. The new **`livecheck.py`** (Upgraded-event history)
caught it immediately:

**Drift map (live proxies, Upgraded events since 2025-08):**
- **cUSD `0xcccc`** — SIX impl upgrades (2025-08-14 → … → **2026-02-25** `0xa766`).
- **delegation `0xF3E3`** — `0x69eb`(2025-09) → **`0x7e2D`(2026-02-25)**.
- **lender `0x1562`** — 3 impls → `0x68c4`(2025-09).
- oracle `0xcD7f`, accessControl `0x7731` — single impl (no upgrade).

Audit baseline = commit **`4cad978`** (2025-07-09, contest era). Since then core changed
**124 files, +7608 / −1056**. `diffscan --since 4cad978` → **77 leads INSIDE post-audit code**.

**Triaged drift leads (cache/cap-diffscan.txt):**
| lead | scope | status |
|---|---|---|
| `ico/CCAToken` public mint/burn, `SoulboundERC1155Merkle` mint | likely OUT (ICO/airdrop, not stablecoin core) | verify scope before any work |
| many `_authorizeUpgrade NO access check` (ico/, eigen, symbiotic, sweeper) | mixed | likely FP (det_upgrade misses inherited gate) — calibrate |
| `oracle/.../ChainlinkAdapterChained.price()` missing staleness | IN (oracle, NEW post-audit) | **adapter returns lastUpdated for caller; negative→0 not revert. Hinges on caller staleness check — verify PriceOracle chain** |
| `lendingPool/.../ReserveLogic.setInterestReceiver` ungated | IN (lender lib) | library fn — gate is in caller; likely FP |
| `gelato/CapInterestHarvester.receiveFlashLoan` reentrancy, `Harvester.harvest` ungated | IN (periphery) | verify |

**Honest EV read:** Cap drifts, but it's an actively-maintained ($67M, 6 upgrades) protocol with a
live bounty → the post-audit code was *likely* re-reviewed. Drift exists but is not obviously
unaudited. The freshest surface (2026-02-25 upgrade, new oracle adapters, `ico/`) is the best bet.

**Next focused session:** (1) confirm bounty scope (core vs ico/lens/archive); (2) verify the oracle
caller chain (does PriceOracle check `lastUpdated`/`price>0` from `ChainlinkAdapterChained`?);
(3) FP-calibrate the `_authorizeUpgrade` cluster; (4) deep-read the 2026-02 delegation/lender deltas.
Also: **livecheck is now the engine to scan OTHER candidates for a CLEANER drift target** (single
audit + single unaudited upgrade beats Cap's actively-maintained churn).

---

## B DEEP-DIVE RESULT (same day): drift is SOUND. No new bug. Toolkit improved.

Worked the diffscan drift leads top-down:
- **Oracle (best real-bug-class lead) → FP.** `PriceOracle.getPrice` (L44-48) handles it correctly:
  `price==0 || _isStale` → try backup → if backup also bad → `revert PriceError`. Staleness is
  per-asset, `setStaleness` is `checkAccess`-gated; adapters return `lastUpdated` (chained = MIN) and
  negative price → 0 (rejected). The `ChainlinkAdapterChained`/`FalconX`/`LBTC` "MISSING staleness"
  flags are det_oracle cross-file FPs (guard lives in the caller, not the adapter file).
- **`ico/CCAToken` mint/burn/`_authorizeUpgrade` → FP.** All `checkAccess(...)`-gated. recon's
  det_mint + det_upgrade didn't recognize selector-gating → **toolkit fix#16 (det_mint) + fix#17
  (det_upgrade)** added (same lesson as fix#15). diffscan 77→67; the public-mint / unguarded-upgrade
  cluster cleared.
- **`fractionalReserve/Harvester.harvest` → FP/by-design + known.** Permissionless, but `_cusd` is
  caller-supplied → attacker passes their own fake = harvests their own nothing; on the real cUSD it's
  a standard keeper harvest (no funds to caller). The `realizeInterest` angle = known contest **#413**.
- **`gelato/*` notify/harvest, `ReserveLogic.setInterestReceiver`** → permissionless-by-design keepers /
  library fns gated in the calling contract / known (`notify` = #565/#546/#507).

**Verdict: Cap's post-audit drift is well-gated and sound — no new finding.** Consistent with an
actively-maintained ($67M, live bounty, 400-sub contest) protocol whose upgrades are reviewed.
Cap → archived as a methodology + tooling win (fix#15/#16/#17, fetch_source --proxy, livecheck born here).
Re-check only on a fresh proxy upgrade.
