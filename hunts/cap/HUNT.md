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
