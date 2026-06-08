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
