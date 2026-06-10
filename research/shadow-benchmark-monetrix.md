# Shadow-benchmark #1 — our pipeline vs a SOLVED contest (Monetrix, C4 2026-04)

First time we measure our own recall (borrow #5 from the Krait study). Method: clone the solved C4 scope,
run `recon` + `hypothesize` (no peeking), then diff what we'd surface vs the PUBLISHED findings
(code4rena.com/reports/2026-04-monetrix + Zellic V12 public run v12.sh/runs/2147).

**Target:** Monetrix — HyperCore/Hyperliquid stablecoin (USDM/sUSDM + MonetrixVault + Yield/Redeem escrows +
MonetrixAccountant backing math + PrecompileReader). DeFi accounting-heavy.

## What WE surfaced (recon + hypothesize, blind)
- recon `[!]`: `MonetrixAccountant.sol:199` (TODO/incomplete-logic), `InsuranceFund.sol:38` (reentrancy CEI). +10 lower leads.
- hypothesize round-trip seeds: `deposit<->withdraw`, `burn<->mint`, `supplyToBlp<->withdraw`, `addMultisigSupplyToken<->removeSuppliedEntry`.

## The PUBLISHED findings (sample)
- **C4 [M-01]:** "PM borrow liabilities are omitted from backing, allowing phantom surplus settlement" -- an
  ACCOUNTING bug in `MonetrixAccountant.totalBackingSigned()` / settle (liabilities undercount -> phantom surplus).
- **Zellic V12 cluster:** `distributeYield()` griefable DoS (escrow balance pushed high -> every call reverts);
  **stale-yield overminting** after `settle()` (distributes stale yield -> over-mints USDM while undercollateralized);
  hardcoded `HLP_VAULT` constant (upgrade-rigid). All in Accountant / YieldEscrow / Vault / settle.

## RESULT — honest recall
- **AREA recall = GOOD.** Our net flagged the RIGHT FILES: `MonetrixAccountant` (M-01's exact file) + the
  vault/escrow round-trips (the V12 yield/settle cluster) + `InsuranceFund`. We pointed at every neighborhood
  where the real findings live.
- **FINDING recall (recon ALONE) = LOW.** The actual bugs are ECONOMIC/ACCOUNTING reasoning bugs (backing
  undercount -> phantom surplus; stale-yield overminting). Regex recon CANNOT find these -- it can only flag
  "Accountant has a TODO" and "there's a round-trip pair". The bug is in the *numbers*, not a syntactic pattern.

## LESSON (validates borrows #1+#2 -- this is the payoff)
The benchmark is objective proof of what we already suspected: **our deterministic net (recon+hypothesize) is a
PRE-FILTER that points at the right files; it is NOT a finder of economic bugs.** The FINDING comes from the L4
read. And M-01 is *exactly* an **Accountant-mindset + coupled-state** finding ("trace every wei -- does
totalBacking account for ALL liabilities across settle?") -- precisely what `L4-READ.md` (#2) Step-1 Accountant
mindset + Step-5 coupled-state now force. The stale-yield-overminting is a Step-3 Feynman ORDERING/ASSUMPTIONS +
Step-4 missing-checkpoint finding. So: had we run `L4-READ.md` on the Accountant file recon flagged, the
methodology routes straight at M-01. -> #1+#2 aren't theory; the benchmark shows they're the missing finder.

## Takeaways
1. **recon/hypothesize = aim; L4-READ = fire.** Never conclude "clean" from a quiet recon -- run L4-READ on the
   flagged Tier-1 files (Accountant/Vault/escrows) regardless of `[!]` count.
2. **Detector-gap:** an "accounting/backing conservation" reasoning class (liabilities-omitted-from-backing) --
   not statically catchable; belongs as a hypothesize invariant template ("Σ liabilities <= backing across ALL
   settle paths") + the L4 Accountant lens.
3. **Next:** formalize a `toolkit/shadow.py` harness (clone from a registry -> run pipeline -> diff vs a findings
   list -> recall/precision dashboard) so improvements are measured, not vibed. Monetrix = data point #1.
