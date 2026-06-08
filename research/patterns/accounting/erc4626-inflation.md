# Pattern 01 — ERC-4626 share-price / exchange-rate manipulation

**Tier:** T2 (cross-component / invariant) — partly T1-detectable (the pre-conditions), but the *impact* needs reasoning.
**One line:** an attacker moves a vault's assets-per-share by **donating** assets (or shrinking supply) when the share
math is unprotected, so either (a) later depositors mint too few shares (theft), or (b) a *consumer* that prices the
vault share as collateral/oracle over-values it (the big-money version).

## 1. Mechanism
ERC-4626 share price = `totalAssets() / totalSupply()`. Two ingredients make it manipulable:
1. **`totalAssets()` is balance-based** — e.g. `asset.balanceOf(address(this))` (or sums `balanceOf` of wrappers).
   Then anyone can **donate** by transferring tokens straight to the vault → `totalAssets` jumps, `totalSupply` doesn't.
2. **No virtual-shares offset** — OZ `ERC4626._decimalsOffset()` defaults to **0** (mitigation OFF unless overridden).
   `convertToShares(assets) = assets * (totalSupply + 10**offset) / (totalAssets + 1)`. With offset 0 and an empty/low
   vault, 1 wei mints 1 share, then a donation makes each share worth ~the whole donation.

**Flavor (a) — vault-internal first-depositor theft.** Vault empty (fresh deploy OR after a full withdrawal). Attacker
deposits 1 wei → 1 share. Donates D → share price ≈ D. Victim deposits V<D → `V*(1+1)/(D+1)` rounds to **0 shares**,
their V is absorbed by the attacker's 1 share. (A `ZeroShares` revert downgrades this to **griefing/DoS + rounding-loss**
rather than full theft — see dStake.)

**Flavor (b) — vault-as-oracle (the $-version).** A *lending* protocol prices the vault share (`convertToAssets`/
`pricePerShare`) as collateral. Attacker inflates the rate via donation → borrows against the inflated collateral / self-
liquidates → drains the lender. The vault itself need not lose anything; the **consumer** that trusted its rate does.

## 2. Real examples
- **Venus Protocol, Feb-2025, ~$716k (ZKsync).** Flash-loaned ~$4M, donated into Mountain's **wUSDM** ERC-4626 wrapper,
  inflated its exchange rate **1.06 → 1.7**, then **self-liquidated** two accounts on Venus that priced wUSDM as
  collateral. Flavor (b). Root cause: "the vault standard has no safeguard against a manipulated rate used by a lender."
- **Inertia, May-2026, ~$152k.** Manipulated **roETH** (LST) exchange rate via **supply reduction + direct donation**,
  then over-borrowed across **5 lending markets**. Flavor (b), LST collateral. "Its own pricing safeguards failed to
  contain the manipulated collateral value." (Old class, still shipping — that's the point.)
- **dStake / dTRINITY (our session, first-hand).** `DStakeToken` is OZ ERC4626 with **no `_decimalsOffset` override**;
  `DStakeCollateralVault.totalValueInDStable()` sums `IERC20(asset).balanceOf(this)` → **donatable**. Team's own comment
  *accepts* the empty-vault residual (≤1 wei) — but only the first-depositor-windfall, not the donation-amplification.
  Flavor (a) griefing + the rate feeds dLEND (flavor b surface). Verdict: real surface, **known/accepted** + bounty
  closed → not payable, but a textbook teaching case. (See `hunts/crypto-unicorns`/scout notes.)
- **Classic:** Cream/Compound-fork first-depositor donation (2021-2022) — the original of the class.

## 3. The "tell" (read/grep checklist)
- Vault is/extends **ERC4626** (`convertToShares/Assets`, `previewDeposit`, `totalAssets`). 
- `totalAssets()` reads a **`balanceOf(address(this))`** (donatable) vs an internally-tracked accumulator (safe).
- **No `_decimalsOffset()` override** (or it returns 0) → no virtual shares.
- A reachable **empty/low-supply state**: fresh deploy with no seed; OR a path to fully withdraw (`totalSupply→0`).
- **Who consumes the share price?** grep the org for `convertToAssets`/`previewRedeem`/`pricePerShare`/`getRate` used by
  a *lending/oracle* contract → that's flavor (b), the high-impact one.

## 4. Detector idea (static, T1) — enhance `det_erc4626`
Currently `det_erc4626` flags "vault with no `_decimalsOffset`/dead-shares". Sharpen to a **2-of-2 high-confidence** flag:
- (1) contract `is ERC4626*` AND no `_decimalsOffset` override returning >0, **AND**
- (2) its `totalAssets()` body contains `\.balanceOf\(\s*address\(this\)\s*\)` (balance-based).
→ note: "ERC4626 inflation-vulnerable: no virtual shares + balance-based totalAssets — check first-depositor + who prices the share." Downgrade to `[.]` if a **dead-shares mint** (`_mint(address(0|dead|this), …)` in init) OR a `MIN_SHARES`/min-deposit guard is present (the mitigation — see §6). *Backlog: fix#20.*

## 5. Hypothesis / invariant (T2/T3 — the real edge)
- **Cross-component hypothesis (the $-finder):** "Is this vault's exchange rate read as a PRICE by any other in-scope
  contract?" → `hypothesize.py` shared-state/consumer matrix. If yes → flavor (b) → highest severity.
- **Invariant to fuzz (scaffold.py / Echidna):** `pricePerShareAfterDonation == pricePerShareBefore` — i.e. a raw
  `asset.transfer(vault, X)` (no deposit) **must not change** `convertToAssets(1e18)`. If it moves → totalAssets counts
  un-deposited balance → vulnerable. Also: `convertToShares(convertToAssets(s)) ≤ s` (no free shares round-trip).
- **Adversarial sequence:** empty vault → deposit(1 wei) → donate(D) → victim deposit(V) → assert victim shares ≥ fair.

## 6. Mitigations to RECOGNIZE (avoid FP — the session's #1 lesson)
A vault is **safe / not a finding** if ANY of these is present:
- **Virtual shares:** `_decimalsOffset()` overridden to return >0 (OZ ≥4.9 default mitigation).
- **Dead shares:** initializer mints a chunk of shares to `address(0)`/the contract/a burn address (Uniswap-v2 style).
- **Internal accounting:** `totalAssets()` returns a tracked `_totalDeposited` accumulator, NOT `balanceOf` → donations ignored.
- **Min-deposit / MIN_SHARES floor** that makes the rounding-loss negligible (but check the arithmetic is symmetric —
  Monolith's `MIN_SHARES=1e16` had `previewMint` mulDivUp vs `maxWithdraw` mulDivDown asymmetry → re-open it).
- **Seeded at deploy** (the deploy script makes a meaningful first deposit) → closes flavor (a) for fresh deploy, but
  **NOT** for post-full-withdrawal → still check the withdrawal path can't reach `totalSupply==0`.
- **Vault rate not used as an oracle** anywhere → flavor (b) is off the table (only griefing remains).

> Sharpest single question for the $: **"who treats this vault's share as a price, and can I move that price for 1 block?"**
