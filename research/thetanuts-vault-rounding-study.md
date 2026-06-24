# Thetanuts Finance exploit — vault share-price rounding (studied 2026-06-24)

**Incident:** 2026-06-15, Thetanuts Finance (Ethereum). ~$2.1M drained from a **deprecated "Index Vault"**
(migrated away from years ago, "no relation to current contracts"). ~$2M recovered by a whitehat; attacker
kept ~$105k (swapped to ~60 ETH) + ~$34k in option tokens. (SlowMist / PeckShield.)

**Root cause:** flawed share-pricing in the legacy vault. Redemption: **`payout = backing * amount / totalSupply`**.
As `totalSupply` shrinks toward 0 (via burns), each remaining share is "backed" by a disproportionate slice
of `backing` -> redeeming a tiny share returns inflated value. The mint side rounds the opposite way (shares
floor to ~0 cost). Attack = repeated **mint-and-redeem cycles amplified by a flash loan** on a near-empty vault.

## Two classes (both matter)
1. **Bug class:** vault share math keyed on `totalSupply`/`totalShares` (`X * amount / totalSupply`) with NO
   low/zero-supply protection -> the share price is manipulable when supply is small (drain-to-near-empty,
   then the ratio explodes; or mint rounds to 0 = free shares). Generalizes the ERC4626 first-depositor
   inflation to ANY custom vault. This is the empty/near-empty-vault share-price attack.
2. **Target class:** a **deprecated-but-still-funded** contract — migrated away from, unaudited-since, still
   on-chain, still holding value, still callable. "Deprecated" != "safe." A SOURCING lane: old vaults with
   residual TVL are high-EV (forgotten, often un-monitored, classic bug shapes).

## Could OUR engine have caught the bug? — honest verdict (before this study)
- `det_erc4626`: **MISS.** Gated on the literal `ERC4626` string; the Index Vault is custom/pre-4626. And it
  targets donation-inflation, not shrinking-supply redemption.
- `det_precision`: **MISS.** It only flags the *syntactic* divide-before-multiply order (`a/b*c`). The bug
  formula `backing * amount / totalSupply` multiplies FIRST (correct order) — it just floors to 0 / inflates
  when totalSupply is tiny. A round-to-zero RESULT, not a divide-before-multiply ordering.
- => **Real gap.** Built `det_vault_share_math` (recon #40): string-agnostic share-math keyed on
  totalSupply/totalShares with no minimum/dead-shares/zero-guard. Cedes the ERC4626 case to det_erc4626.

## Hypothesis / invariant (for the L4 read)
- **Invariant:** for a vault, `mint(x)` then immediately `redeem(sharesMinted)` returns <= x (no round-trip
  profit), AND no sequence of mint/redeem at any `totalSupply` (incl. near-0) extracts more `backing` than
  deposited. Fuzz at `totalSupply in {0, 1, dust}`.
- **Mitigations to recognize (FP):** MINIMUM_SHARES / dead-shares seed (`_mint(address(0)/0xdead/this)`),
  `_decimalsOffset` (OZ virtual shares), an explicit `totalSupply == 0` first-deposit special-case, or a
  hard minimum deposit. Any of these -> the low-supply window is closed -> lead is dead.

## Sources
- cryptopolitan / beincrypto / cryip / cryptonews / crypto-economy — $2.1M deprecated Index Vault, June 2026
- SlowMist (integer-division/mint flaw), PeckShield (whitehat recovery)
