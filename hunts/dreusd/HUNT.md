# HUNT: DRE / dreUSD (Sherlock contest, LIVE 2026-06-08 -> 06-17)

First **genuinely-live** target this run: a Sherlock audit contest in progress. dreUSD = a
USD stablecoin (mint vs whitelisted stablecoins) with an ERC4626 savings vault (`dreUSDs`),
async-NFT redemption (`dreWithdrawalNFT` + keeper bot), an oracle (`dreUSDOracle`), an Aave V3
yield adapter, a rewards distributor, and a **LayerZero OFT** for cross-chain shares
(`dreShareOFT` / `dreShareOFTAdapter` / `dreOVaultComposer`). EXACTLY our watchlist prediction
(`dre-scope-public`). Clone (faithful participant mirror): gitignored `hunts/_volume/dreusd`.
Recon: `hunts/_volume/dreusd-recon.md`; hypotheses: `hunts/_volume/dreusd-hypo.md`.

White-hat: read public contest scope + local analysis only; no exploitation; a real finding
would be disclosed via the official Sherlock channel (KYC) by the user.

## Dual-engine run -> 7 high-signal leads; top ones triaged

| Lead | Detector | Verdict |
|---|---|---|
| `dreUSDManager.mintFrom:373` PUBLIC mint | supply `[!]` | **FP / well-built** -- a signature-gated meta-tx mint: collateral pulled from `from` via `_transferAndMint`; EIP-712 `_authorize` binds from/receiver/asset/amountIn/minAmountOut/deadline/**nonce**, domain separator uses live `block.chainid`, OZ `ECDSA.recover`, `signer!=from -> revert`. Replay/param-omission/fork-replay all closed. |
| `dreUSDs` ERC4626 inflation | erc4626 `[!]` | **refuted** -- `totalAssets()` is internal-accounting (`_virtualBalance + vested`, NOT `balanceOf(this)`); virtual balance tracks deposits and IGNORES direct transfers -> donation can't move the share price (a sound, non-standard mitigation; `excessDreUSD()`/`withdrawExcessDreUSD` sweep stray tokens) |
| `dreUSDManager.fillWithdrawal:534` reentrancy | reentrancy `[!]` | **refuted / low** -- `onlyRole(TREASURY_ROLE)` (trusted keeper), not attacker-callable |
| `dreAaveAdapter:109` reentrancy, `dreShareOFTAdapter:87` unchecked transfer | reentrancy / unchecked `[!]` | TODO -- adapter CEI + SafeERC20 hygiene; verify |
| ovault `dreShareOFT:13` / `dreOVaultComposer:16` ERC4626 | erc4626 `[!]` | TODO -- the OFT/compose layer (verify the lzCompose source-validation, our Malda class) |

## Outcome -- no confirmed finding from the pattern leads (carefully-built protocol)
The headline supply/inflation/reentrancy leads all triage to well-built: a correct EIP-712 auth,
a virtual-balance inflation mitigation, role-gated keepers, sanctions/freeze hooks on every share
transfer. The engines AIMED right (straight to the manager + vault) and the triage was rigorous.

**The real finding, if any, lives in the cross-chain OFT/compose layer** (`dreShareOFT` /
`dreOVaultComposer` / `dreShareOFTAdapter`) -- our studied Malda lzCompose class (does the compose
handler validate the message source / the composed call's target?). NOT yet read -> the recommended
next deep-dive (and the most submission-worthy angle on this live contest).

## System notes (backlog, not fixed -- avoid over-fitting)
- **det_erc4626 refinement candidate:** a vault whose `totalAssets()` uses internal accounting
  (`_virtualBalance` / `_totalAssets`, NOT `balanceOf(this)`) is donation-resistant -> the inflation
  lead could be DOWNGRADED (complement of fix#20's balance-based sharpening). Nuanced (internal
  accounting alone doesn't kill first-deposit rounding) -> note, don't auto-fix.
- `_authorize` / `_validateAddress` / `_validateController` (DRE, Centrifuge, MagicSwap) are a
  recurring inline-auth idiom family worth recognizing later; left as triaged FPs for now.
