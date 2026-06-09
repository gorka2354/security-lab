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
| `dreShareOFTAdapter:87` unchecked transfer | unchecked `[!]` | **FP -> fix#29** -- `try IERC20.transfer(...) returns (bool ok)` captures the return in try/catch (bridge-delivery-must-not-revert -> stuckFundsRecipient on failure); det_unchecked didn't see the try/returns capture |
| `dreOVaultComposer:16` / `dreShareOFT:13` ERC4626 + OFT/compose (Malda class) | erc4626 `[!]` | **by-design** -- `dreOVaultComposer` is a THIN override of the audited LZ `VaultComposerSync`; `lzCompose` + source-validation live in the UNCHANGED base (not weakened). The overrides (`_depositAndSend`/`_redeemAndSend`/`_sendLocal`/`_refund`) are documented POST-AUDIT fixes (preserve minAmountLD, refund native, stuckFundsRecipient fallback) -- carefully done |

## Outcome -- no confirmed finding from the pattern leads (carefully-built protocol)
The headline supply/inflation/reentrancy leads all triage to well-built: a correct EIP-712 auth,
a virtual-balance inflation mitigation, role-gated keepers, sanctions/freeze hooks on every share
transfer. The engines AIMED right (straight to the manager + vault) and the triage was rigorous.

**The OFT/compose deep-dive (the Malda angle) is now done -> also well-built.** `dreOVaultComposer`
extends the audited LayerZero `VaultComposerSync`; the `lzCompose` entry + message-source validation
(the Malda concern) live in the UNCHANGED base -- DRE did not override or weaken them. What DRE *did*
override is explicitly post-audit hardening (the comments cite the prior audit issue): preserve
`minAmountLD` for OFT slippage (was 0), refund native on local sends, and route failed refunds to a
`stuckFundsRecipient` multisig so a frozen/sanctioned recipient can't trap a bridged message. These
overrides read carefully; no missing source-check, no minAmountLD=0, no value-lock.

**dreUSD conclusion: no confirmed finding** -- a carefully-built, post-audit-patched protocol. The
durable value of this LIVE-contest pass: validated both upgraded engines on genuinely-fresh code (they
aimed at the right contracts), and extracted **fix#29** (det_unchecked: `try X.transfer() returns(bool)`
captures the return). A submission-worthy bug here would require deep economic/oracle reasoning beyond a
pattern pass (e.g. the express-withdrawal NFT accounting, the dreUSDOracle pricing under depeg) -- noted
for a possible focused follow-up before the 06-17 close.

## Full-force ECONOMIC deep-dive (L4, beyond patterns) -> no demonstrable finding
Read the full pricing + mint/redeem + express-withdrawal + vault economics:
- **Oracle (`dreUSDOracle`):** sequencer-uptime + grace, per-token staleness (60s-24h), price>0,
  deviation-from-$1 band (default 1%), decimals validation, sane-range feed check on `setOracle`. Solid.
- **Mint vs redeem symmetry:** mint credits dreUSD via `getUsdValue` (truncates DOWN); redeem pays
  `getTokenAmount` (truncates DOWN). Both round toward the PROTOCOL -> NO round-trip profit. Mint is
  fee-on-transfer-safe (custodian balance-diff) and slippage-checked; `mintFrom`/FiatMint paths fully
  bound (EIP-712 + nonce / custodian-sig + mintRef-replay + chainId + daily cap).
- **Express withdrawal accounting:** internally consistent -- `expressWithdrawalAvailable` decremented
  on request (`_queueExpressWithdrawal` line 733) and restored on filler payback; filler made whole via
  `expressFillerDebt`; user pays the fee; NFT burned + fee deleted BEFORE transfer (CEI); nonReentrant +
  EXPRESS_OPERATOR-gated fill. No double-fill, no available-cap bypass, no filler-debt drift.
- **dreUSDs vault:** virtual-balance `totalAssets` (donation-resistant); rewards claimed inside deposit/
  withdraw hooks (no instant vest-steal). UUPS/roles gated.
- **Residual (Low / by-design, NOT a confident finding):** mint accepts MANY stablecoins but redeem is
  USDC-only -> a cross-collateral oracle arb exists IF an oracle lags reality, but it's bounded by the
  1% deviation band + staleness and is ~neutral in REAL value (oracle ~= real price) -> inherent accepted
  multi-collateral risk, not a clean exploit. Calibrated down honestly (Malda/Cap discipline: never
  report a non-demonstrable finding).

**Outcome:** dreUSD held up under a full economic pass -- no submittable bug found. Threads a longer
audit could still pull (not exhausted here): cross-chain share/asset conservation across hub+spoke under
partial fills/refunds; the Aave-adapter withdraw accounting; whether a sanctioned-after-request express
NFT permanently strands its slice of `expressWithdrawalAvailable`. None rose to a confident, demonstrable
finding in this pass.

## System notes (backlog, not fixed -- avoid over-fitting)
- **det_erc4626 refinement candidate:** a vault whose `totalAssets()` uses internal accounting
  (`_virtualBalance` / `_totalAssets`, NOT `balanceOf(this)`) is donation-resistant -> the inflation
  lead could be DOWNGRADED (complement of fix#20's balance-based sharpening). Nuanced (internal
  accounting alone doesn't kill first-deposit rounding) -> note, don't auto-fix.
- `_authorize` / `_validateAddress` / `_validateController` (DRE, Centrifuge, MagicSwap) are a
  recurring inline-auth idiom family worth recognizing later; left as triaged FPs for now.
