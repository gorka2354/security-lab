# HUNT: dTRINITY (hats-finance, no-KYC) -- surfaced by scout.py (scout->hunt loop)

First target picked by the new `scout.py` Stage-0 optimizer (top non-LARGE fresh fit). dTRINITY =
a stablecoin (dUSD/dS via an AMO) + a dLEND Aave-v3 fork + dStake (staked-dUSD ERC4626 yield) +
dLOOP (leveraged-looping vaults) + dPOOL (Curve LP vaults) + an oracle aggregator + Odos-swap
liquidators. 152 prod .sol, but 144 are the **vanilla dLEND Aave fork** (upstream, skip); the novel
surface is dstable / vaults / oracle_aggregator. dTRINITY is also our `det_index` origin
($257k Aave-fork empty-market index inflation). Clone gitignored `hunts/_volume/dtrinity`.

White-hat: read-only on public hats scope; any finding -> hats submit by the user (no-KYC).

## Triage of the dTRINITY-specific leads
| Lead | Verdict |
|---|---|
| `AmoManager.allocateAmo:123` reentrancy + `:140/:176` unchecked transfer | **low/by-design** -- both `onlyRole(AMO_ALLOCATOR_ROLE)` (admin/keeper, not attacker-callable); dstable is their own token (returns true); + an explicit `AmoSupplyInvariantViolation` guard |
| `DStakeToken:18` ERC4626 first-depositor inflation | **TODO (candidate, likely mitigated)** -- OZ-v5 `ERC4626Upgradeable`, no `_decimalsOffset()` override and no dead-shares seed in `initialize`, BUT OZ v5 has built-in virtual shares (the `+1`) which bounds the inflation even at offset 0 -> catastrophic theft unlikely; confirm via `totalAssets` source + deploy-seed before sizing |
| `StaticATokenLM:29` balance-based totalAssets (fix#20 flag) | **likely upstream** -- the canonical Aave-Labs static-aToken wrapper (audited); verify it's in dTRINITY's scope vs vendored |
| `oracle_aggregator/helper/ChainlinkDecimalConverter` MISSING price>0 (x4) + Redstone wrapper MISSING decimals() | **TODO** -- a decimal-rescaler; verify whether the `price>0` / staleness check is enforced upstream in the aggregator that consumes it (cross-file) -- high impact if not (stablecoin collateral pricing) |
| `DStakeRouterDLend:188` / `WrappedDLendConversionAdapter:67/105` reentrancy | **TODO** -- dUSD<->dLEND-aToken conversion under reentrancy; attacker-reachable (deposit/withdraw); verify share/asset desync |
| `dloop/*` ERC4626 inflation (x6) | **TODO** -- leveraged-looping vaults (novel + complex leverage math); same OZ-v5 caveat + the loop accounting is the real surface |

## Outcome -- scout->hunt loop validated; no confirmed finding in this pattern pass
The new `scout.py` picked dTRINITY automatically, and the engines aimed at the right novel core
(AMO / dStake / oracle), skipping the 144-file vanilla Aave fork. The headline pattern leads triage
to admin-gated (AMO) or OZ-v5-mitigated (dStake inflation). No clean demonstrable bug from the
pattern pass on a reviewed hats-contest protocol.

**Genuinely open threads** (a deeper/longer pass, most submission-worthy on this no-KYC contest):
(1) the oracle_aggregator price>0/staleness enforcement across the converter->aggregator boundary
(cross-file -- our known det_oracle limitation); (2) dLOOP leverage accounting (deposit/redeem under
the borrow/deposit loop); (3) DStakeRouter conversion reentrancy (dUSD<->dLEND share/asset desync).
Left as ledger TODOs (not silenced) for a focused follow-up.

**Lesson:** scout.py closed the discovery gap -- from "hand-search every hunt" to "tool picks the
top fresh fit and aims the engines." The hunt itself confirms the recurring truth: reviewed code's
pattern layer is clean; the remaining value is deep cross-file/economic reasoning (L4).
