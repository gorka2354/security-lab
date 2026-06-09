# HUNT: RockSolid Network (rETH Vault) -- scout v2 candidate #3

Third scout-v2 (`--source defillama`) target: RockSolid "Liquid Vaults" (DefiLlama Yield/vault,
audits=0, ~$19.5M TVL, Ethereum). Flagship = **RockSolid rETH Vault** `rock.rETH`
(`0x936faCdf10c8c36294e7b9d28345255539d81bc7`, proxy -> impl `0x2b65...dedf`), deposit rETH
(`0xae78736c...6393`, Rocket Pool) -> ERC-7540 async share token. Clone gitignored `hunts/_volume/rocksolid`.
**CLEAN pass** (engines ran; the one applicable drift verified MOOT on-chain). No finding.

## What it actually is -- a verbatim Lagoon (ex-Hopper) v0.5.0 fork
Storage namespace `erc7201:hopper.storage.*` -> this is **Lagoon Finance async-vault v0.5.0**, deployed
as-is. Diffed every core file (`Vault/ERC7540/FeeManager/Roles/Silo/Whitelistable`) and their
`src/protocol/{FeeRegistry,Events}.sol` against canonical Lagoon (`hopperlabsxyz/lagoon-v0`):
- `src/protocol/*` == canonical `protocol-v1/*` (only renamed the dir; byte-identical logic).
- Core v0.5.0 == canonical, modulo formatting + a spurious `pragma solidity "0.8.26"` (quoted) from the
  Sourcify metadata. **Zero custom code drift.**

## The only drift = version lag (v0.5.0 vs canonical v0.5.1 / v0.6.0) -- and it's MOOT here
- **v0.5.0 -> v0.5.1 patch = whitelist hardening:** v0.5.1 adds `_doubleWhitelistedCheck(a,b)` to ALL
  claim paths (`_deposit/_mint/_redeem/_withdraw`) + `syncDeposit`, and validates `controller`/`receiver`
  (not just `owner`). v0.5.0 only checks `isWhitelisted(owner)` at request time -> in a WHITELISTED vault a
  non-whitelisted controller/receiver could be issued/claim shares (a KYC/compliance bypass, not fund loss).
  Also adds `InvalidController(controller==0)` (v0.5.0 lacks -> only self-griefing) and `isWhitelisted`
  auto-passes `address(0)`.
- **MOOT on-chain:** read the deployed vault's `Whitelistable.isActivated` (ERC-7201 slot
  `...4800` +1 = `...4801`) = `0x00` -> **whitelist disabled / permissionless**; `isWhitelisted(0xdEaD)`
  returns `true`. With `isActivated==false`, `isWhitelisted()` returns `true` for everyone, so the missing
  double-checks have ZERO effect. The entire v0.5.1 security delta does not apply to this deployment.
- **v0.5.1 -> v0.6.0** is a major *redesign* (libraries, syncMode/isAsyncOnly, preMint/maxCap,
  entry/exit/haircut fees, allowHighWaterMarkReset), not a discrete backportable security fix.

## Recon flags -- triaged
- `Vault.sol:63` ERC4626 first-depositor inflation -> **FP (by design + moot):** `totalAssets()` returns the
  **bookkept** `$.totalAssets` state var (ERC7540.sol:151-153), NOT `asset.balanceOf(this)`, so donation/
  force-feed cannot move the share price; `convertToShares/Assets` also use OZ virtual shares
  (`+10**_decimalsOffset()`, `+1`). And the vault is already seeded (~7943 shares / ~$19M) -> first-depositor
  window long closed.
- `Vault.sol:200` `syncDeposit` reentrancy (external call -> state write) -> FP: asset is rETH (plain ERC20,
  no transfer hooks); `safeTransferFrom` to `safe()` then mint; no attacker-controlled callback.
- `ERC7540.sol:305/314` mint -> gated (settle/claim machinery), supply bounded by settled requests.

## Status -- CLEAN (no finding)
Verbatim audited Lagoon v0.5.0; no custom drift; the one applicable version-lag patch (v0.5.1 whitelist)
is verified MOOT for this permissionless vault (on-chain `isActivated==false`). NAV is bookkept (no donation
attack), inflation virtual-share-mitigated, vault seeded. Nothing to disclose with impact. (Informational-only
hygiene: sync the fork to the latest Lagoon for defense-in-depth.) Primary session win remains Ledgity (Medium).

## Method note -- scout v2 keeps surfacing audited forks
Usual ETH0 (= audited USD0/DaoCollateral), RockSolid (= audited Lagoon v0.5.0): the actionable
(fetchable-source) DefiLlama candidates trend toward forks of audited code; the genuinely-novel-code targets
sit on obscure chains without easy verified-source access. The win condition is **drift** (RockSolid had none)
or **a version-lag patch that APPLIES to the live config** (RockSolid's didn't). Worth teaching scout/recon to
flag "fork of known-audited base + version-behind" early, so drift-diff is step 1, not step 5.
