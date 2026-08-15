# HUNT: Krystal Community Vault (public-vault module) -- deployed-leftovers triage round

Third of three deployed-but-undug candidates this round (Lista RWA, Textile FX, Krystal Community
Vault). Resolved via GitHub (`KrystalDeFi/krystal-vault-contracts-v2`) -- permissionless
strategist-created farming vaults, distinct from the already-triaged `krystal-shared-vault`
(SharedVault module, deep-dived same day, found hardened/CLEAN). This is a DIFFERENT Krystal
product line (`contracts/public-vault/*`) that dive did not cover.

White-hat: static + local Foundry unit test only (no fork RPC, no mainnet writes). Compiles the
Etherscan-VERIFIED deployed source verbatim. Deployed target confirmed LIVE+funded before any deep
read (Gate-0).

## Gate-0 (LIVE-FIRST)
- `vaultFactory` 0xff630c5d2fb9920c29c264b85e968d435f07e293: ACTIVE on Ethereum (chain 1, 20+ recent
  txns) and Arbitrum; DORMANT/UNKNOWN on BSC/Base in the default 5000-block window (not chased --
  Ethereum alone was enough to find + confirm the bug).
- Same CREATE2 address across eth/base/bsc/arb/polygon/hyperevm (`contracts.json`), so the
  vulnerable implementation is identically deployed on all six.
- 24 `VaultCreated` events on Ethereum since launch; batch Gate-0'd all 24 clone addresses ->
  21 EMPTY (totalSupply==0, never funded -- park), 3 ACTIVE:
  - `0xe646a4487a49fb8e2545af788a3228a88cc2fcf0` -- **public** (`allowDeposit=true`), principal=USDC,
    `vaultOwnerFeeBasisPoint=1000` (10%), owner `0x47f698b9...`, totalSupply 1468.60,
    `getTotalValue()` = **$1,452.78 USDC**, live TVL is 2 open Uniswap V3 LP positions via
    `LpStrategy` (0x851ee187...) + $0.001 loose USDC -- REAL third-party-depositor victim vault.
  - `0x896ebed6659e6046f3f20067214304192d777458` -- currently **private** (`allowDeposit=false`),
    owner `0x76288b61...`, totalSupply 899.10 -- same bug reachable, but only the owner's own funds
    are at stake while private.
  - `0xeb3e57d985ce5dfb6210aa8ae7e5b46eb3bb2aba` -- 1 recent txn, totalSupply 0 (freshly touched,
    not funded) -- not pursued.

## The finding: `Vault.harvest()` delegatecalls a caller-supplied, UNWHITELISTED `asset.strategy`

`contracts/core/Vault.sol` (Etherscan-verified, deployed at
`0x964b88db9c467c34e8d5d2b1b833e8e6ae46198a`):

```solidity
function harvest(AssetLib.Asset calldata asset, uint64 gasFeeX64, uint256 amountTokenOutMin)
    external override onlyAuthorized whenNotPaused nonReentrant
    returns (AssetLib.Asset[] memory harvestedAssets)
{
    require(asset.strategy != address(0), InvalidAssetStrategy());   // <-- only checks non-zero
    harvestedAssets = _harvest(asset, gasFeeX64, amountTokenOutMin);
    ...
}

function _harvest(AssetLib.Asset memory asset, ...) internal returns (...) {
    inventory.removeAsset(asset);
    ...
    bytes memory returnData = _delegateCallToStrategy(asset.strategy, data);  // <-- attacker's strategy
    ...
}
```

Compare the sibling `allocate()`, which explicitly gates the delegatecall target:
```solidity
require(configManager.isWhitelistedStrategy(address(strategy)), InvalidStrategy());
```
`harvest()`/`_harvest()` has **no such check anywhere on the path** -- textbook
ACCESS-CONTROL-sibling-inconsistency (recon.py Heuristic 3), just not on the line recon.py itself
flagged (it flagged `LpStrategy.harvest` for missing a modifier, a false positive -- that fn is only
ever meant to run via delegatecall so `address(this)`==vault there; the REAL gap is one layer up, in
`Vault.harvest()`'s failure to validate the `asset.strategy` FIELD against the whitelist before
using it as the delegatecall target).

**Why the caller can forge `asset.strategy` freely:** `InventoryLib.removeAsset()` looks up the
stored entry by `(asset.token, asset.tokenId)` ONLY --
```solidity
uint256 index = self.assetIndex[asset.token][asset.tokenId] - 1;
AssetLib.Asset storage storedAsset = self.assets[index];
require(storedAsset.amount >= asset.amount, "InventoryLib: insufficient amount");
```
-- it never compares `asset.strategy` to `storedAsset.strategy`. `AssetLib.Asset{ assetType,
strategy, token, tokenId, amount }` has `strategy` as a plain, independently-supplied struct field.
So a caller can reference ANY real, existing inventory entry (readable via the public
`getInventory()` view -- e.g. the principal-token entry `(token=principalToken, tokenId=0)` that
exists in EVERY funded vault since `initialize()`/`deposit()`, or a real Uniswap V3 LP-NFT entry
`(token=NFPM, tokenId=<real id>)`) by its `(token, tokenId)`, while setting `.strategy` to their own
contract and `.amount=0` (trivially passes `storedAsset.amount >= 0`). `_delegateCallToStrategy`
then delegatecalls the attacker's contract with the VAULT's full storage + identity (`address(this)`
== vault). The attacker's fallback isn't limited to the referenced asset either -- once inside the
delegatecall it has unrestricted access to every token/NFT the vault holds (confirmed against the
live vault's `getInventory()`: 2 Uniswap V3 LP-NFT entries via NFPM `0xc36442b4...` + the USDC
principal entry -- a real attack payload would drain all three, not just the one asset cited in the
calldata).

**Who is `onlyAuthorized`:** `vaultOwner || admins[msg.sender] || configManager.isWhitelistedAutomator(msg.sender)`.
`vaultOwner` is set to whoever calls `VaultFactory.createVault()` -- i.e. **anyone**, for $0 (a
"Community Vault" is permissionless to create). So the most direct exploitation isn't even a
compromised admin/automator key: **any anonymous strategist can create a public vault, let real
depositors join trusting the platform's strategy whitelist, then call `harvest()` once with a
self-deployed "strategy" to steal 100% of deposited funds** -- no shares burned, no withdrawal fee,
no `minReturnAmount` check (those all live in `withdraw()`, which this path never touches), and the
`allocate()` whitelist check is on a completely different function this path never calls either.

## PoC (confirmed, not just reasoned)
`../../krystal-community-vault-poc/` -- Foundry unit test compiling the fetched VERIFIED source
verbatim (no modifications), no fork needed:
```
cd krystal-community-vault-poc && forge test -vv
[PASS] test_harvest_delegatecalls_unwhitelisted_strategy_and_drains_vault() (gas: 318036)
```
Trace confirms: strategist (`onlyAuthorized` by construction) calls `harvest()` with a forged
`Asset{strategy: EvilStrategy, token: USDC, tokenId: 0, amount: 0}` -> `EvilStrategy.fallback()`
executes via delegatecall (`address(this)` == the vault) -> `IERC20(USDC).transfer(attacker,
vaultBalance)` -> depositor's full 100,000 USDC drained in one call, zero shares burned,
`MockConfigManager.isWhitelistedStrategy(EvilStrategy)` never even queried on the exploit path
(confirmed false in the test, confirming the missing gate).

## Audit cross-check (known/fixed-bug discipline)
Downloaded the repo's public Verichains audit (`audit/Verichains Public Report - Krystal.pdf`,
commit `0a5d5679...`, Jun 10 2025) and read the findings table. 7 findings total (3 HIGH: TotalValue
undercount/Acknowledged, deposit-denominator/Fixed, init-parameter/Fixed; 1 MEDIUM: replayable
signatures in `executeAllocate`/Acknowledged; 3 INFO). **None of the 7 is this bug** -- the
`harvest()`/`InventoryLib` struct-field trust gap was not caught by the prior audit. Novel finding,
not a known/fixed issue.

## Verdict: REAL, worth escalating (recorded in ledger)
Confirmed via source read + working local PoC against the verbatim deployed/verified contract.
Currently-live blast radius: ~$1,453 USDC in the one public+funded vault found this pass (modest --
Community Vaults are a small, early-adoption feature: 24 created, 21 never funded), but the bug is
100%-drain, zero-cost-to-attacker, and identically deployed on 6 chains via the same CREATE2
implementation address. Not disclosed to Krystal/Kyber by this session (out of scope for a triage
round) -- flagged for responsible disclosure per repo policy (no bounty program found in this pass;
disclose privately to the Krystal/KyberNetwork team, e.g. via their GitHub security contact or
Immunefi if listed).

**Next steps (not done this round):** (1) fork-PoC against a live vault to quantify a real
mainnet-state drain (the local test already proves the mechanism; a fork run would just confirm
against the real `LpStrategy`/`ConfigManager`/live Uniswap positions); (2) check whether the same
struct-field gap exists in `allocate()`'s `inputAssets` handling (it DOES check
`isWhitelistedStrategy`, but worth confirming `inventory.removeAsset(inputAsset, true)` can't be
similarly forged elsewhere); (3) check the other 5 chains' factories for any additional live funded
vaults beyond the Ethereum set gated this round.
