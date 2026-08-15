# Krystal Community Vault - harvest() delegatecalls a caller-forged, unwhitelisted strategy -> total vault drain

**Target:** Krystal Community Vault (`github.com/KrystalDeFi/krystal-vault-contracts-v2`), **deployed
and live**. Vault implementation `0x964b88db9c467c34e8d5d2b1b833e8e6ae46198a` (Ethereum mainnet,
same address on Base/BSC/Arbitrum/Polygon/HyperEVM via CREATE2), used by every "Community Vault"
EIP-1167 clone created through `VaultFactory` `0xff630c5d2fb9920c29c264b85e968d435f07e293`.
**Component:** `contracts/core/Vault.sol` (`harvest`/`_harvest`) + `contracts/libraries/InventoryLib.sol` (`removeAsset`).
**Class:** access-control sibling inconsistency -> arbitrary delegatecall (struct-field trust mismatch).
**Verdict:** **CONFIRMED** (local Foundry PoC against the verbatim Etherscan-verified deployed source, no fork needed).
**Severity:** **High** (100% fund drain, single tx, zero cost to attacker, no shares burned / no fee / no `minReturnAmount` backstop on this path). Currently-live blast radius modest (~$1,453 USDC in the one public funded vault found this pass -- an early-adoption feature, 24 vaults created, 21 never funded) but the mechanism generalizes to every vault the factory creates, on all 6 chains.

---

## Mechanism

`Vault.harvest()` is `onlyAuthorized` (vaultOwner / `admins[]` / a platform-whitelisted automator)
and takes the `AssetLib.Asset` to harvest as a raw calldata parameter -- including its `.strategy`
field, which becomes the **delegatecall target**:

```solidity
// Vault.sol
function harvest(AssetLib.Asset calldata asset, uint64 gasFeeX64, uint256 amountTokenOutMin)
    external override onlyAuthorized whenNotPaused nonReentrant
    returns (AssetLib.Asset[] memory harvestedAssets)
{
    require(asset.strategy != address(0), InvalidAssetStrategy());   // only checks non-zero
    harvestedAssets = _harvest(asset, gasFeeX64, amountTokenOutMin);
    ...
}

function _harvest(AssetLib.Asset memory asset, ...) internal returns (...) {
    inventory.removeAsset(asset);
    ...
    bytes memory returnData = _delegateCallToStrategy(asset.strategy, data);  // <-- caller-controlled
    ...
}
```

Compare the sibling `allocate()`, which is also `onlyAuthorized` but explicitly gates its
delegatecall target:
```solidity
require(configManager.isWhitelistedStrategy(address(strategy)), InvalidStrategy());
```
`harvest()`/`_harvest()` has **no equivalent check anywhere on the path**.

**Why `inventory.removeAsset(asset)` doesn't stop it:** the lookup is keyed by `(token, tokenId)`
only --
```solidity
// InventoryLib.sol
uint256 index = self.assetIndex[asset.token][asset.tokenId] - 1;
AssetLib.Asset storage storedAsset = self.assets[index];
require(storedAsset.amount >= asset.amount, "InventoryLib: insufficient amount");
```
-- it never compares `asset.strategy` against `storedAsset.strategy`. `AssetLib.Asset{ assetType,
strategy, token, tokenId, amount }` carries `strategy` as an independent field. So a caller can
reference ANY real, existing inventory entry by `(token, tokenId)` (all readable via the public
`getInventory()` view -- e.g. the principal-token entry that exists in every funded vault since
`initialize()`/`deposit()`, or a real Uniswap V3 LP-NFT entry), forge `.strategy` to their own
contract, and set `.amount = 0` (trivially passes `storedAsset.amount >= 0`). The vault then
delegatecalls the attacker's contract with full storage + identity (`address(this) == vault`). The
attacker's code isn't limited to the cited asset either -- once inside the delegatecall it can drain
every token/NFT the vault holds, not just the one referenced in the calldata (confirmed against the
one live public vault found this pass: its real `getInventory()` holds 2 Uniswap V3 LP-NFT positions
via `NonfungiblePositionManager` + loose USDC -- all three are reachable from the same delegatecall).

**Who can trigger it:** `onlyAuthorized` = `vaultOwner || admins[msg.sender] ||
configManager.isWhitelistedAutomator(msg.sender)`. `vaultOwner` is whoever calls
`VaultFactory.createVault()` -- **anyone, for $0** ("Community Vault" creation is permissionless).
So the direct path doesn't even need a compromised admin/automator key: any anonymous strategist can
create a public vault, let real depositors join trusting the platform's `isWhitelistedStrategy`
safety net, then call `harvest()` once against a self-deployed "strategy" and take everything --
no shares burned, no withdrawal fee, no `minReturnAmount` check (all of that machinery lives in
`withdraw()`, which this path never touches).

## PoC

`test/HarvestDrain.t.sol` -- local Foundry unit test, no fork/RPC. Compiles the **actual**
Etherscan-verified deployed source (`lib/krystal-vault-src/`, fetched via
`toolkit/fetch_source.py 0x964b88db9c467c34e8d5d2b1b833e8e6ae46198a --chain 1`), unmodified. A
minimal `MockConfigManager` (tracks a real `isWhitelistedStrategy` mapping -- the PoC's
`EvilStrategy` is asserted NOT whitelisted) and a minimal `FakeERC20` (real balance/allowance
semantics) stand in for the platform's off-chain-configured singletons; everything else is the
genuine `Vault` contract and `AssetLib`/`InventoryLib` libraries.

Setup mirrors the real flow: strategist creates a public vault (`allowDeposit=true`, principal =
mock USDC), a depositor deposits 100,000 USDC trusting the platform's strategy whitelist. Exploit:
strategist (== `vaultOwner`, `onlyAuthorized` by construction) calls
`harvest({strategy: EvilStrategy, token: USDC, tokenId: 0, amount: 0}, 0, 0)`.
`EvilStrategy`'s fallback runs via delegatecall (`address(this) == vault`), sweeps the vault's full
USDC balance to the attacker, and returns a validly-ABI-encoded empty `AssetLib.Asset[]` so
`abi.decode` in `_harvest` succeeds and the call completes without reverting.

```
source toolkit/env.sh          # forge on PATH; forge auto-installs solc 0.8.28
cd krystal-community-vault-poc && forge test -vv
```
Result: `[PASS] test_harvest_delegatecalls_unwhitelisted_strategy_and_drains_vault() (gas: 318036)`.
Trace confirms the full drain in one call and confirms `isWhitelistedStrategy(EvilStrategy) ==
false` throughout (the exploit path never queries it).

## Audit cross-check (known/fixed-bug discipline)

Read the project's public audit (`Verichains, "Security Audit - Liquidity Vault Smart Contracts",
Jun 10 2025`, commit `0a5d5679...`). 7 findings total (3 HIGH, 1 MEDIUM, 3 INFO) -- none of them is
this bug (the closest, "Incorrect Calculation of TotalValue in Vault", is an unrelated
share-accounting undercount, Acknowledged/not fixed). This is a novel finding, not a
previously-disclosed/fixed issue.

## Scope / when it bites

- **Live now:** any currently-public (`allowDeposit=true`) funded Community Vault -- confirmed one
  such vault on Ethereum (`0xe646a4487a49fb8e2545af788a3228a88cc2fcf0`, `getTotalValue()` =
  $1,452.78 USDC, 2 open Uniswap V3 LP positions + owner fee configured at 10%).
- **Latent:** every other vault the factory has created or will create, on all 6 chains the
  implementation is deployed to (same CREATE2 address) -- including currently-private vaults that
  later flip `allowDeposit=true` via the one-time `allowDeposit()` transition and any vault created
  after this report.
- Recurs on demand: no rate-limit/cooldown on `harvest()`; each call can re-drain whatever principal
  has re-accumulated.

## Fix recommendation

Gate `_harvest`'s delegatecall target exactly like `allocate()` already does:
```solidity
require(configManager.isWhitelistedStrategy(asset.strategy), InvalidStrategy());
```
placed in `harvest()` (and any other caller-suppliable-`Asset` entry point) before
`_delegateCallToStrategy` is ever reached. Belt-and-suspenders: have `InventoryLib.removeAsset`
require `storedAsset.strategy == asset.strategy` (not just matching `token`/`tokenId`) so a forged
`.strategy` field can never pass the inventory gate even if a future entry point forgets the
whitelist check.
