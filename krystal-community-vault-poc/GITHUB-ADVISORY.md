# GitHub Security Advisory — copy-paste into the form

Go to `github.com/KrystalDeFi/krystal-vault-contracts-v2` → **Security** → **Advisories** → **Report a
vulnerability** (if the button is absent, private reporting isn't enabled → use the email/socials in
`DISCLOSURE.md`). Fill the fields below.

---

**Title:**
`harvest() delegatecalls a caller-forged, unwhitelisted strategy → full Community Vault drain`

**Severity:** `High`
(CVSS ~8.5 — AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H. PR:L because the attacker must be the vault's own
`vaultOwner`, which is permissionless to become for $0. See the honest blast-radius note under Impact.)

**CWE:** `CWE-829: Inclusion of Functionality from Untrusted Control Sphere` (SWC-112: Delegatecall to
Untrusted Callee)

**Affected:** `contracts/core/Vault.sol` (`harvest` / `_harvest` / `_delegateCallToStrategy`) +
`contracts/libraries/InventoryLib.sol` (`removeAsset`). Deployed implementation
`0x964b88db9c467c34e8d5d2b1b833e8e6ae46198a` (Ethereum + Base/BSC/Arbitrum/Polygon/HyperEVM via CREATE2),
behind every "Community Vault" EIP-1167 clone from `VaultFactory 0xff630c5d2fb9920c29c264b85e968d435f07e293`.

---

**Description (paste into the advisory body):**

`Vault.harvest()` is `onlyAuthorized` and takes the `AssetLib.Asset` to harvest as a raw calldata
parameter, including its `.strategy` field — which becomes the **delegatecall target** in
`_delegateCallToStrategy(asset.strategy, ...)`. Unlike the sibling `allocate()`, which requires
`configManager.isWhitelistedStrategy(strategy)`, the harvest path has **no whitelist check anywhere**.

`InventoryLib.removeAsset` keys its lookup by `(asset.token, asset.tokenId)` only and never validates
`asset.strategy` against the stored entry. So a caller references any real inventory entry by
`(token, tokenId)` (readable via `getInventory()` — e.g. the principal-token entry present in every
funded vault), forges `.strategy` to an attacker-deployed contract, and sets `.amount = 0` (passes
`storedAsset.amount >= 0`). The vault then delegatecalls the attacker's contract with full storage +
identity (`address(this) == vault`), which drains every token/NFT the vault holds — bypassing the
shares / withdrawal-fee / `minReturnAmount` machinery entirely (all of which live only in `withdraw()`).

`vaultOwner` is whoever calls `VaultFactory.createVault()` — **permissionless, $0**. So no compromised
key is needed: any anonymous strategist can create a public vault, let real depositors join trusting the
platform's `isWhitelistedStrategy` safety net, then call `harvest()` once against a self-deployed
"strategy" and take everything.

**PoC:** a local Foundry test compiles the verbatim Etherscan-verified deployed `Vault.sol` (no fork,
no live-chain interaction) — a depositor deposits 100,000 USDC, the strategist calls
`harvest({strategy: EvilStrategy, token: USDC, tokenId: 0, amount: 0}, 0, 0)`, and `EvilStrategy` sweeps
the vault via the delegatecall. `[PASS] ...drains_vault (gas: 318036)`. Full report + PoC available
privately on request. Cross-checked against the public Verichains audit (Jun 2025) — this is novel.

**Fix:** gate the harvest path exactly like `allocate()`:
```solidity
require(configManager.isWhitelistedStrategy(asset.strategy), InvalidStrategy());
```
before `_delegateCallToStrategy` is reached (in `harvest()` and any other caller-suppliable-`Asset`
entry point). Belt-and-suspenders: have `InventoryLib.removeAsset` require
`storedAsset.strategy == asset.strategy`.

---

**Impact (honest blast-radius — include it, it builds trust):**

The bug is a **100% drain of any funded Community Vault**, single tx, zero attacker cost. That said, a
live-state check (2026-08) shows the Community Vault product is **currently dormant**: the factory's last
activity was ~3 months ago (Ethereum ~96d, Arbitrum ~81d; no funded instances found on Base/BSC), and the
one funded public vault (`0xe646a4487a49fb8e2545af788a3228a88cc2fcf0`, ~$1.4K) has been idle ~127 days.
So the *current* funds at risk are small — but the flaw is systemic (every clone, all 6 chains) and would
become High-impact the moment the product is revived or a larger vault is funded. Worth fixing before any
relaunch / new deposits.
