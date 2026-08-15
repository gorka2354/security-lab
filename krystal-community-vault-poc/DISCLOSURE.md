# Responsible-disclosure package — Krystal Community Vault

**Status:** ready to send. Kept private; NO live-contract interaction (PoC runs locally against the
Etherscan-verified deployed source). No public bounty program found for Krystal/Kyber (no Immunefi
page, no SECURITY.md on `github.com/KrystalDeFi/krystal-vault-contracts-v2`), so this is a courtesy
responsible disclosure.

## Recommended channel (pick one, in order)
1. **GitHub private Security Advisory** on `KrystalDeFi/krystal-vault-contracts-v2` (repo is public):
   Security tab → "Report a vulnerability". Cleanest + private. If the repo hasn't enabled it, use (2)/(3).
2. **Direct security contact:** try `security@krystal.app` / `contact@krystal.app`; check `krystal.app`
   `/.well-known/security.txt` and their docs (`docs.krystal.app`) for a disclosure address.
3. **Official socials** (last resort, ask for a private channel — do NOT post details publicly):
   Krystal Twitter/X (@KrystalDefi) or Discord — request a secure channel, then share the report.

Attach the full technical report `FINDING.md` + the PoC (`test/HarvestDrain.t.sol`) only over the
private channel.

---

## Cover note (paste into the advisory / email)

> **Subject:** [Security] High-severity vulnerability in the deployed Krystal Community Vault — coordinated disclosure
>
> Hi Krystal / Kyber security team,
>
> I'm a security researcher. I've identified and **confirmed with a working PoC** (run locally against
> your Etherscan-verified deployed source — no live-contract interaction) a **High-severity**
> vulnerability in the deployed Community Vault implementation
> `0x964b88db9c467c34e8d5d2b1b833e8e6ae46198a` (used by every EIP-1167 clone from `VaultFactory`
> `0xff630c5d2fb9920c29c264b85e968d435f07e293`, on all 6 chains it's deployed to).
>
> **Summary:** `Vault.harvest()` delegatecalls a **caller-supplied** `asset.strategy` address with **no
> `isWhitelistedStrategy` check** — unlike the sibling `allocate()`, which requires it — and
> `InventoryLib.removeAsset` keys by `(token, tokenId)` without validating `asset.strategy`. A
> permissionless vault creator (`vaultOwner`) can therefore delegatecall an arbitrary contract **with
> the vault's identity** and drain **all depositor funds in a single transaction**, bypassing the
> shares / withdrawal-fee / `minReturnAmount` machinery entirely. Currently-live public funded vaults
> are affected today; it generalizes to every vault the factory has created or will create.
>
> I have kept this private and have not interacted with any live contract. I'd like to coordinate a
> fix under responsible disclosure and can share the full technical report + reproducible PoC over a
> secure channel of your choice.
>
> **One-line fix:** gate the harvest path's delegatecall target exactly like `allocate()` already does —
> `require(configManager.isWhitelistedStrategy(asset.strategy), InvalidStrategy());` before
> `_delegateCallToStrategy` is reached (and, belt-and-suspenders, have `InventoryLib.removeAsset`
> require `storedAsset.strategy == asset.strategy`).
>
> Happy to help verify the fix. Thanks for building in the open.
>
> — [your name / handle]

## Disclosure hygiene
- Do NOT publish the exploit publicly or on-chain before the team has fixed + acknowledged.
- Give a reasonable coordinated window (e.g. 90 days, or sooner given live funds).
- If they have a bounty you missed, submit there instead (a live-fund-theft High is typically well-rewarded).
