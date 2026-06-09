# HUNT: MagicSwap v2 (TreasureProject/magicswapv2-contracts)

First **dual-engine** run (recon-21 + hypothesize-with-bridge) on a real project. MagicSwap v2 =
UniswapV2 fork + a custom NFT-aware router (`MagicSwapV2Router`, "universal token compat" = swap
NFTs via fungible vault tokens) + `StakingContractMainnet`. Part of the declining Treasure GameFi
ecosystem. Skill-practice (no bounty). Clone: gitignored `hunts/_volume/magicswap` (40 prod .sol).
Recon: `hunts/_volume/magicswap-recon.md`; hypotheses: `hunts/_volume/magicswap-hypo.md`.

## The dual-engine CONVERGENCE (why this was the spot to dig)
- **recon (analyzer):** `MagicSwapV2Router` -> 5x reentrancy [!] + unchecked transfer; `NftVault.skim`
  / `NftVaultPermissioned.skim` ungated; `StakingContract.claimRewards` ungated; strict-balance ==.
- **hypothesize (attacker):** round-trip pairs `depositVault<->withdrawVault`, `addLiquidityNFT<->
  removeLiquidityNFT`, `stake<->unstake` -> "is the caller ever richer after?".
- Both point at the **NFT-vault deposit/withdraw + LP flow** -> that is where I dug.

## Triage (verify-before-claiming)

| Lead | Detector | Verdict | Why |
|---|---|---|---|
| `NftVault.skim:245` / `NftVaultPermissioned.skim:267` | access/sibling `[!]` | **FP** | gated by `isTokenAllowed -> revert MustBeDisallowedToken` -> can only rescue NON-backing tokens (Uniswap-skim pattern); can't touch vault NFTs |
| `StakingContract.claimRewards:325` | access `[!]` | **FP -> fix#26** | user self-claim (`userStakes[msg.sender]`), `nonReentrant`, standard rewardPerLiquidity accumulator; det_access missed the self-scope key (it sits past the 280-char window) |
| `MagicSwapV2Router` reentrancy x5 (92/138/180/217/254) | reentrancy `[!]` | **low / by-design** | periphery router, no persistent per-user state; NFT-deposit callbacks go to the trusted vault; `pair.mint` is balance-based; the NFT-to-`_to` callback in removeLiquidityNFT holds only transient funds |
| `NftVaultPermissioned.sol:234` strict `==` on `balanceOf(this)` | strict-balance `[!]` | **refuted** | force-feeding the vault token only makes the `==` false -> falls through to the WORKING normal burn path, not a DoS. (Detector surfaced; L4 refuted -- the loop working.) |
| `Router:85` / `NftVaultManager:23` unchecked transfer | unchecked `[!]` | hygiene | use SafeERC20; tokens in scope are standard |

**NftVault accounting (the round-trip):** deposit mints `ONE*amount`; withdraw burns `ONE*amount`.
Boundary cases are intentional haircuts for dust locked in the UniV2 pair: last-NFT redeems for
`LAST_NFT_AMOUNT` (99.9%) and the first NFT after an empty vault mints `ONE - totalSupply` to absorb
leftover. Both move value in the protocol's favor; round-trip is symmetric in the normal case. No leak.

## Outcome -- no finding (well-built Treasure production AMM); system learned
- **fix#26 `det_access`:** the self-scope `mapping[msg.sender]` check now scans the FULL function body,
  not just the first 280 chars -> user-claim fns (claimRewards-class) that index `userStakes[msg.sender]`
  deep in a loop no longer FP. The `[msg.sender]`-as-key shape is specific (unlike fix#13's bare
  msg.sender) so widening is safe. Regression test added; claimRewards FP confirmed gone on live code.
- **det_strict_balance (the new 21st detector) earned its keep:** it surfaced a real strict `==` on a
  balance; triage refuted it (force-feed falls through to a working path) -- exactly surface-then-verify.

**Lesson:** the dual-engine convergence (recon "here" + hypothesize "round-trip") is a good *aimer* --
it sent me straight to the NFT-vault flow instead of reading 40 files. The code held up; the durable
value is fix#26 + a validated new detector.
