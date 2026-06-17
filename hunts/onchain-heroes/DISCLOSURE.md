# Onchain Heroes — responsible disclosure (goodwill)

**Contract:** `HeroGachaMachine` (Abstract, chain 2741) — proxy `0xB964Bbf171ec414d2343066fD217FeC036B7B098`.
The identical pattern is in `GachaMachine` (`gachaWeaponMachine`, `0x24b15b69343b58bdd5482986978308934a2fd91e`).
**Class:** unbounded loop + upfront-payment → user funds stranded on a misconfigured slot.
**Severity (honest):** Low–Medium. NOT a permissionless drain — it is owner-config-triggered and strands (does
not steal) funds. Currently dormant on HeroGachaMachine (its slot rarities read `0`, so `mintWeapons` reverts
early), but the fragile code is live in both machines and would bite on the next slot configuration.

## The bug

`mintWeapons` charges `hero20` UPFRONT, then requests a VRF number; the weapon is minted in the VRF callback
(`vrfCallback`, the only fulfillment path). Inside the callback the weapon rarity is picked with an UNBOUNDED loop
over a `uint24` `chances` (three packed probability bytes):

```solidity
uint256 aR = randomNumber % 100;
for (uint256 i; true;) {
    uint256 rewardProb = (chances >> i) & 0xff;
    probability += rewardProb;
    if (aR < probability) { weaponRarity = (i >> 3); break; }
    i += 8;                       // 0, 8, 16, 24, 32, ...
}
```

`chances` holds only 3 bytes. If those three probabilities **sum to less than 100**, then for any VRF roll with
`aR ∈ [sum, 99]` the `if (aR < probability)` never becomes true: once `i ≥ 24`, `chances >> i == 0`, so
`probability` stops growing and the loop spins `i = 24, 32, 40, …` until it runs out of gas and **reverts**.

Because this revert happens **inside the VRF callback** — the only place the weapon is minted and the only way the
request is ever fulfilled — the request is stuck forever, and the `hero20` the user already paid in `mintWeapons`
is **stranded** (no weapon, no refund). It hits probabilistically: every roll with `aR ≥ sum(chances)` reverts.

## Trigger / impact
- **Trigger:** an admin configures a slot whose 3 rarity-chance bytes sum to < 100 (a plausible config mistake;
  e.g. setting only two tiers, or a typo). No attacker action needed.
- **Impact:** users who roll that slot lose their `hero20` on the unlucky rolls; partial silent brick of the slot.
- **Not exploitable permissionlessly:** `aR` comes from the (unbiasable, gated) VRF, so a user cannot force the
  revert; and the chances are owner-set. This is a funds-safety / robustness issue, not theft.

## What is solid (so you know we looked)
- The VRF is correctly gated: `randomNumberCallback` reverts unless `msg.sender == address(vrf)`.
- `userRandomness` is committed at request time (before the VRF resolves), so the outcome is not user-biasable.
- `BlacksmithCrafting` and `WeaponShardRemixer` were reviewed and look correct (the remixer uses a *bounded*
  single `aR < failuerChances` check, so this loop issue does not apply there).

## Recommended fix (any one closes it; ideally all three)
1. **Validate the config:** in `setSlotRarity`, require the three chance bytes to sum to ≥ 100 (or exactly 100).
2. **Bound the loop:** stop at `i < 24` and, if no bucket matched, assign a default (e.g. the top/common rarity)
   instead of looping forever.
3. **Don't strand funds:** since payment is taken before an action that can fail, add a refund/retry path for an
   unfulfilled request (or take payment only on successful fulfillment).

## Disclosure terms
Reported in good faith, no bounty expected. No funds were touched and no exploit was run — this is a static review
of the verified source plus the on-chain slot config. Happy to clarify or help verify the fix.
