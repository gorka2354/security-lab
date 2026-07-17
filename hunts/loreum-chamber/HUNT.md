# HUNT: Loreum Chamber  (loreum-org/chamber)

- **Date:** 2026-06-11
- **Source:** GitHub sweep (fresh under-reviewed Solidity, deploy artifacts) -> novel "Agentic Corporations Onchain".
- **Repo:** https://github.com/loreum-org/chamber  (Solidity, 15 contracts, no license, 10 stars)
- **What:** Chamber = an **ERC4626 vault + ERC721 membership + delegation/seats governance + a multisig Wallet**
  (treasury). Holders delegate Chamber shares to membership tokenIds -> a sorted leaderboard (Board) -> top N
  tokenIds become directors -> directors confirm/execute the Wallet's treasury txns.
- **Deploy status:** `app/contracts/deployments.json` chainId **31337 (Anvil/local)**; broadcast on chain 1 is a
  DRY-RUN. **Pre-launch / not mainnet.** -> LIVE-FIRST: any finding here is park-not-urgent.
- **Verdict:** **No finding on the examined surfaces.** Well-hardened (numbered Findings 4/6/11 fixed in-code),
  despite the under-reviewed appearance.

## Triage + detect
- forkdrift: greenfield (novel, no known base) -> hunt the whole surface.
- recon-29: 4 `[!]` leads, all `Chamber.sol:321/425` (updateSeats / revokeConfirmation) -> **FP**: both carry the
  `isDirector(tokenId)` custom auth modifier, which recon doesn't recognize (not `only*` / INLINE_AUTH). Same
  class as the Liquity `_requireCallerIs` FP. Precision-fix candidate (recognize `is<Role>(id)` modifier gates).
- deepdive: Tier-1 = Chamber.sol.

## L4 read -> the main hypothesis (the GameFi/gambling focus: governance/economic)
**Hypothesis (voting-weight double-count / governance capture):** `delegate(tokenId, amount)` records a holder's
delegation bounded by their share balance AT DELEGATE-TIME. If `transfer` didn't sync delegations, an attacker
could delegate N -> transfer the N shares to an alt -> the alt re-delegates the same N -> K accounts recycle N
shares into K*N leaderboard weight -> capture all director seats -> control the Wallet (treasury).

**VERIFY -> MITIGATED (not a finding):** Chamber overrides `_update` (Chamber.sol:703, the single OZ-v5 balance
chokepoint covering transfer/transferFrom/burn/ERC4626 redeem):
```solidity
if (from != 0 && value > 0 && balanceOf(from) - value < totalHolderDelegations[from]) revert ExceedsDelegatedAmount();
```
So delegation-committed shares CANNOT move -> the exploit reverts at the transfer step; voting weight is bounded
by circulating shares. The in-code comment is explicit: *"Fixes Finding 4: ERC4626 withdraw/redeem previously
bypassed delegation checks."* ERC4626 first-deposit inflation is also mitigated (Finding 6, `_decimalsOffset()=3`,
OZ virtual shares); evicted-node undelegate handled (Finding 11).

## Honest takeaway
The engine aimed correctly (recon/deepdive -> Chamber; L4 -> the delegation<->transfer surface, the highest-EV
governance bug class) and the VERIFY discipline held: the hypothesis was their already-fixed Finding 4, and the
`_update` chokepoint provably blocks it -> **no false-positive filed**. That non-report IS the win of a sharpened
+ QA'd engine. Target is pre-launch + reviewed; not re-examined: the Board doubly-linked-list ordering and the
Wallet confirm/execute auth (left for a future pass if it goes live).
