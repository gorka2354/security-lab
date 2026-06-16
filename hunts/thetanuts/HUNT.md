# HUNT / case-study — ThetaNuts legacy Index Vault ($2.1M, Ethereum, 2026-06-15)

NOT a finding (already-exploited, deprecated, out-of-scope) -- a **post-mortem learning case** + an
honest "would our engine have caught it?" measurement + the detector harvest it produced.

## The hack
- **Victim:** `0xC2C3AE0a7b405058558C9b4a63b373486CB86Ac7` -- a legacy "Index Vault" the team migrated
  away from *years ago*. **UNVERIFIED** on Etherscan / not on Sourcify (closed source).
- **Exploit tx:** `0xbba9f138fe39503bfd1aa62932dbd6ab35d37d23d48e4b7bf2988a9d5dc39fec`; exploiter
  `0x30498e4466789E534c72e03B52A16c978655b41e`. ~$2.1M drained; a whitehat clawed back ~$2M of option tokens.
- **Root cause (SlowMist + Blockaid):** low-supply share-accounting flaw in the index-token mint/claim.
  - redeem/claim: `payout = backing * amount / totalSupply` -> inflates as totalSupply is driven near zero.
  - deposit/mint: `shares = assets * totalSupply / backing` -> **rounds to ZERO** via integer division
    when `backing` is donation-inflated -> "the deposit formula evaluated to 0 -> mint for free".
  - `backing` is **balance-based** (the vault's own token balance) -> a flash-loaned donation moves it.
  - **NO** minimum-supply / dead-shares / virtual-offset guard. Flash loans amplified the mint/redeem cycles.
- **Class:** the ERC4626 first-depositor / donation **inflation attack** -- but in a BESPOKE, pre-ERC4626
  index vault with no standard interface. "Abandoned code is not safe code."

## PoC (`thetanuts-poc/`, forge test 3/3)
Faithful reconstruction from the post-mortems (source is unverified, so this is modelled, not copied):
- `test_DonationInflation_StealsVictimDeposit`: attacker bootstraps supply=1, donates a flash-loaned
  200k USDC (balance-based `backing` spikes), the victim's 100k USDC deposit **rounds to 0 shares**, the
  attacker redeems the lone share for the **whole pool** -> profit = **exactly the victim's 100k** (stolen).
- `test_DepositRoundsToZero_VictimGetsNothing`: the isolated round-to-zero primitive.
- `test_Control_GuardedVaultBlocks`: the same vault WITH dead-shares/min-supply -> victim gets 999 shares
  (attack mitigated). Confirms the fix.

## Would our engine have caught it? HONEST: no (as deployed) -- two compounding gates, one now fixed.

**Gate 1 -- REACH (dominant, still open):** the victim is **unverified** + not on Sourcify, and was in
**no bounty scope** (deprecated). `fetch_source` returns "no verified source" -> the whole source-based
pipeline stops at the door. A deprecated-but-live unverified contract is a real blind spot; catching this
class proactively needs **bytecode/decompilation** or deprecated-deployment monitoring, not source recon.
This is itself the lesson of the hack (old code stays live on-chain).

**Gate 2 -- DETECT (now fixed):** measured concretely -- ran `recon.py` on the faithful reconstruction
with the word "ERC4626" stripped (a real bespoke vault has no such string). Result: **`det_erc4626`
returned 0** (it hard-gated on the literal `\bERC4626\b`), `det_precision` returned 0 (the formula is
multiply-before-divide, correct order), `det_mint` only caught the mock token. **NONE of the 38 detectors
flagged the actual bug.** -> Harvested: broadened `det_erc4626` to ALSO fire structurally on the bespoke
shape -- a deposit `*\s*totalSupply\s*/` paired with a redeem `*\s*\w+\s*/\s*totalSupply` and NO
dead-shares/min-supply guard -> `[!]`, with a balance-based-backing donation note. Requiring BOTH shapes
keeps pure staking math (`reward*1e18/totalSupply` alone) from tripping it. TP-grounded on the clean
reconstruction (fires `[!]`), **0 FP across the 29-target fetched corpus**, golden 353->356
(TP + staking-negative + guarded-negative). Now: IF we reach a similar bespoke vault's source, we flag it.

## Reach-extender harvest (`toolkit/reach_bytecode.py`) -- partially closes the dominant gate
The reach gap (Gate 1) is the harder one, so I built the first response: when `fetch_source` returns "no verified
source", `reach_bytecode.py` reads the deployed BYTECODE (`eth_getCode`, works for ANY address), recovers the
function-dispatcher SELECTORS (opcode-aware PUSH4 walk), resolves them to signatures (4byte.directory; openchain if
reachable; an offline ERC20/4626 map), and triages the surface (vault/share? mint/redeem? owner-drain?).
**Ground-truth on the actual unverified victim `0xC2C3AE0a`:** recovered **36/50 signatures** from raw bytecode --
`deposit/withdraw/initWithdraw/epoch` (withdrawal queue), `mint/claim/mintFee`, `rebalance/vaults/totalWeight/sync`,
Aave integration (`getLendingPool/setAaveAddressProvider`) -- and correctly fired **`[!] UNVERIFIED but
VAULT-SHAPED -> share-inflation review warranted`**. So ThetaNuts would NO LONGER be invisible: the triage surfaces
it. `fetch_source` now prints the `reach_bytecode` fallback hint on any unverified miss. golden 358->360.

## Decompile layer (`toolkit/decompile_match.py`) -- the MATH, recovered from bytecode
Went the next layer up: DECOMPILE the unverified bytecode and detect the round-to-zero MATH itself.
Decompilation (panoramix) needs Unix signals + does NOT run natively on Windows -> the **WSL lane**
(`toolkit/WSL-LANE.md`; do NOT `pip install panoramix` on the Windows Python -- it drags in a web3 beta that
breaks the toolkit). End-to-end on the real victim `0xC2C3AE0a`: panoramix (WSL) decompiled the 12.5KB
bytecode -> 71KB pseudocode with `totalSupply` RESOLVED BY NAME, and `decompile_match.py` flagged
**18 proportional `vaults[..].field_256 * _mintAmount / totalSupply` sites, NO dead-shares guard ->
round-to-zero / inflated redeem (ThetaNuts class)**. det_erc4626 (source) needs both share shapes; decompiled
output only carries the `/ totalSupply` redeem shape, so this is a panoramix-tuned matcher (golden-tested).

## Takeaway
The engine had the right INSTINCT (this class was already a detector) but was **too narrowly keyed** to the
ERC4626 interface (detector gap -- closed) and **couldn't reach** an unverified deprecated deployment (reach gap).
Both layers of the reach gap are now addressed: `reach_bytecode` recovers the SURFACE (Windows), and the WSL
decompile lane + `decompile_match` recovers the MATH. An unverified live contract like ThetaNuts is now triaged
from bytecode all the way to the share-inflation finding. Remaining frontier: panoramix is old (chokes on modern
0.8.x dispatchers) and needs `totalSupply` named -> a slot-based pass (heimdall, or "which storN is the supply
counter") is the next refinement.
