# VERDICT: Stash (Yuga Labs / Lightyear) -- bid/liquidity economics

**Result: CLEAN (no finding).** The 4 economic leads from `hunts/punks-terminal/HUNT.md`
were fork-proven CONSERVATIVE under genuinely adversarial mainnet-fork tests. Prior reasoning
(Sonnet triage) is CONFIRMED, now with executable evidence rather than reasoning alone.

- Fork: ethereum mainnet @ block `25755766` (RPC `https://ethereum-rpc.publicnode.com`).
- Real deployed system: `STASH_FACTORY 0x0000...6750` -> `deployStash(owner)` -> real proxy over
  the live impl, wired to real WETH / CryptoPunks. Real EOA-owned punks listed on the fork drive
  the `buyPunk` for-sale branch. Owner EIP-712 `PunkBid` signatures built + signed with `vm.sign`.
- Suite: `test/StashFork.t.sol` -- 11 tests, all PASS.

## Reproduce

```
# libs are gitignored (**/lib/); restore them once:
cd punks-terminal-poc
git clone --depth 1 https://github.com/Vectorized/solady.git lib/solady && rm -rf lib/solady/.git
cp -r ../thetanuts-poc/lib/forge-std lib/forge-std       # or: forge install foundry-rs/forge-std
source ../toolkit/env.sh
forge test -vv
```

## Per-lead verdict + evidence

### LEAD 1 (HIGH) -- filler economics -- CLEAN
Total ETH out of the Stash per `processPunkBid` == `bidPrice` EXACTLY; a malicious/arbitrary
filler cannot extract more than `bidPrice - minValue`.
- `test_Lead1_FillerEconomics_ConservesToBidPrice`: for-sale punk, `minValue=1e18`, `bidPrice=5e18`,
  arbitrary filler EOA. Asserts `stashOut == 5e18`, `fillerGain == 4e18`, `sellerCredited == 1e18`,
  `stashOut == sellerCredited + fillerGain` (no surplus/leak), owner receives the punk.
- `test_Lead1_MinValueAboveBid_Reverts`: punk listed above the signed bid -> reverts
  `CannotTransferMoreThanBidAmount` (cannot be forced to overpay).
- `test_Lead1_SelfListedZeroMinValue_NoOverExtraction`: filler self-lists at `minValue=0` and is the
  filler -> pockets full `bidPrice`, but the Stash STILL pays only `bidPrice` total. The overpay is the
  owner's own signed collection-bid intent (`root==0`), not a protocol leak.

### LEAD 2 (HIGH, highest value) -- two-reservation double-spend -- CLEAN
An open ETH auction order and a signed punk bid share one ETH balance but are fully reconciled.
- `test_Lead2_AuctionLockSurvivesPunkBid_NoDoubleSpend`: Stash has 5 ETH; a whitelisted auction locks
  4 ETH; a 5 ETH punk bid settles (availableETH=1 forces a 4 ETH WETH top-up). After settlement the
  Stash still holds EXACTLY the locked 4 ETH, and the auction pulls its full 4 ETH via `processOrder`.
  The same ETH is never spent twice; conservation: 5 ETH in + 4 WETH topped-up = 9 = 5 (punk) + 4 (auction).
- `test_Lead2_CannotSpendLockedETH_WhenNoWethTopUp` (the kill-shot): same setup but owner has NO usable
  WETH -> `processPunkBid` REVERTS (WETH `transferFrom` fails) rather than dipping into the auction's
  locked ETH. Proof that locked ETH is *never* used to fund a punk bid.

Why it holds: after `_swapWETH(bidPrice - availableETH)` the ETH balance becomes `bidPrice + lockedETH`;
`processPunkBid` then pays out exactly `bidPrice`, leaving exactly `lockedETH`. If the WETH shortfall
cannot be pulled, the whole tx reverts -- locked ETH is structurally unreachable.

### LEAD 4 (MED) -- WETH over-pull -- CLEAN
`_swapWETH` pulls only the shortfall (allowance-bounded) and never consumes WETH locked by a
WETH-denominated order.
- `test_Lead4_SwapWeth_PreservesWethOrderLock_AndPullsOnlyShortfall`: Stash holds 6 WETH with 4 WETH
  locked by a WETH order (2 free); a 5 ETH punk bid with 0 stash ETH needs a 5-ETH top-up. It unwraps
  the 2 free WETH and pulls EXACTLY 3 WETH from the owner. Asserts owner WETH delta == 3 (not more),
  Stash WETH after == 4 (the locked order untouched), and the WETH auction pulls its full 4 WETH.
- `test_Lead4_AllowanceBoundsThePull`: owner approves less than the shortfall -> the pull and the whole
  bid revert. Cannot over-pull owner WETH beyond allowance.

Why it holds: in both `_swapWETH` branches the post-call WETH balance equals `lockedWETH` exactly
(`withdraw(wethAmount)` after topping the free portion), so a separate WETH order's reservation is preserved.

### LEAD 3 (MED) -- nonce / replay -- CLEAN
- `test_Lead3_CancelBeatsProcess`: `cancelPunkBid(nonce)` sets `usedPunkBidNonces` (checked FIRST in
  `processPunkBid`), so a subsequent fill reverts `BidCanceled`. The lead#3 "usesRemaining desync" is
  dead code -- the used flag always wins.
- `test_Lead3_SingleUseCannotReplay`: a used single-use bid cannot be replayed (`BidCanceled`).
- `test_Lead3_MultiUseBoundedByNumberOfUnits`: a `numberOfUnits=2` bid fills exactly twice, then the
  third attempt reverts. Multi-use is hard-bounded by `numberOfUnits`.

### CLAIM D -- CEI safety -- CLEAN
- `test_ClaimD_ReentrancyOnPayout_IsBlockedByBurnedNonce`: the filler is a contract that re-enters
  `processPunkBid` from its `receive()` during the final `amountDueToCaller` payout. The re-entrant call
  fails (`BidCanceled` -- the nonce is burned BEFORE the external call), the filler is paid exactly once
  (`bidPrice - minValue`), and exactly one `bidPrice` leaves the Stash. CEI holds.

## Considered and dismissed (honest coverage notes)
- **Multi-use bid re-entrancy** could interleave a 2nd use inside the 1st use's payout, but total uses
  remain hard-bounded by `numberOfUnits` (`usedPunkBidNonces` is set when the last use is consumed), and
  each use is economically neutral (delivers a punk, pays `bidPrice`). No over-extraction.
- **Signature malleability**: SignatureCheckerLib omits the malleability check, but a malleated signature
  recovers the same signer + same `bidNonce`, so the used-nonce check blocks reuse. No gain.
- **Wrapped-punk branch** (`amountDueToCaller = bidPrice`, caller must own the wrapped punk via the
  implicit `PunkTransferHelper` ownership check) pays exactly `bidPrice` total and is owner-gated; it was
  analyzed by reading (same conservation shape as the for-sale branch) rather than fork-exercised, because
  it requires full legacy-wrapper/721 approval plumbing and carries strictly lower economic risk than the
  permissionless for-sale filler path that IS fork-proven here.
- **Order bookkeeping** (`_cleanStaleBids` / `_removeBid` swap-and-pop over the finalized-index bitmap)
  is owner/whitelisted-auction gated on a single-user contract; it is not a cross-user fund-theft surface
  and was out of scope for these four economic leads.

## Threat-model framing
The Stash is a per-user contract with an IMMUTABLE owner. The only permissionless fund-moving entrypoint
is `processPunkBid` (anyone may fill an unwrapped, listed punk bid for MEV). That path is bounded to the
owner's signed `bidPrice`, and the two reservation systems (auction orders vs signed punk bids) over the
shared ETH/WETH balance are reconciled such that balance always stays >= locked. No adversarial construction
extracted free value.
