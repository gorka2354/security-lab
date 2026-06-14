# HUNT: punks-terminal (Yuga Labs / Lightyear "Stash") -- CryptoPunks trading terminal

- Frontend: https://punks.lightyear.build/stash  (Next.js; product = "Stash" by Yuga Labs / Lightyear)
- Bounty: ~$1M (Immunefi-class). Author tag in source: "Yuga Labs", security-contact security@yugalabs.io.
- Chain: ethereum mainnet.

## REACH (done) -- via frontend bundle -> on-chain -> Sourcify (FULL verified source)
- STASH_FACTORY  = 0x000000000000A6fA31F5fC51c1640aAc76866750  (ACTIVE, code=3974B, currentVersion=1)
    - Solady-modified ERC1967Factory; deterministic CREATE2 per owner (salt = owner<<96 | const).
    - deployStash(owner) permissionless; addVersion/setAuction role-gated (OwnableRoles).
- STASH IMPLEMENTATION = 0x00000000000060D035a8002956B5fb02e3968eec  (code=12540B; v1)
    - activity.py = DORMANT but that's EXPECTED: it's the logic impl behind proxies; funds/events live
      in per-owner proxy clones (delegatecall). System IS live (factory active, impl wired).
- Source clone: hunts/_volume/fanout-punks-terminal/impl/src/Stash.sol (758 LOC) + interfaces.
- Constructor wires: factory, WETH(0xC02a..), CryptoPunks(0xb47e3cd8..), LegacyWrappedPunks(0xb7f7f6..),
  CryptoPunks721, PunkTransferHelper.

## TRIAGE
- forkdrift: NO audited base matched -> greenfield/original. No audit evidence in repo (likely PRIVATELY
  audited given Yuga + $1M, no public report found).
- recon [!]: initialize() ungated (but guarded by _initialized flag -> FP), 2x unchecked-ERC20-return
  (withdrawERC721 uses raw transferFrom on an IERC721 -> not an ERC20 FP; _swapWETH uses raw WETH
  transferFrom -> WETH reverts on failure, low sev). The real surface is the bid/liquidity economics, not recon hits.

## MODEL
Per-user Stash (immutable owner) holds ETH/WETH/ERC20 + Punks. Two independent reservation systems on the
same ETH balance:
  (a) auction ORDERS: placeOrder/processOrder, locked via paymentTokenToOrders + _totalLockedAndStaleBids;
      caller must be a factory-whitelisted auction; tx.origin==owner on placeOrder.
  (b) signed PUNK BIDS: processPunkBid -- EIP-712(owner sig) + optional Merkle set + accountNonce/bidNonce;
      for UNWRAPPED listed punks ANYONE can be the filler (MEV), paid (bidPrice - minValue); tops up ETH
      shortfall by pulling owner WETH via _swapWETH up to owner's WETH allowance.

## LEADS (concrete, for deep-dive)
1. [HIGH] processPunkBid filler economics (L293-405): availableETH snapshotted once; _swapWETH top-up pulls
   owner WETH (allowance-bounded); amountDueToCaller=bidPrice-minValue paid to arbitrary msg.sender.
   Owner signed only bidPrice+merkle. Verify a malicious filler / self-listed cheap punk / minValue
   manipulation can't extract > owner's intended bidPrice, and WETH top-up can't over-pull across bids.
2. [HIGH] Two reservation systems share one ETH balance. processPunkBid subtracts auction-order locks via
   availableLiquidity(0) but then tops up from WETH; placeOrder/withdraw use the same locks. Model whether
   an open auction order + a signed punk bid lets total committed exceed balance (double-spend/over-withdraw).
3. [MED] Multi-use nonce: punkBidNonceUsesRemaining seeded from order.numberOfUnits-1 on first use; check
   no replay buys > numberOfUnits, and usedPunkBidNonces vs usesRemaining can't desync (cancelPunkBid sets
   used=true but leaves usesRemaining != 0).
4. [MED] _swapWETH(L631-649): WETH availableLiquidity includes Stash's own WETH that may be locked by a
   WETH-denominated order; ensure unwrap/withdraw of WETH doesn't free WETH reserved for a separate order.

## GATE
LIVE: yes (factory ACTIVE, v1 impl deployed & wired, holds user funds in per-owner proxies).
Verdict: DIG (greenfield, live, novel fund-holding bid engine, concrete economic leads). Care: likely
privately audited -> bar is high; focus the deep-dive on the two reservation-systems interaction (#1/#2).
