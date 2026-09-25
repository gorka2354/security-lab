# HUNT: fake-world-assets-v2 (FWA V2, https://www.fwa.fun) -- wave-14, 2026-09-26

Verdict: CLEAN (honest-negative) on the value-bearing core. No PoC-worthy lead survived.
Gate: LIVE-FUNDED (LIVE + ACTIVE + FUNDED). Sev: n/a.

## Phase 0 -- reach + live gate
- DefiLlama: "Fake World Assets V2", Luck Games, TVL ~$2.6M, audits=0, listed 2026-09-25, twitter token_works
  (parent#fake-world-assets; V1 also listed). DefiLlama "address" 0xa0df17b5...c845 = the FWA ERC20 token
  (DECOY; same address DefiLlama shows for "Fake Wall Street") -> real contracts from DefiLlama-Adapters
  projects/fwa-fun-v2/index.js.
- Chain: Ethereum (1). All sources verified (Sourcify / Etherscan-v2). Clones in hunts/_volume/fake-world-assets-v2/.
  | role                         | address                                    | value      |
  | FWAV2 main pool (core)       | 0x958C41181182e76F221331b2755b77D9e1426A98 | 722.3 ETH  |
  | FWAIR launch manager/registry| 0x716486a7bD6B4d7409fC4F8B52f0B23D2BcFac72 | 0          |
  |  launch #1 (FWAIRLaunchV2)   | 0xA59A249355efE20c6de666aaC43773aA1FD59De6 | 25.4 ETH   |
  | user-owned pool factory      | 0xf5a3a153164791ab579c3d9ba5dbecf7cdfd300c | 7 clones ~39.5 ETH |
  |  pool[5] FWACloneBuyback     | 0xd134029b301a820C137b5E7854bd21b83a6a7EAe | 38.24 ETH (impl 0x60661cfa46a470e0922a3b6e9998b343a3a53669) |
  |  pools 0,2,3,4,6 (standard)  | impl 0xeaa4d032...(not read)               | ~1.3 ETH   |
  | FWAV2Rewards                 | 0xA54b44C7a894AA19C49734A753D01f9B8C5f6516 | 0.14 ETH   |
  | floor oracle                 | 0xaA4D9009a4664604b57644bF13e447E9036727DC | 0          |
  | owner (FWAV2)                | 0x019817aD02a31B990433542097bE29D97613E8Cb |            |
- threat.py main pool: LIVE + ACTIVE + FUNDED (first-seen ~16d, last tx 0.0d). 37,744 acquisitions processed,
  40.5k listings, 2,579 active, acquisition fee ~0.082 ETH, crown pot 4.46 ETH (top listing 29537).
  Frontend acquire() args seen on-chain: maxFee=quote, minWeightedValue=~quote, maxNegativeSlippageBps=1000.
- Relation to fake-wall-street-fws (ledger 2026-08-22, CLEAN): same TokenWorks family (shared token address
  in DefiLlama metadata), but a DIFFERENT codebase: FWS = Pyth Entropy lootbox on Robinhood Chain; FWA V2 =
  Chainlink VRF v2.5 subscription + an ordered acquisition sequencer on Ethereum. Same hardened style.
- Bounty: programs.py match "fake world assets"/"fwa"/"tokenworks"/"fwa.fun" -> no program.

## Design (FWAV2.sol, 2700 lines)
Depositors list an ERC721 + ETH backing; selection weight = 1e36/backing (inverse); acquisition price =
EV*(1+5%) where EV = harmonic mean of backings. Purchaser pays fee+VRF fee -> Chainlink VRF word -> ordered
processor selects a listing via a sparse segment tree -> purchaser keeps NFT (backing -> depositor, -1%) or
sells it back for 90% of backing (keepNFT / acceptDepositorBid / acceptBidAsTokens / relistNFT; depositor
fallbacks after 24h; permissionless finalize after 7d). Fees split flat per active listing (accumulator) +
5% "crown" pot to the top-backed listing. Backing capped by a challenge-based floor oracle (ask*1.1).

## What I read (L4, value-moving paths)
FWAV2: listNFT/_createListing/staging+reservation, _activateListing, withdrawListing, kickListing,
updateBacking, claimTopSpot, acquire/_validateAcquisition/_openAcquisition, rawFulfillRandomWords/
fulfillRandomWords/_tryProcessCallbackHead, processAcquisitions/_settleReadyAcquisition/_finishAcquisition,
all purchaser/depositor resolutions, _deliverNFT/_transferNFT/recoverStuckNFT, withdrawEarnings/
claimListingFees/payoutFees, _distribute/_vacateTop/_settleAndRemove, tree add/remove/select, setUint/setAddr.
FWAV2Rewards: listing hooks, acquisition hooks, settleListing, token claims, epoch claims, buyFor/unlockCallback.
FWAIRLaunchV2 + FWAIRLaunchVRFConsumerV2: backer-selection RNG, receive()/payment context, _syncPosition.
FWACloneBuyback: exit lock, withdraw/updateBacking, _settleReadyAcquisition, keepNFT/acceptBuyback/auto-reload.

## Leads and fates
L1 RNG post-reveal steering (the VRF word is public -- mempool + RandomnessCached event -- before ordered
   processing; selection uses the LIVE tree) -> KILLED. unsettledAcquisitionCount is a pool-mutation lock:
   withdrawListing/updateBacking/claimTopSpot/kickListing revert WithdrawLocked, activateListings no-ops,
   new deposits/relists go to a FIFO staging queue whose batch is reserved AT REQUEST TIME (before any word
   exists). Kill-gate proven on a mainnet fork: hunts/fake-world-assets-v2/lockcheck (see Repro).
L2 re-roll by making the callback fail / time out -> KILLED. Callback is coordinator-only, caches the word
   in ~60k gas, then a failure-isolated fast path (pop(call), 700k stipend, 50k reserve); a late word ->
   TimedOut -> fee refund only (never selectable); terminal/duplicate words ignored (fork replay check).
   Deadline slip is not caller-controllable (Chainlink node timing).
L3 selective / out-of-order processing -> KILLED. Strict nextSequenceToProcess FIFO; Pending head blocks;
   Ready #2 cannot settle before #1 (fork test asserts it).
L4 stale price across sequences / count>1 / front-run staging dilution -> BY DESIGN, bounded: settlement
   re-prices; positive drift <= protocol-snapshotted 10%, negative <= purchaser's bps (frontend: 10%),
   else pull refund. Dilution needs unsettled>0, max 6 reserved per request vs 2,579 active -> immaterial.
L5 recon [!] FWAV2.sol:1504 "msg.value read INSIDE a loop" -> FP: msg.value checked once (1496) vs
   count*(fee+vrf) and refunded after the loop (1507); loop body never reads it.
L6 recon [!] 1308 updateBacking / 2017 recoverStuckNFT "UNGATED" -> FP: _activeOwned (depositor) +
   _requireExitUnlocked; stuckNFTRecipient[id]==msg.sender.
L7 recon [!] 2177 "ERC20 return ignored" + [.] 1249/2044 fee-on-transfer -> FP: ERC721 transferFrom with an
   ownerOf(tokenId)==to post-check / ERC721 safeTransferFrom.
L8 escrow solvency / double pay -> none found. Per-listing backing resolves exactly once
   (Allocated->Settled); fee split = (ownerCut-slice)+slice+distributable; accumulator floor/ceil never
   over-credits; crown pot zeroed in the same write as topListingId, paid only to the top holder.
L9 sequencer brick (would freeze all 722 ETH behind WithdrawLocked) via a reverting rewards hook -> KILLED:
   hooks revert only on broken invariants (double-activate, unknown request); accTokenPerSqrt overflow
   needs ~1e14 token events; rewards is one-time-set, trusted.
L10 FWAIR launch RNG (25.4 ETH) -> KILLED: one-shot VRF wrapper word, consumed in strict offset order,
   supporters fixed before Randomizing; settlement from an immutable FWAV2 receipt (exact amount, fail-closed).
L11 user-owned clones: owner-vs-purchaser steering -> same exit lock + inventory-version binding; buyback
   ETH is a pull credit, NFT return best-effort. Standard impl 0xeaa4d032... NOT read (~1.3 ETH) -> residual.
L12 builder self-referral (acquire(purchaser=otherWallet) earns the builder slice of the 1% protocol fee
   as an FWA buy allowance) -> incentive note, not a vuln (intended permissionless referral).
L13 crown economics (5% of distributable fees -> top-backed listing; pot 4.46 ETH live) -> by design; cap
   bypass (FWAIR / oracle-exempt) is owner-curated only (launches need owner approval + code-hash).

## Repro (kill-gate evidence, local fork only)
  source toolkit/env.sh; cd hunts/fake-world-assets-v2/lockcheck
  forge test --fork-url https://ethereum-rpc.publicnode.com -vv
  -> [PASS] test_postRevealPoolIsFrozen() (gas: 1532233)  (1 passed; pre-existing live unsettled=1 handled)

## Final
CLEAN. The system is a mature, security-conscious design (explicit anti-steering sequencer, fail-closed
receipts, pull payments). Residual unread surface: standard clone impl 0xeaa4d032..., FWAVRFService,
floor oracle internals, FWAToken/buyback (token-side), purchase notifier.
