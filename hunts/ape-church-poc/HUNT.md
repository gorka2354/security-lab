# Ape Church (ApeChain on-chain casino) — gaming warm-up + concurrency model

DefiLlama "Ape Church" (Luck Games, ApeChain chainid 33139). A House bankroll vault + ~20 luck games
(SpeedCrash, Roulette, Plinko, VideoPoker, ScratchCard, BananaWheel, ...). No bounty -> learning/disclosure track.

## Read (House 0x2054709F.. + SpeedCrash 0x5B44Ce34..)
- House = reflection bankroll vault (totalSupply=balance, shares=internal/total*balance). First-depositor
  inflation guarded by `require(nToMint>0)`. payout/houseProfit are `onlyGame nonReentrant`. Withdrawals
  pause while `resolutionsPending>0`. Competent.
- Randomness = Chainlink VRF, proper 2-step request->callback. Outcome only in fulfillRandomWords (not in play()).
- SpeedCrash = provably-fair crash: target locked at bet, crash=(1-edge)/(1-e) from VRF, bet-size capped by
  `potentialProfit <= house.maxPayout()` (SpeedCrash:585). Math correct. No player "обход" found.

## Concurrency angle — MODELED (test/Concurrency.t.sol), verdict: DEFENDED (not a vuln)
- Hypothesis: bet-time check is per-bet against the FULL balance; N concurrent max bets could collectively
  exceed the bankroll and drain/DoS the house when many win.
- Foundry model (faithful accounting): NAIVE (no payout re-cap) drains 100->0 and reverts winner #51 (DoS).
  REAL House RE-CAPS at payout time `sendAmount = min(value, balance*maxPayoutPerGame/FEE_DENOM)` (House.sol:844)
  -> payouts geometrically decay (first 2.0 -> last 0.61 ether), house NEVER insolvent / never reverts.
- Lesson: the bet-time check alone is insufficient; the load-bearing defense is the payout-time re-cap.
  Residual: concurrent winners are underpaid vs bet-time expectation = intended current-capacity cap.

Ledger: ape-church-house concurrency-maxpayout-aggregation = fp (defended).
