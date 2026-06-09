# HUNT: Acre (thesis/acre) -- scout v2 candidate #2

Second scout-v2 (`--source defillama`) target: Acre BTC-staking (DefiLlama Yield, audits=0, ~$3.4M TVL,
Ethereum). `stBTC` (staked-BTC ERC4626) + Bitcoin depositor/redeemer (tBTC bridge) + Mezo/Midas yield
allocators + WithdrawalQueue. By **Thesis** (the tBTC team) -> careful code expected. Clone gitignored
`hunts/_volume/acre` (19 prod .sol). PARTIAL pass (engines ran; top lead triaged; deeper threads parked).

## Triaged
- `stBTC.sol:411` PUBLIC mint/burn `[!]` -> **FP**: `burnReceipt(amount)` is a thin proxy to `repayDebt()`
  which burns the CALLER's own shares (`super._burn(msg.sender, ...)`, self-scoped) -- not "mint from
  nothing". (Thin-delegator whose target isn't mint*/burn*-named, so fix#31 didn't catch it; niche, not
  worth a detector change -- broadening would risk under-flagging real ungated mints.)
- `BitcoinDepositor(V2)` ERC4626-inflation `[!]` -> the depositor mints stBTC; stBTC is OZ ERC4626
  (virtual shares bound first-depositor inflation, as elsewhere). Low/verify.

## Threads parked (deeper pass, if pursued)
- `MezoAllocator:114` / `MidasAllocator:81` reentrancy: the yield allocators (deposit/withdraw to Mezo/Midas)
  -> verify share/asset accounting + whether attacker-reachable (likely keeper/owner-gated).
- `BitcoinDepositor:199/244`: the BTC->tBTC->stBTC deposit flow (ungated-sibling + reentrancy) -> the
  cross-chain deposit-finalization path.
- WithdrawalQueue async accounting + stBTC.totalAssets including allocated funds (donation/allocator-manip?).

## Status
Engines ran cleanly (scout v2 -> recon -> hypothesize). Top supply-integrity lead = FP. No confirmed
finding in this partial pass (Thesis-quality, audits=0 but careful). Parked the allocator/queue threads.
Primary session win remains Ledgity (the confirmed Medium). Next: deeper Acre or the next scout candidate.
