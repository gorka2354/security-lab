# Fan-out triage: fresh-defillama-wave-2  (chain multi)  2026-06-27

8 targets triaged. **TRIAGE-LEVEL** -- `top_leads` are HYPOTHESES from a shallow skim, NOT verified findings; deep L4 happens later on the DIG queue.

| target | type | chain | gate | fork/audit | rec | top leads (hypotheses) |
|---|---|---|---|---|---|---|
| Everything (UniPool engine) — DefiLlama Lending $1.1M, audits=0 | oracle,lending,amm,leverage (oracle-less tick-based AMM+lending) | multi | LIVE + very active | greenfield-custom — besp | **DIG** | Oracle-less tick price derived from AMM reserves f; Liquidation entrypoint — no self-liq guard, roundi; External-call-then-state-write with no nonReentran |
| Rysk Premium (Arbitrum) — resolved to Rysk V12 "Ciao" CLOB derivatives core | yield, options/derivatives (perp+spot CLOB margin) | multi | LIVE — Rysk V12 de | greenfield-custom — Rysk | **DIG** | Perp margin health funding-sign + int256.mul math; Taker order has NO on-chain signature check; ADL path skips both maker+taker signatures |
| Mezo Vaults (Mezo BTC L2, chainid 31612) | vault,yield | multi | DORMANT/DUST on Me | fork-of-Upshift (Atomic  | **SKIP** | ERC4626 share-price / first-depositor inflation on; Epoch vs instant-redeem buffer accounting (PPS sta |
| 1sec (onesec) ICP<->EVM message-passing bridge | bridge | multi | LIVE. Locker EOA o | greenfield-custom — chai | **SKIP** | - |
| Hyperbeat USD (hbUSDC) | HyperEVM chainid 999 | lending,stablecoin (RWA mToken / manual-priced redeemable) | multi | ACTIVE: hbUSDC tok | fork-of-Midas (RedDuck S | **SKIP** | - |
| Ignition LST (Fogo liquid staking, stake FOGO -> LST) | lst,staking | multi | LIVE-ish: Fogo mai | fork-of-SPL-Stake-Pool ( | **SKIP** | - |
| Lorenzo sUSD1+ (BTCfi yield-stable vault, BNB Chain) | yield,stablecoin,btcfi | multi | LIVE — DefiLlama $ | fork-of-Veda-Labs-Boring | **SKIP** | - |
| Boar Finance | yield | multi | LIVE: $1.06M TVL o | unknown - BoarBTCRelay i | **SKIP** | - |

## Deep-dive queue (DIG / DIG-CAREFUL) -- verify these by hand

### Everything (UniPool engine) — DefiLlama Lending $1.1M, audits=0  (DIG)
- Reachable full verified-source engine, live + very active (txns days old, $1.1M, 252k loans, 4 chains), audits=0, and a novel oracle-less tick-based AMM-lending design that sits squarely in the #1 oracle/lending zone with several concrete high-signal leads (tick-price Likwid class, liquidation 4-check, CEI reentrancy in a unified pool, vault index seed). High finding-density profile (exactly the fresh-unaudited target the engine targets). Only caveat: no confirmed in-scope bounty — must establish a disclosure channel before live testing, hence not an unconditional DIG.
  - lead: Oracle-less tick price derived from AMM reserves feeding liquidation eligibility  [src/libraries/UniPoolPairTicks.sol:131,161 (calcReserveAtPrice/calcPriceAtTick);] (?)
  - lead: Liquidation entrypoint — no self-liq guard, rounding direction, manipulable heal  [src/UniPoolPair.sol:495 ; src/libraries/UniPoolPairLiquidate.sol:54] (?)
  - lead: External-call-then-state-write with no nonReentrant across the UNIFIED pool  [src/libraries/UniPoolPairRepay.sol:73 ; UniPoolPairSwap.sol:109 ; UniPoolPairBor] (?)
  - lead: Aave-style liquidityIndex with no visible min-liquidity/seed guard on shared vau  [src/UniPoolVault.sol:205,470,478,504,524] (?)
  - lead: Internal swap with amountOutMin==0 + strict balanceOf == equality (force-feed)  [src/libraries/UniPoolPairBorrow.sol:131 (minOut=0); UniPoolPairMint.sol:106-107,] (?)

### Rysk Premium (Arbitrum) — resolved to Rysk V12 "Ciao" CLOB derivatives core  (DIG)
- Reachable full source of a LIVE, unaudited (no audit evidence in repo), in-zone derivatives core (options/perp CLOB) with an active Rysk Immunefi bounty. recon is clean (expected — bugs here are reasoning-tier margin/funding/liquidation math, not pattern-matchable). Real manual EV in MarginDirective funding-sign math + the operator-trusted taker/ADL no-signature settlement paths. Discounts: ciao addresses + bounty-scope coverage unconfirmed, and the design is operator-gated (off-chain orderbook) so callability must be proven before severity (death.fun lesson). Literal Premium vault share-math is out of reach in this repo.
  - lead: Perp margin health funding-sign + int256.mul math  [hunts/_volume/rysk-ciao/src/contracts/libraries/MarginDirective.sol:22-90 (getPe] (?)
  - lead: Taker order has NO on-chain signature check  [OrderDispatch.sol:210-212 ('we dont conduct a signature check on the taker')] (?)
  - lead: ADL path skips both maker+taker signatures  [OrderDispatch.sol:254-259 (no signature checks for ADL, 'last resort')] (?)
  - lead: Withdrawal-fee accounting on subaccount balances  [Ciao.sol:109-111 setWithdrawalFee (uncapped) + requestWithdrawal:282-296] (?)
