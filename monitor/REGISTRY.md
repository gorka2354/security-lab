# Target registry  (189 triaged protocols)  -- generated 2026-09-26

> Auto-derived by `toolkit/registry.py` from the ledger + fan-out tables (+ HUNT addresses).
> Pure projection (re-derive every run; never hand-edit). `radar.py` watches the live + non-SKIP rows.

## By status
- **REAL**: 19
- **DIG**: 46
- **CLEAN**: 124

## Fork-base index  (one upstream CVE -> re-scan all of these)
- **uniswap** (6): autorange-vaultfactory-0x93590F9a, krystal-community-vault-lpStrategy-0x851ee187bc85152708d38a421d48733f1490a8e3, krystal-shared-vault, krystal-sharedvault-v4, magicswap, sakuraswap
- **curve** (5): curve-llamalend-v2, luxmarket, predix-plinko, pulso-market, rdmbtc/puls-primitives
- **aave** (5): Kona Lend, RealT RMM Marketplace V2, Vena Finance, Zentra Finance, realt-rmm-v2
- **liquity** (4): Flex, mezo-borrow, mezo-musd, stockfi
- **compound** (4): capyfi, ledgity, venus-flux, wstgbp
- **morpho** (3): longbow, morpho-midnight, stakelink
- **lagoon** (2): rocksolid, syntropia
- **yearn** (1): SuperEarn
- **euler** (1): Twyne
- **velodrome** (1): Aborean
- **hyperlane** (1): Dango Bridge
- **m^0** (1): nerona

## Radar shortlist  (DIG/PARK/REAL or has live addresses): 72

| status | target | zones | chains | fork-base | owasp | addrs | sources |
|---|---|---|---|---|---|---|---|
| REAL | clawking | nft | opbnb,polygon | - | - | 1 | ledger |
| REAL | dealers-sh | nft | - | - | - | 4 | ledger |
| REAL | ea-finance-staking-wcc | staking | bsc | - | - | - | ledger |
| REAL | equivaults | oracle | eth,fantom,polygon | - | SC02,SC10 | - | ledger |
| REAL | gigaverse | - | - | - | - | 1 | immunefi,ledger |
| REAL | head2head-monkebet | - | apechain | - | - | - | ledger |
| REAL | heavy-helms | - | - | - | - | - | ledger |
| REAL | hoodbet-fun | yield | robinhood | - | - | 1 | ledger |
| REAL | krystal-community-vault-0xff630c5d | vault | arb,bsc,eth | - | SC01 | - | ledger |
| REAL | liquihood | - | - | - | - | 3 | ledger |
| REAL | luxmarket | oracle | xlayer | curve | - | 1 | ledger |
| REAL | pmarket-ctfexchange | - | polygon | - | - | - | ledger |
| REAL | pulso-market | - | amoy | curve | - | - | ledger |
| REAL | realt-rmm-v2 | - | gnosis | aave | SC10 | - | ledger |
| REAL | risex-oracle-hardening | oracle | - | - | SC02 | - | ledger |
| REAL | tartswap-lpfarmv3 | - | - | - | - | - | ledger |
| REAL | the-arbiter-arena | - | monad-testnet | - | - | - | ledger |
| REAL | wager-chess-fenestbuc | gamefi | monad-testnet | - | SC01,SC03 | - | ledger |
| REAL | witty-arcade | - | abstract,eth | - | - | - | defillama,ledger |
| DIG | ape-church | - | apechain | - | - | - | ledger |
| DIG | arcis-core | - | - | - | - | - | ledger |
| DIG | arcus-perps | dex,perp | robinhood | - | - | - | ledger |
| DIG | artosphere-discoverystaking | staking | - | - | SC04 | - | ledger |
| DIG | centrifuge | - | - | - | SC01,SC03 | - | ledger |
| DIG | clash-jayteemoney | - | - | - | - | - | ledger |
| DIG | death-fun | gambling | abstract | - | - | 2 | defillama,fanout,ledger |
| DIG | dtrinity | oracle | - | - | SC02,SC05 | - | contest,ledger |
| DIG | eva-markets | bridge,credit,gamefi | eth | - | - | 6 | defillama,fanout,ledger |
| DIG | Everything | dex,lending,oracle | arb,bsc,eth | - | SC02,SC05 | - | defillama,fanout,ledger |
| DIG | everything-inc | dex,lending,oracle | arb | - | - | - | ledger |
| DIG | Flex | lending | - | liquity | - | - | fanout,ledger |
| DIG | GigaJuiceSystem | gamefi | - | - | - | - | fanout,ledger |
| DIG | ImportExportSystem | gamefi | - | - | - | - | fanout,ledger |
| DIG | katana-perps | perp | katana | - | - | - | ledger |
| DIG | Kona Lend | lending | abstract | aave | SC02 | - | defillama,fanout,ledger |
| DIG | krystal-community-vault-lpStrategy | vault | eth | uniswap | - | - | ledger |
| DIG | lazy | gamefi,vault,yield | eth | - | - | - | defillama,fanout,ledger |
| DIG | levr-bet | - | monad | - | - | 6 | ledger |
| DIG | LiveArt/VestingStrategy | - | bsc | - | - | - | ledger |
| DIG | meridian-perps | oracle,perp | robinhood | - | - | - | ledger |
| DIG | mezo-borrow | cdp,gamefi,lending | - | liquity | - | - | defillama,fanout,ledger |
| DIG | mezo-musd | - | - | liquity | SC01,SC03 | - | fanout,ledger |
| DIG | Monolith Market | cdp,stablecoin,vault | eth | - | SC03 | - | fanout,ledger |
| DIG | narbet-casino | - | monad | - | - | - | ledger |
| DIG | narbet-monad | - | monad | - | - | - | defillama,ledger |
| DIG | native-credit | credit,vault | - | - | SC01,SC03 | - | ledger |
| DIG | panoptic-v2 | dex | eth | - | - | - | defillama,ledger |
| DIG | perpl-exchange-monad | - | monad | - | - | - | ledger |
| DIG | perpl-monad | perp | monad | - | - | - | ledger |
| DIG | punks-terminal | gamefi | eth | - | - | 2 | defillama,fanout,ledger |
| DIG | R25 / Lazy Protocol -- LazyUSDVaul | gamefi,vault | eth | - | - | - | defillama,fanout,ledger |
| DIG | RealT RMM Marketplace V2 | - | gnosis | aave | - | - | defillama,fanout,ledger |
| DIG | RedeemSystem | gamefi | - | - | - | - | fanout,ledger |
| DIG | rho-x-lp-vault | rwa,vault | - | - | SC05 | - | ledger |
| DIG | risex | oracle | - | - | SC01 | 1 | ledger |
| DIG | royco-v2 | credit,oracle | arb,eth | - | SC01,SC02 | 1 | defillama,ledger |
| DIG | Rysk Premium | perp,yield | arb | - | - | - | defillama,fanout,immunefi |
| DIG | rysk-premium-vault-registry | vault | arb,eth,hyperliquid | - | - | - | defillama,ledger |
| DIG | SparkDEX stFLR | index,staking,vault | - | - | - | - | defillama,fanout,ledger |
| DIG | stockfi | cdp | bsc | liquity | - | - | ledger |
| DIG | SuperEarn | bridge,vault,yield | kaia | yearn | - | - | defillama,fanout,ledger |
| DIG | Tizi | oracle,stablecoin,staking | - | - | - | 1 | fanout,ledger |
| DIG | Twyne | credit,index,lending | - | euler | SC02,SC03,SC05 | - | defillama,fanout,immunefi |
| DIG | witty | - | abstract | - | - | - | defillama,fanout,ledger |
| DIG | Zentra Finance | lending,stablecoin | btc,citrea | aave | - | - | defillama,fanout,ledger |
| CLEAN | fake-world-assets-v2 | oracle | eth | - | - | 9 | defillama,ledger |
| CLEAN | ledgity | - | - | compound | SC05 | 1 | ledger |
| CLEAN | longbow | oracle,vault | robinhood | morpho | - | 7 | ledger |
| CLEAN | maseer-one-wstgbp | oracle,rwa | arb,eth | - | - | 1 | ledger |
| CLEAN | predix-plinko | vault | arb | curve | - | 7 | ledger |
| CLEAN | rocksolid | vault | - | lagoon | - | 1 | ledger |
| CLEAN | stakelink | stablecoin | - | morpho | SC01,SC02 | 4 | ledger |

## Full inventory (by status)

| status | target | zones | chains | fork-base | entries | first | last |
|---|---|---|---|---|---|---|---|
| REAL | clawking | nft | opbnb,polygon | - | 1 | 2026-08-21 | 2026-08-21 |
| REAL | dealers-sh | nft | - | - | 1 | 2026-08-23 | 2026-08-23 |
| REAL | ea-finance-staking-wcc | staking | bsc | - | 2 | 2026-08-15 | 2026-08-15 |
| REAL | equivaults | oracle | eth,fantom | - | 1 | 2026-08-15 | 2026-08-15 |
| REAL | gigaverse | - | - | - | 1 | 2026-06-15 | 2026-09-26 |
| REAL | head2head-monkebet | - | apechain | - | 1 | 2026-08-21 | 2026-08-21 |
| REAL | heavy-helms | - | - | - | 1 | 2026-06-11 | 2026-06-11 |
| REAL | hoodbet-fun | yield | robinhood | - | 1 | 2026-08-21 | 2026-08-21 |
| REAL | krystal-community-vault-0xff630c5d | vault | arb,bsc | - | 2 | 2026-08-15 | 2026-08-15 |
| REAL | liquihood | - | - | - | 1 | 2026-08-22 | 2026-08-23 |
| REAL | luxmarket | oracle | xlayer | curve | 1 | 2026-08-21 | 2026-08-21 |
| REAL | pmarket-ctfexchange | - | polygon | - | 1 | 2026-08-25 | 2026-08-25 |
| REAL | pulso-market | - | amoy | curve | 2 | 2026-08-22 | 2026-08-26 |
| REAL | realt-rmm-v2 | - | gnosis | aave | 2 | 2026-08-28 | 2026-08-28 |
| REAL | risex-oracle-hardening | oracle | - | - | 1 | 2026-08-25 | 2026-08-25 |
| REAL | tartswap-lpfarmv3 | - | - | - | 1 | 2026-08-26 | 2026-08-26 |
| REAL | the-arbiter-arena | - | monad-testnet | - | 1 | 2026-08-22 | 2026-08-22 |
| REAL | wager-chess-fenestbuc | gamefi | monad-testnet | - | 2 | 2026-07-10 | 2026-09-26 |
| REAL | witty-arcade | - | abstract,eth | - | 1 | 2026-08-22 | 2026-08-22 |
| DIG | ape-church | - | apechain | - | 1 | 2026-07-01 | 2026-07-01 |
| DIG | arcis-core | - | - | - | 1 | 2026-08-26 | 2026-08-26 |
| DIG | arcus-perps | dex,perp | robinhood | - | 1 | 2026-08-25 | 2026-08-25 |
| DIG | artosphere-discoverystaking | staking | - | - | 1 | 2026-08-28 | 2026-08-28 |
| DIG | centrifuge | - | - | - | 7 | 2026-06-09 | 2026-08-14 |
| DIG | clash-jayteemoney | - | - | - | 1 | 2026-08-23 | 2026-08-23 |
| DIG | death-fun | gambling | abstract | - | 2 | 2026-06-14 | 2026-06-15 |
| DIG | dtrinity | oracle | - | - | 5 | 2026-06-09 | 2026-08-14 |
| DIG | eva-markets | bridge,credit,gamefi | eth | - | 3 | 2026-06-13 | 2026-08-14 |
| DIG | Everything | dex,lending,oracle | arb,bsc | - | 4 | 2026-06-27 | 2026-08-15 |
| DIG | everything-inc | dex,lending,oracle | arb | - | 1 | 2026-08-25 | 2026-08-25 |
| DIG | Flex | lending | - | liquity | 2 | 2026-06-14 | 2026-06-14 |
| DIG | GigaJuiceSystem | gamefi | - | - | 1 | 2026-06-15 | 2026-06-15 |
| DIG | ImportExportSystem | gamefi | - | - | 1 | 2026-06-15 | 2026-06-15 |
| DIG | katana-perps | perp | katana | - | 2 | 2026-08-22 | 2026-08-23 |
| DIG | Kona Lend | lending | abstract | aave | 2 | 2026-06-14 | 2026-06-15 |
| DIG | krystal-community-vault-lpStrategy | vault | eth | uniswap | 1 | 2026-08-15 | 2026-08-15 |
| DIG | lazy | gamefi,vault,yield | eth | - | 2 | 2026-06-13 | 2026-07-01 |
| DIG | levr-bet | - | monad | - | 1 | 2026-09-26 | 2026-09-26 |
| DIG | LiveArt/VestingStrategy | - | bsc | - | 1 | 2026-06-14 | 2026-06-14 |
| DIG | meridian-perps | oracle,perp | robinhood | - | 1 | 2026-08-22 | 2026-09-26 |
| DIG | mezo-borrow | cdp,gamefi,lending | - | liquity | 3 | 2026-06-13 | 2026-08-14 |
| DIG | mezo-musd | - | - | liquity | 7 | 2026-06-10 | 2026-08-14 |
| DIG | Monolith Market | cdp,stablecoin,vault | eth | - | 2 | 2026-06-14 | 2026-06-14 |
| DIG | narbet-casino | - | monad | - | 1 | 2026-08-22 | 2026-08-22 |
| DIG | narbet-monad | - | monad | - | 1 | 2026-08-22 | 2026-08-22 |
| DIG | native-credit | credit,vault | - | - | 4 | 2026-06-10 | 2026-08-14 |
| DIG | panoptic-v2 | dex | eth | - | 1 | 2026-06-28 | 2026-06-28 |
| DIG | perpl-exchange-monad | - | monad | - | 1 | 2026-08-15 | 2026-08-15 |
| DIG | perpl-monad | perp | monad | - | 1 | 2026-08-25 | 2026-08-25 |
| DIG | punks-terminal | gamefi | eth | - | 2 | 2026-06-13 | 2026-08-14 |
| DIG | R25 / Lazy Protocol -- LazyUSDVaul | gamefi,vault | eth | - | 1 | 2026-06-13 | 2026-06-13 |
| DIG | RealT RMM Marketplace V2 | - | gnosis | aave | 1 | 2026-08-28 | 2026-08-28 |
| DIG | RedeemSystem | gamefi | - | - | 1 | 2026-06-15 | 2026-06-15 |
| DIG | rho-x-lp-vault | rwa,vault | - | - | 1 | 2026-08-15 | 2026-08-15 |
| DIG | risex | oracle | - | - | 3 | 2026-08-25 | 2026-08-25 |
| DIG | royco-v2 | credit,oracle | arb,eth | - | 3 | 2026-06-09 | 2026-06-09 |
| DIG | Rysk Premium | perp,yield | arb | - | 1 | 2026-06-27 | 2026-06-27 |
| DIG | rysk-premium-vault-registry | vault | arb,eth | - | 1 | 2026-08-15 | 2026-08-15 |
| DIG | SparkDEX stFLR | index,staking,vault | - | - | 1 | 2026-08-28 | 2026-08-28 |
| DIG | stockfi | cdp | bsc | liquity | 1 | 2026-08-22 | 2026-08-22 |
| DIG | SuperEarn | bridge,vault,yield | kaia | yearn | 2 | 2026-08-28 | 2026-08-28 |
| DIG | Tizi | oracle,stablecoin,staking | - | - | 4 | 2026-06-14 | 2026-09-26 |
| DIG | Twyne | credit,index,lending | - | euler | 7 | 2026-06-26 | 2026-06-26 |
| DIG | witty | - | abstract | - | 2 | 2026-06-14 | 2026-06-15 |
| DIG | Zentra Finance | lending,stablecoin | btc,citrea | aave | 2 | 2026-08-28 | 2026-08-28 |
| CLEAN | 1sec | bridge | - | - | 1 | 2026-06-27 | 2026-06-27 |
| CLEAN | Aborean | dex,stablecoin | abstract | velodrome | 1 | 2026-06-15 | 2026-06-15 |
| CLEAN | AccountSystem | gamefi | - | - | 1 | 2026-06-15 | 2026-06-15 |
| CLEAN | acre | - | - | - | 1 | 2026-06-09 | 2026-06-09 |
| CLEAN | alchemix-v3 | index | - | - | 2 | 2026-06-09 | 2026-06-09 |
| CLEAN | Alvara | - | - | - | 1 | 2026-06-14 | 2026-06-14 |
| CLEAN | ammalgam | - | - | - | 1 | 2026-08-15 | 2026-08-15 |
| CLEAN | ammalgam-vaults | - | - | - | 1 | 2026-08-15 | 2026-08-15 |
| CLEAN | Ample | gamefi | - | - | 1 | 2026-06-13 | 2026-06-13 |
| CLEAN | ample-money | savings | - | - | 1 | 2026-08-25 | 2026-08-25 |
| CLEAN | Antarctic Exchange | dex,perp | arb | - | 1 | 2026-06-26 | 2026-06-26 |
| CLEAN | ape-church-deathfun | - | apechain,eth | - | 1 | 2026-07-01 | 2026-07-01 |
| CLEAN | ape-church-house | - | - | - | 1 | 2026-06-27 | 2026-06-27 |
| CLEAN | apiary-berachain | - | - | - | 1 | 2026-06-14 | 2026-06-14 |
| CLEAN | apriori-aprmon | vault | monad | - | 2 | 2026-08-15 | 2026-08-25 |
| CLEAN | Arc AgentForge Protocol | - | - | - | 1 | 2026-08-28 | 2026-08-28 |
| CLEAN | Archiel Finance | - | - | - | 1 | 2026-08-28 | 2026-08-28 |
| CLEAN | Artosphere | prediction | - | - | 1 | 2026-08-28 | 2026-08-28 |
| CLEAN | astro-fun-crashgame | vault | robinhood | - | 1 | 2026-08-25 | 2026-08-25 |
| CLEAN | autorange-vaultfactory-0x93590F9a | - | arb | uniswap | 1 | 2026-08-15 | 2026-08-15 |
| CLEAN | avalon-superearn | gamefi,vault | eth | - | 1 | 2026-06-13 | 2026-06-13 |
| CLEAN | avocado-fund | - | arb | - | 1 | 2026-08-26 | 2026-08-26 |
| CLEAN | azverse-perps-assetvault | perp,vault | arb | - | 1 | 2026-08-15 | 2026-08-15 |
| CLEAN | Boar Finance | yield | - | - | 1 | 2026-06-27 | 2026-06-27 |
| CLEAN | Caldera | - | robinhood | - | 1 | 2026-08-28 | 2026-08-28 |
| CLEAN | cambria-duelarena | - | abstract | - | 1 | 2026-06-15 | 2026-06-15 |
| CLEAN | cap | - | - | - | 1 | 2026-06-08 | 2026-06-08 |
| CLEAN | capyfi | oracle | eth | compound | 1 | 2026-06-30 | 2026-09-26 |
| CLEAN | chisino-megaeth | lottery,stablecoin | megaeth,robinhood | - | 1 | 2026-08-22 | 2026-08-22 |
| CLEAN | Citrea Bridge | bridge | citrea,eth | - | 1 | 2026-06-26 | 2026-06-26 |
| CLEAN | curve-llamalend-v2 | lending,vault | op | curve | 1 | 2026-08-17 | 2026-08-17 |
| CLEAN | Dango Bridge | bridge | eth | hyperlane | 1 | 2026-06-26 | 2026-06-26 |
| CLEAN | darkforest | - | - | - | 3 | 2026-06-09 | 2026-06-09 |
| CLEAN | dreusd | bridge,nft | - | - | 7 | 2026-06-09 | 2026-06-09 |
| CLEAN | Edel | lending | - | - | 1 | 2026-06-14 | 2026-06-14 |
| CLEAN | enhanced-finance | vault | eth | - | 1 | 2026-08-17 | 2026-08-17 |
| CLEAN | etherorcs | - | polygon | - | 5 | 2026-06-09 | 2026-06-09 |
| CLEAN | fake-wall-street | - | robinhood | - | 1 | 2026-08-22 | 2026-08-22 |
| CLEAN | fake-wall-street-fws | lottery | robinhood | - | 1 | 2026-08-22 | 2026-08-22 |
| CLEAN | fake-world-assets-v2 | oracle | eth | - | 1 | 2026-09-26 | 2026-09-26 |
| CLEAN | FedeMolteni/forecast | oracle | - | - | 1 | 2026-08-22 | 2026-08-22 |
| CLEAN | flip-battle | credit,gamefi | - | - | 1 | 2026-06-13 | 2026-06-13 |
| CLEAN | fluid-dex-v2 | dex,lending,oracle | - | - | 2 | 2026-08-15 | 2026-08-15 |
| CLEAN | gacha | nft,prediction | abstract | - | 1 | 2026-06-15 | 2026-06-15 |
| CLEAN | GAIB | lending,rwa,staking | - | - | 1 | 2026-06-26 | 2026-06-26 |
| CLEAN | gigaverse-PetRacingSystem-0x0BA76C | - | abstract | - | 1 | 2026-06-15 | 2026-06-15 |
| CLEAN | gigaverse-RandomSystem-2741-0x7b5b | - | - | - | 1 | 2026-06-15 | 2026-06-15 |
| CLEAN | helm-arc | - | - | - | 1 | 2026-08-26 | 2026-08-26 |
| CLEAN | hyperbeat-liquid-bank | gamefi | - | - | 1 | 2026-06-13 | 2026-06-13 |
| CLEAN | Hyperbeat USD | lending,rwa,stablecoin | hyperevm | - | 2 | 2026-06-27 | 2026-08-17 |
| CLEAN | Ignition LST | staking | - | - | 1 | 2026-06-27 | 2026-06-27 |
| CLEAN | ItemMarketSystem | gamefi | - | - | 1 | 2026-06-15 | 2026-06-15 |
| CLEAN | justlend-v2 | lending | - | - | 1 | 2026-06-28 | 2026-06-28 |
| CLEAN | K613 | lending,staking | - | - | 1 | 2026-06-14 | 2026-06-14 |
| CLEAN | krystal-shared-vault | vault | arb,bsc | uniswap | 1 | 2026-08-15 | 2026-08-15 |
| CLEAN | krystal-sharedvault-v4 | vault | arb | uniswap | 1 | 2026-08-15 | 2026-08-15 |
| CLEAN | krystal-sharedvault-v4-strategy/0x | vault | - | - | 1 | 2026-08-15 | 2026-08-15 |
| CLEAN | ledgity | - | - | compound | 2 | 2026-06-09 | 2026-06-13 |
| CLEAN | lisAster | yield | - | - | 1 | 2026-06-14 | 2026-06-14 |
| CLEAN | lisAster:0xFceB31A79F71AC9CBDCF853 | yield | - | - | 1 | 2026-06-14 | 2026-06-14 |
| CLEAN | lista-rwa-0xFceB31A79F71AC9CBDCF85 | rwa,vault | bsc,eth | - | 1 | 2026-08-15 | 2026-08-15 |
| CLEAN | LiveArt | rwa | - | - | 1 | 2026-06-14 | 2026-06-14 |
| CLEAN | longbow | oracle,vault | robinhood | morpho | 1 | 2026-09-26 | 2026-09-26 |
| CLEAN | Lorenzo sUSD1+ | stablecoin,vault,yield | - | - | 1 | 2026-06-27 | 2026-06-27 |
| CLEAN | loreum-chamber | - | - | - | 2 | 2026-06-11 | 2026-06-11 |
| CLEAN | magicswap | vault | - | uniswap | 4 | 2026-06-09 | 2026-06-09 |
| CLEAN | mantle-index-four | gamefi,index | mantle | - | 1 | 2026-06-13 | 2026-06-13 |
| CLEAN | mantle-index-four-fund | index,rwa | mantle | - | 1 | 2026-06-16 | 2026-06-16 |
| CLEAN | maseer-one-wstgbp | oracle,rwa | arb,eth | - | 1 | 2026-08-21 | 2026-09-26 |
| CLEAN | mellow | - | - | - | 1 | 2026-06-09 | 2026-06-09 |
| CLEAN | meridian-predict | vault | robinhood | - | 2 | 2026-08-17 | 2026-08-17 |
| CLEAN | Mezo Vaults | vault,yield | - | - | 1 | 2026-06-27 | 2026-06-27 |
| CLEAN | mezo-vaults-smusd | index,savings,yield | - | - | 1 | 2026-08-25 | 2026-08-25 |
| CLEAN | mini-7575-vault | vault | - | - | 1 | 2026-08-26 | 2026-08-26 |
| CLEAN | morpho-midnight | index,oracle | - | morpho | 2 | 2026-08-15 | 2026-08-25 |
| CLEAN | myriad-markets | prediction | abstract | - | 1 | 2026-06-15 | 2026-06-15 |
| CLEAN | nerona | - | - | m^0 | 2 | 2026-06-10 | 2026-06-10 |
| CLEAN | onchain-heroes | - | - | - | 1 | 2026-09-26 | 2026-09-26 |
| CLEAN | PetRacingSystem | gamefi | - | - | 1 | 2026-06-15 | 2026-06-15 |
| CLEAN | pharaoh-dlmm | - | avax | - | 1 | 2026-06-28 | 2026-06-28 |
| CLEAN | plinth | - | - | - | 1 | 2026-08-28 | 2026-08-28 |
| CLEAN | posi-vaults | staking | - | - | 2 | 2026-06-13 | 2026-06-13 |
| CLEAN | PRED | prediction | - | - | 1 | 2026-06-14 | 2026-06-14 |
| CLEAN | predix-plinko | vault | arb | curve | 1 | 2026-09-26 | 2026-09-26 |
| CLEAN | predmart | lending,vault | polygon | - | 1 | 2026-08-21 | 2026-08-21 |
| CLEAN | RandomSystem | gamefi | - | - | 1 | 2026-06-15 | 2026-06-15 |
| CLEAN | rdmbtc/puls-primitives | - | - | curve | 2 | 2026-08-22 | 2026-08-22 |
| CLEAN | reserve | - | - | - | 1 | 2026-06-07 | 2026-06-07 |
| CLEAN | revert-lend | lending | - | - | 1 | 2026-06-10 | 2026-06-10 |
| CLEAN | riccati-finance | lending | - | - | 1 | 2026-08-26 | 2026-08-26 |
| CLEAN | rocksolid | vault | - | lagoon | 2 | 2026-06-09 | 2026-06-09 |
| CLEAN | royco-day | oracle | - | - | 1 | 2026-08-15 | 2026-08-15 |
| CLEAN | rujira-money-market | credit,lending,vault | abstract | - | 1 | 2026-08-17 | 2026-08-17 |
| CLEAN | RushBase | oracle,prediction | - | - | 1 | 2026-08-28 | 2026-08-28 |
| CLEAN | rysk-ciao | - | - | - | 1 | 2026-06-27 | 2026-06-27 |
| CLEAN | sakuraswap | dex | abstract,zksync | uniswap | 1 | 2026-06-15 | 2026-06-15 |
| CLEAN | sodax-spoke-assetmanager-0x39E77f8 | bridge | eth | - | 1 | 2026-08-15 | 2026-08-15 |
| CLEAN | SoDEX Bridge / SoSoValue SSI Proto | bridge,dex,index | - | - | 1 | 2026-06-26 | 2026-06-26 |
| CLEAN | solo-ascend | gamefi | - | - | 1 | 2026-06-13 | 2026-06-13 |
| CLEAN | spaceship-aviator-crash | - | - | - | 1 | 2026-06-17 | 2026-06-17 |
| CLEAN | stakelink | stablecoin | - | morpho | 6 | 2026-06-05 | 2026-06-05 |
| CLEAN | stakewise | - | eth | - | 6 | 2026-06-07 | 2026-06-07 |
| CLEAN | stobox | - | eth | - | 2 | 2026-06-09 | 2026-06-09 |
| CLEAN | strato | cdp,gamefi,stablecoin | - | - | 1 | 2026-06-13 | 2026-06-13 |
| CLEAN | syntropia | yield | - | lagoon | 1 | 2026-06-10 | 2026-06-10 |
| CLEAN | tartswap | - | bsc | - | 1 | 2026-08-26 | 2026-08-26 |
| CLEAN | textile-fx | dex,vault | - | - | 1 | 2026-08-15 | 2026-08-15 |
| CLEAN | textile-fx-0x225f99aaaa914d0481ef3 | - | - | - | 1 | 2026-08-15 | 2026-08-15 |
| CLEAN | the-lobster-pot | gamefi | eth,monad-testnet | - | 1 | 2026-06-13 | 2026-06-13 |
| CLEAN | The Pit | prediction | arb | - | 1 | 2026-08-28 | 2026-08-28 |
| CLEAN | townsquare-credit-vault | credit,vault | - | - | 2 | 2026-08-15 | 2026-08-15 |
| CLEAN | townsquare-loop-vaults | - | - | - | 1 | 2026-08-15 | 2026-08-15 |
| CLEAN | usual-eth0 | - | - | - | 1 | 2026-06-09 | 2026-06-09 |
| CLEAN | Valos | credit,rwa,vault | monad | - | 1 | 2026-08-28 | 2026-08-28 |
| CLEAN | vbill | lending | - | - | 2 | 2026-06-10 | 2026-06-10 |
| CLEAN | Vena Finance | credit,lending,oracle | fluent | aave | 1 | 2026-06-26 | 2026-06-26 |
| CLEAN | VendorSystem | gamefi | - | - | 1 | 2026-06-15 | 2026-06-15 |
| CLEAN | venus-flux | gamefi,lending | - | compound | 2 | 2026-06-13 | 2026-06-26 |
| CLEAN | Wise Token | staking,yield | - | - | 1 | 2026-08-28 | 2026-08-28 |
| CLEAN | wolfgame | - | - | - | 4 | 2026-06-09 | 2026-06-09 |
| CLEAN | wstgbp | lending,oracle | - | compound | 3 | 2026-08-15 | 2026-09-26 |
| CLEAN | xax-xausd-vault | vault | eth | - | 1 | 2026-08-22 | 2026-08-22 |
| CLEAN | xphere-stake | staking,vault | - | - | 1 | 2026-08-26 | 2026-08-26 |
| CLEAN | Zentory Protocol | vault | hyperevm | - | 1 | 2026-08-28 | 2026-08-28 |
