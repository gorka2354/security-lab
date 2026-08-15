# Target registry  (113 triaged protocols)  -- generated 2026-08-15

> Auto-derived by `toolkit/registry.py` from the ledger + fan-out tables (+ HUNT addresses).
> Pure projection (re-derive every run; never hand-edit). `radar.py` watches the live + non-SKIP rows.

## By status
- **REAL**: 5
- **DIG**: 28
- **CLEAN**: 80

## Fork-base index  (one upstream CVE -> re-scan all of these)
- **uniswap** (4): krystal-community-vault-lpStrategy-0x851ee187bc85152708d38a421d48733f1490a8e3, krystal-shared-vault, magicswap, sakuraswap
- **compound** (3): capyfi, ledgity, venus-flux
- **liquity** (3): Flex, mezo-borrow, mezo-musd
- **aave** (2): Kona Lend, Vena Finance
- **morpho** (2): morpho-midnight, stakelink
- **lagoon** (2): rocksolid, syntropia
- **euler** (1): Twyne
- **velodrome** (1): Aborean
- **hyperlane** (1): Dango Bridge
- **m^0** (1): nerona

## Radar shortlist  (DIG/PARK/REAL or has live addresses): 36

| status | target | zones | chains | fork-base | owasp | addrs | sources |
|---|---|---|---|---|---|---|---|
| REAL | capyfi | oracle | eth | compound | SC02 | - | immunefi,ledger |
| REAL | equivaults | oracle | eth,fantom,polygon | - | SC02,SC10 | - | ledger |
| REAL | heavy-helms | - | - | - | - | - | ledger |
| REAL | krystal-community-vault-0xff630c5d | vault | arb,bsc,eth | - | SC01 | - | ledger |
| REAL | wager-chess-fenestbuc | gamefi | eth | - | SC01,SC03 | - | ledger |
| DIG | ape-church | - | - | - | - | - | ledger |
| DIG | centrifuge | - | - | - | SC01,SC03 | - | ledger |
| DIG | death-fun | gambling | abstract,eth | - | - | 2 | defillama,fanout,ledger |
| DIG | dtrinity | oracle | - | - | SC02,SC05 | - | contest,ledger |
| DIG | eva-markets | bridge,credit,gamefi | eth | - | - | 6 | defillama,fanout,ledger |
| DIG | Everything | dex,lending,oracle | eth | - | SC02 | - | defillama,fanout,ledger |
| DIG | Flex | lending | - | liquity | - | - | fanout,ledger |
| DIG | GigaJuiceSystem | gamefi | - | - | - | - | fanout,ledger |
| DIG | gigaverse | - | - | - | - | 1 | immunefi,ledger |
| DIG | ImportExportSystem | gamefi | - | - | - | - | fanout,ledger |
| DIG | Kona Lend | lending | abstract | aave | SC02 | - | defillama,fanout,ledger |
| DIG | krystal-community-vault-lpStrategy | vault | eth | uniswap | - | - | ledger |
| DIG | lazy | gamefi,vault,yield | eth | - | - | - | defillama,fanout,ledger |
| DIG | LiveArt/VestingStrategy | - | bsc | - | - | - | ledger |
| DIG | mezo-borrow | cdp,gamefi,lending | - | liquity | - | - | defillama,fanout,ledger |
| DIG | mezo-musd | - | - | liquity | SC01,SC03 | - | fanout,ledger |
| DIG | Monolith Market | cdp,stablecoin,vault | eth | - | SC03 | - | fanout,ledger |
| DIG | native-credit | credit,vault | - | - | SC01,SC03 | - | ledger |
| DIG | panoptic-v2 | dex | eth | - | - | - | defillama,ledger |
| DIG | punks-terminal | gamefi | eth | - | - | 2 | defillama,fanout,ledger |
| DIG | R25 / Lazy Protocol -- LazyUSDVaul | gamefi,vault | eth | - | - | - | defillama,fanout,ledger |
| DIG | RedeemSystem | gamefi | - | - | - | - | fanout,ledger |
| DIG | rho-x-lp-vault | rwa,vault | - | - | SC05 | - | ledger |
| DIG | royco-v2 | credit,oracle | arb,eth | - | SC01,SC02 | 1 | defillama,ledger |
| DIG | Rysk Premium | perp,yield | arb | - | - | - | defillama,fanout,immunefi |
| DIG | Tizi | oracle,stablecoin,staking | - | - | - | 1 | fanout,ledger |
| DIG | Twyne | credit,index,lending | - | euler | SC02,SC03,SC05 | - | defillama,fanout,immunefi |
| DIG | witty | - | abstract | - | - | - | defillama,fanout,ledger |
| CLEAN | ledgity | - | - | compound | SC05 | 1 | ledger |
| CLEAN | rocksolid | vault | - | lagoon | - | 1 | ledger |
| CLEAN | stakelink | stablecoin | - | morpho | SC01,SC02 | 4 | ledger |

## Full inventory (by status)

| status | target | zones | chains | fork-base | entries | first | last |
|---|---|---|---|---|---|---|---|
| REAL | capyfi | oracle | eth | compound | 1 | 2026-06-30 | 2026-06-30 |
| REAL | equivaults | oracle | eth,fantom | - | 1 | 2026-08-15 | 2026-08-15 |
| REAL | heavy-helms | - | - | - | 1 | 2026-06-11 | 2026-06-11 |
| REAL | krystal-community-vault-0xff630c5d | vault | arb,bsc | - | 2 | 2026-08-15 | 2026-08-15 |
| REAL | wager-chess-fenestbuc | gamefi | eth | - | 2 | 2026-07-10 | 2026-07-10 |
| DIG | ape-church | - | - | - | 1 | 2026-07-01 | 2026-07-01 |
| DIG | centrifuge | - | - | - | 7 | 2026-06-09 | 2026-08-14 |
| DIG | death-fun | gambling | abstract,eth | - | 2 | 2026-06-14 | 2026-06-15 |
| DIG | dtrinity | oracle | - | - | 5 | 2026-06-09 | 2026-08-14 |
| DIG | eva-markets | bridge,credit,gamefi | eth | - | 3 | 2026-06-13 | 2026-08-14 |
| DIG | Everything | dex,lending,oracle | eth | - | 3 | 2026-06-27 | 2026-06-27 |
| DIG | Flex | lending | - | liquity | 2 | 2026-06-14 | 2026-06-14 |
| DIG | GigaJuiceSystem | gamefi | - | - | 1 | 2026-06-15 | 2026-06-15 |
| DIG | gigaverse | - | - | - | 1 | 2026-06-15 | 2026-06-15 |
| DIG | ImportExportSystem | gamefi | - | - | 1 | 2026-06-15 | 2026-06-15 |
| DIG | Kona Lend | lending | abstract | aave | 2 | 2026-06-14 | 2026-06-15 |
| DIG | krystal-community-vault-lpStrategy | vault | eth | uniswap | 1 | 2026-08-15 | 2026-08-15 |
| DIG | lazy | gamefi,vault,yield | eth | - | 2 | 2026-06-13 | 2026-07-01 |
| DIG | LiveArt/VestingStrategy | - | bsc | - | 1 | 2026-06-14 | 2026-06-14 |
| DIG | mezo-borrow | cdp,gamefi,lending | - | liquity | 3 | 2026-06-13 | 2026-08-14 |
| DIG | mezo-musd | - | - | liquity | 7 | 2026-06-10 | 2026-08-14 |
| DIG | Monolith Market | cdp,stablecoin,vault | eth | - | 2 | 2026-06-14 | 2026-06-14 |
| DIG | native-credit | credit,vault | - | - | 4 | 2026-06-10 | 2026-08-14 |
| DIG | panoptic-v2 | dex | eth | - | 1 | 2026-06-28 | 2026-06-28 |
| DIG | punks-terminal | gamefi | eth | - | 2 | 2026-06-13 | 2026-08-14 |
| DIG | R25 / Lazy Protocol -- LazyUSDVaul | gamefi,vault | eth | - | 1 | 2026-06-13 | 2026-06-13 |
| DIG | RedeemSystem | gamefi | - | - | 1 | 2026-06-15 | 2026-06-15 |
| DIG | rho-x-lp-vault | rwa,vault | - | - | 1 | 2026-08-15 | 2026-08-15 |
| DIG | royco-v2 | credit,oracle | arb,eth | - | 3 | 2026-06-09 | 2026-06-09 |
| DIG | Rysk Premium | perp,yield | arb | - | 1 | 2026-06-27 | 2026-06-27 |
| DIG | Tizi | oracle,stablecoin,staking | - | - | 3 | 2026-06-14 | 2026-06-15 |
| DIG | Twyne | credit,index,lending | - | euler | 7 | 2026-06-26 | 2026-06-26 |
| DIG | witty | - | abstract | - | 2 | 2026-06-14 | 2026-06-15 |
| CLEAN | 1sec | bridge | - | - | 1 | 2026-06-27 | 2026-06-27 |
| CLEAN | Aborean | dex,stablecoin | abstract | velodrome | 1 | 2026-06-15 | 2026-06-15 |
| CLEAN | AccountSystem | gamefi | - | - | 1 | 2026-06-15 | 2026-06-15 |
| CLEAN | acre | - | - | - | 1 | 2026-06-09 | 2026-06-09 |
| CLEAN | alchemix-v3 | index | - | - | 2 | 2026-06-09 | 2026-06-09 |
| CLEAN | Alvara | - | - | - | 1 | 2026-06-14 | 2026-06-14 |
| CLEAN | ammalgam-vaults | - | - | - | 1 | 2026-08-15 | 2026-08-15 |
| CLEAN | Ample | gamefi | - | - | 1 | 2026-06-13 | 2026-06-13 |
| CLEAN | Antarctic Exchange | dex,perp | arb | - | 1 | 2026-06-26 | 2026-06-26 |
| CLEAN | ape-church-deathfun | - | eth | - | 1 | 2026-07-01 | 2026-07-01 |
| CLEAN | ape-church-house | - | - | - | 1 | 2026-06-27 | 2026-06-27 |
| CLEAN | apiary-berachain | - | - | - | 1 | 2026-06-14 | 2026-06-14 |
| CLEAN | avalon-superearn | gamefi,vault | eth | - | 1 | 2026-06-13 | 2026-06-13 |
| CLEAN | azverse-perps-assetvault | perp,vault | arb | - | 1 | 2026-08-15 | 2026-08-15 |
| CLEAN | Boar Finance | yield | - | - | 1 | 2026-06-27 | 2026-06-27 |
| CLEAN | cambria-duelarena | - | abstract | - | 1 | 2026-06-15 | 2026-06-15 |
| CLEAN | cap | - | - | - | 1 | 2026-06-08 | 2026-06-08 |
| CLEAN | Citrea Bridge | bridge | eth | - | 1 | 2026-06-26 | 2026-06-26 |
| CLEAN | Dango Bridge | bridge | eth | hyperlane | 1 | 2026-06-26 | 2026-06-26 |
| CLEAN | darkforest | - | - | - | 3 | 2026-06-09 | 2026-06-09 |
| CLEAN | dreusd | bridge,nft | - | - | 7 | 2026-06-09 | 2026-06-09 |
| CLEAN | Edel | lending | - | - | 1 | 2026-06-14 | 2026-06-14 |
| CLEAN | etherorcs | - | polygon | - | 5 | 2026-06-09 | 2026-06-09 |
| CLEAN | flip-battle | credit,gamefi | - | - | 1 | 2026-06-13 | 2026-06-13 |
| CLEAN | gacha | nft,prediction | abstract | - | 1 | 2026-06-15 | 2026-06-15 |
| CLEAN | GAIB | lending,rwa,staking | - | - | 1 | 2026-06-26 | 2026-06-26 |
| CLEAN | gigaverse-PetRacingSystem-0x0BA76C | - | abstract | - | 1 | 2026-06-15 | 2026-06-15 |
| CLEAN | gigaverse-RandomSystem-2741-0x7b5b | - | - | - | 1 | 2026-06-15 | 2026-06-15 |
| CLEAN | hyperbeat-liquid-bank | gamefi | - | - | 1 | 2026-06-13 | 2026-06-13 |
| CLEAN | Hyperbeat USD | lending,rwa,stablecoin | hyperevm | - | 1 | 2026-06-27 | 2026-06-27 |
| CLEAN | Ignition LST | staking | - | - | 1 | 2026-06-27 | 2026-06-27 |
| CLEAN | ItemMarketSystem | gamefi | - | - | 1 | 2026-06-15 | 2026-06-15 |
| CLEAN | justlend-v2 | lending | - | - | 1 | 2026-06-28 | 2026-06-28 |
| CLEAN | K613 | lending,staking | - | - | 1 | 2026-06-14 | 2026-06-14 |
| CLEAN | krystal-shared-vault | vault | arb,bsc | uniswap | 1 | 2026-08-15 | 2026-08-15 |
| CLEAN | krystal-sharedvault-v4-strategy/0x | vault | - | - | 1 | 2026-08-15 | 2026-08-15 |
| CLEAN | ledgity | - | - | compound | 2 | 2026-06-09 | 2026-06-13 |
| CLEAN | lisAster | yield | - | - | 1 | 2026-06-14 | 2026-06-14 |
| CLEAN | lisAster:0xFceB31A79F71AC9CBDCF853 | yield | - | - | 1 | 2026-06-14 | 2026-06-14 |
| CLEAN | lista-rwa-0xFceB31A79F71AC9CBDCF85 | rwa,vault | bsc,eth | - | 1 | 2026-08-15 | 2026-08-15 |
| CLEAN | LiveArt | rwa | - | - | 1 | 2026-06-14 | 2026-06-14 |
| CLEAN | Lorenzo sUSD1+ | stablecoin,vault,yield | - | - | 1 | 2026-06-27 | 2026-06-27 |
| CLEAN | loreum-chamber | - | - | - | 2 | 2026-06-11 | 2026-06-11 |
| CLEAN | magicswap | vault | - | uniswap | 4 | 2026-06-09 | 2026-06-09 |
| CLEAN | mantle-index-four | gamefi,index | mantle | - | 1 | 2026-06-13 | 2026-06-13 |
| CLEAN | mantle-index-four-fund | index,rwa | mantle | - | 1 | 2026-06-16 | 2026-06-16 |
| CLEAN | mellow | - | - | - | 1 | 2026-06-09 | 2026-06-09 |
| CLEAN | Mezo Vaults | vault,yield | - | - | 1 | 2026-06-27 | 2026-06-27 |
| CLEAN | morpho-midnight | index,oracle | - | morpho | 1 | 2026-08-15 | 2026-08-15 |
| CLEAN | myriad-markets | prediction | abstract | - | 1 | 2026-06-15 | 2026-06-15 |
| CLEAN | nerona | - | - | m^0 | 2 | 2026-06-10 | 2026-06-10 |
| CLEAN | PetRacingSystem | gamefi | - | - | 1 | 2026-06-15 | 2026-06-15 |
| CLEAN | pharaoh-dlmm | - | avax | - | 1 | 2026-06-28 | 2026-06-28 |
| CLEAN | posi-vaults | staking | - | - | 2 | 2026-06-13 | 2026-06-13 |
| CLEAN | PRED | prediction | - | - | 1 | 2026-06-14 | 2026-06-14 |
| CLEAN | RandomSystem | gamefi | - | - | 1 | 2026-06-15 | 2026-06-15 |
| CLEAN | reserve | - | - | - | 1 | 2026-06-07 | 2026-06-07 |
| CLEAN | revert-lend | lending | - | - | 1 | 2026-06-10 | 2026-06-10 |
| CLEAN | rocksolid | vault | - | lagoon | 2 | 2026-06-09 | 2026-06-09 |
| CLEAN | rysk-ciao | - | - | - | 1 | 2026-06-27 | 2026-06-27 |
| CLEAN | sakuraswap | dex | abstract,zksync | uniswap | 1 | 2026-06-15 | 2026-06-15 |
| CLEAN | SoDEX Bridge / SoSoValue SSI Proto | bridge,dex,index | - | - | 1 | 2026-06-26 | 2026-06-26 |
| CLEAN | solo-ascend | gamefi | eth | - | 1 | 2026-06-13 | 2026-06-13 |
| CLEAN | spaceship-aviator-crash | - | - | - | 1 | 2026-06-17 | 2026-06-17 |
| CLEAN | stakelink | stablecoin | - | morpho | 6 | 2026-06-05 | 2026-06-05 |
| CLEAN | stakewise | - | eth | - | 6 | 2026-06-07 | 2026-06-07 |
| CLEAN | stobox | - | eth | - | 2 | 2026-06-09 | 2026-06-09 |
| CLEAN | strato | cdp,gamefi,stablecoin | - | - | 1 | 2026-06-13 | 2026-06-13 |
| CLEAN | syntropia | yield | - | lagoon | 1 | 2026-06-10 | 2026-06-10 |
| CLEAN | textile-fx | dex,vault | - | - | 1 | 2026-08-15 | 2026-08-15 |
| CLEAN | textile-fx-0x225f99aaaa914d0481ef3 | - | eth | - | 1 | 2026-08-15 | 2026-08-15 |
| CLEAN | the-lobster-pot | gamefi | eth,monad | - | 1 | 2026-06-13 | 2026-06-13 |
| CLEAN | townsquare-credit-vault | credit,vault | - | - | 2 | 2026-08-15 | 2026-08-15 |
| CLEAN | townsquare-loop-vaults | - | - | - | 1 | 2026-08-15 | 2026-08-15 |
| CLEAN | usual-eth0 | - | - | - | 1 | 2026-06-09 | 2026-06-09 |
| CLEAN | vbill | lending | - | - | 2 | 2026-06-10 | 2026-06-10 |
| CLEAN | Vena Finance | credit,lending,oracle | fluent | aave | 1 | 2026-06-26 | 2026-06-26 |
| CLEAN | VendorSystem | gamefi | - | - | 1 | 2026-06-15 | 2026-06-15 |
| CLEAN | venus-flux | gamefi,lending | - | compound | 2 | 2026-06-13 | 2026-06-26 |
| CLEAN | wolfgame | - | - | - | 4 | 2026-06-09 | 2026-06-09 |
