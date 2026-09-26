# HUNT: longbow (Wave-14, 2026-09-26)

Verdict: CLEAN (well-evidenced honest-negative). LIVE-FUNDED. No PoC-able theft; residual
risks are by-design / reasoning-tier (documented below).

## Phase-0 facts
- Protocol: Longbow -- "curated lending on Robinhood Chain" (DefiLlama, category Lending,
  TVL ~$4.4M, audits=0, listed 2026-09-07). twitter longbowlend. github=none on DefiLlama.
- Chain: Robinhood Chain, chainid 4663 (0x1237), Arbitrum Orbit. RPC
  https://rpc.mainnet.chain.robinhood.com (works; block ~0x452e73d). Etherscan-v2 + Sourcify
  both serve verified source for 4663.
- DefiLlama "address" 0x451b42a15100c340ca12f7c66de06fac5ea2d751 = DECOY: it is the BOW gov
  token ("Longbow"/BOW, 18-dec, supply 1e27). Not the core.
- REAL core (resolved via DefiLlama-Adapters projects/longbow/index.js):
  - Morpho Blue singleton  0x9D53d5E3bd5E8d4Cbfa6DB1ca238AEA02E651010  (owner 0x0605..9728,
    feeRecipient = 0x0). STOCK Morpho Blue, verified (Morpho.sol 557 lines, canonical consts).
  - USDG vault (Morpho Vault V2) 0xf0eef247585b184836915e80f984246d981c55c4 (asset=USDG,
    routes to markets via MorphoMarketV1AdapterV2). Verified.
  - Loan asset USDG = "Global Dollar" 0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168, 6-dec.
- Value / liveness: Morpho singleton holds 53,192,986 USDG (shared across ~148 markets;
  Longbow curates 55, ~$4.4M slice). Treasury holds 6,001,392 USDG. Morpho activity ACTIVE,
  last tx 0.0d ago, first-seen ~127d. => LIVE-FUNDED. (threat.py printed EMPTY/PRE-LAUNCH =
  FALSE NEGATIVE: it checks the contract's own ETH/token, not custodied USDG. See toolkit bugs.)
- Audits: 0. Bounty: programs.py not checked (no finding to match).

## What this is (the drift)
Curated Morpho Blue + Morpho Vault V2 (both Morpho's own audited code) on Robinhood Chain.
The only bespoke drift is the ORACLE layer + market curation:
1. wsNET markets (WSNET, WSNET-NN) -- the $1M concentration (WSNET-NN: 1,080,520 USDG supplied /
   1,054,490 borrowed, LLTV 0.625). Bespoke NetNet (OHM-fork) oracle stack:
   - LoopbackOracle 0xCDE9599059f8Ae6D6B9F33A0aF7877827ec75F16
   - PairOracle     0x929631b33F4070D6f54477fba3FD27566567dAca (UniV2 cumulative TWAP)
   - Treasury       0x04822Ea321A0DEE6F40656172F29312104855d66 (RFV backing floor)
   All verified (Sourcify).
2. Memecoin markets (PONS/AI/INDEX/STONKBROKER/GLD/RDDT/COST/DJT/NFLX/HIMS/...): collateral
   priced by a custom "Uniswap V3 Pool Price in USD" aggregator (UNVERIFIED bytecode, codesize
   ~5207, no owner) plugged into a standard MorphoChainlinkOracleV2. Uses UniV3 observe() (TWAP),
   latestRoundData() interface, live updatedAt.
3. Stock markets (NVDA/AAPL/TSLA/SPY/...): standard MorphoChainlinkOracleV2 + RH-owned Chainlink
   push feeds (8-dec, description "RHNVDA/USD" etc, owner 0xeE27..9C52). Quote USDG/USD 8-dec.

## What I read
- LoopbackOracle.sol, PairOracle.sol, Treasury.sol (bespoke wsNET stack) -- full read.
- Morpho.sol core: function set + ConstantsLib (VIRTUAL_SHARES=1e6, LIQUIDATION_CURSOR=0.3e18,
  MAX_LIQUIDATION_INCENTIVE_FACTOR=1.15e18) = canonical Morpho Blue, UNMODIFIED.
- MorphoChainlinkOracleV2 (nvda/ai/pons/... variants: byte-identical bar a comment).
- On-chain: enumerated all 55 markets (loan/coll/oracle/irm/lltv/state), every feed's
  description/decimals/answer/age, price() scaling, pool depth for PONS.

## Leads and their fate
- L1 spot-price manipulation of memecoin feeds -> KILLED: feeds call observe() (TWAP), not
  slot0. PONS pool 0x10CC has observationCardinality=20000 + liquidity ~1.6e23 => TWAP is deep
  and costly to move/sustain across the window. Not a cheap exploit. (Feed unverified but
  bytecode has observe()=883bdbfd, no slot0=3850c7bd.)
- L2 LoopbackOracle spot manipulation -> KILLED: collateral priced at TWAP*(1-haircut) clamped
  to [floor, 5*floor]; spot (_pairPriceWad) used ONLY to fail closed (revert) when spot < 85%
  of TWAP -- never to raise credit. No upward manipulation path.
- L3 Treasury backing-floor inflation -> KILLED (economically): polRfv uses 2*sqrt(x*y) with NET
  floored at 1 USDG (Alpha-Homora fair LP value, k-invariant under swaps). Donating USDG to
  treasury to lift backingPerToken is self-defeating (gain <= LLTV*donation).
- L4 first-depositor / donation / share-inflation on vault -> KILLED: Morpho Blue virtual shares
  (1e6) + Vault V2 are stock audited code.
- L5 decimals/scaling bug -> KILLED: standard markets SCALE_FACTOR 1e24 verified (NVDA price()
  = 225.66e24 matches 8-dec feed $225.66); Loopback price() ~1.75e27 => ~1750 USDG/wsNET, sane.
- L6 liquidation math -> KILLED: stock Morpho LIF (<=1.15x) formula.

## Residual (reasoning-tier / by-design -- NOT a PoC-able finding, WATCH/DIG)
- LoopbackOracle divergence guard (revert when spot < 0.85*TWAP) pauses BOTH borrow AND
  liquidation. During a fast NET dump a borrower can keep spot >15% below TWAP to block their
  own liquidation until TWAP catches up (<= the 30min-4h window) -> a bounded bad-debt window on
  the $1M market. Fail-closed by design; bounded; self-heals. Reasoning-tier.
- Backing-floor pricing (credited >= backingPerToken) is an OHM-style assumption: if wsNET
  market price falls below treasury backing, liquidators won't liquidate (seized collateral <
  debt) -> bad debt. Design assumption, not a code bug.
- Stock feeds: MorphoChainlinkOracleV2 does NO staleness check (known intentional Morpho
  property) while collateral tokens (RHNVDA etc) track equities that trade only in market hours;
  a single RH EOA (0xeE27..9C52) controls every stock feed, and 0x0F52.. controls the tiny
  hand-rolled CASHCAT feeds (codesize 183/855). Centralization + weekend/halt gap = curation/
  trust risk, explicit curator responsibility in the Morpho model.
- DIG (best next step if revisited): can NET totalSupply be reduced via InverseBond faster than
  RFV drops, spiking backingPerToken to over-value wsNET and over-borrow WSNET-NN? Requires the
  InverseBond/Distributor mechanics (not read this session). Likely ratio-preserving by design.

## Final
Longbow is a thoughtfully-built curated Morpho deployment: stock Morpho Blue/Vault V2 core +
a bespoke NetNet oracle stack that is TWAP-based, flash-loan-resistant, manipulation-resistant
(sqrt-LP floor), and fail-closed. No exploitable drift found. CLEAN.
