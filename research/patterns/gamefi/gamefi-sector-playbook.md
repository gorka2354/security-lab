# GameFi / gambling / prediction sector -- hunt playbook (deep-search 2026-06-10)

**Tier:** mixed (T1 weak-RNG/mint are recon-catchable; most game-logic/tokenomics classes are T3 reasoning).
**Why a sector note:** egor's edge is on-chain games; the bug classes here are ones traditional DeFi audits
miss. $47M+ lost to GameFi exploits in 2024 (MakinaFi, DeHero, Polycat); 18% of GameFi findings are Critical+
(higher than DeFi). Sourced from the Zealynx GameFi checklist (55 checks / 2,100+ analyzed issues) + hack
post-mortems + RNG/prediction-market writeups.

## 1. Bug taxonomy (8 categories -- the GameFi-UNIQUE classes are the EV)
- **NFT & Asset (8):** mint-supply-cap (any path incl admin), admin-mint restrictions, **randomness for traits/
  loot** (VRF vs block-var -> our det_weak_randomness), metadata-immutability, **transfer-hook validation**
  (every NFT transfer must sync game state), **cross-contract state consistency** (ownership synced between
  game logic and the NFT contract), marketplace-integration (approved marketplace can't bypass locks),
  **asset-locking** (in-game-locked items can't be transferred/sold externally).
- **Tokenomics & Economy (12):** **inflation control** (emission hard-caps/decay), vesting, burn, supply-oracle
  manip, **reward-rate-limits**, **activity-validation** (rewards require real gameplay, not a no-op call),
  **anti-farming**, **Sybil resistance**, staking-lock, voting-power calc, flash-loan protection, compound-rate.
- **Marketplace & Trading (10):** price-manip, fee-calc accuracy, royalty enforcement, order-expiration,
  **atomic-swap guarantees**, **escrow fund security**, dispute resolution, settlement finality, cross-chain
  bridge validation, **replay-attack prevention** (signed orders/moves).
- **Game Mechanics & Logic (9) <- the most GameFi-unique:** **move verification**, **cooldown enforcement**,
  resource-consumption validation, **state-machine integrity** (illegal state transitions), **anti-cheating**,
  timing-attack resistance, **MEV protection for game actions** (front-run a reveal/move/mint), fair-play,
  **private-information protection** (hidden state must be commit-reveal, not just "not displayed").
- Access Control (7), Oracle & External Data (5), Upgrade (2), Gas (2).

## 2. Our engine: covered vs GAP (detector TODOs)
- COVERED by recon: weak-randomness (`det_weak_randomness`), mint/supply (`det_mint`/supply-integrity),
  reward double-claim (`det_reward`), oracle 3-guard, reentrancy, access-control, strict-balance.
- **GAP (forge detectors / hypotheses):**
  - **activity-validation / no-op reward:** a `claim`/`earn` that pays without proving gameplay (calls a
    mintable points fn with no state-change gate) -> reward-farming. (Cousin of det_reward; needs a "reward
    paid but no game-state precondition" heuristic.)
  - **asset-locking bypass:** an NFT marked locked/staked in game state but `transferFrom` not blocked (the
    lock lives in a different contract than the token's `_update`). -> cross-contract-state hypothesis.
  - **move/state-machine integrity:** an action allowed out of its phase (no `require(state == Phase.X)`).
  - **commit-reveal / private-info:** an outcome (mint rarity, battle, raffle) decided from on-chain "hidden"
    data that's actually readable, OR a reveal front-runnable (MEV). (Extends det_weak_randomness to
    "predictable OR front-runnable outcome".)
  - **cooldown / rate-limit:** a per-action cooldown read from a manipulable timestamp or missing entirely.

## 3. Tools found (worth adopting / examining)
- **Krait CLI** -- `github.com/ZealynxSecurity/krait`: "Claude Code SKILLS for Solidity auditing, 90% precision
  across 40 blind Code4rena contests, zero API cost" (TypeScript, pushed 2026-05). **This is our exact setup
  (Claude Code skills).** HIGH-PRIORITY follow-up: examine its skills -> adopt/borrow what beats our recon, or
  confirm our pipeline is complementary. `/krait:scan --deep` automates ~10/55 of the Zealynx checks.
- **Zealynx GameFi checklist** -- 55 checks, the source of section 1 (use as a manual-review checklist per game).
- Slither / Aderyn (static) for the T1-catchable RNG/mint patterns; Chainlink VRF = the "correct" RNG (its
  ABSENCE on an outcome path is the lead).

## 4. SOURCING fresh GameFi targets (the channel DefiLlama/Immunefi lack)
DefiLlama Gaming = sparse (prediction-markets + dead 2018 degen: EtherFlip/Fomo3D/PoWH3D); Immunefi GameFi =
established/small. Fresh on-chain games surface elsewhere:
- **GameFi launchpads / game hubs:** gamefi.org (Game Hub tracks active projects, 70+ launches), Gamestarter,
  Enjinstarter -- IGO/INO listings = brand-new game contracts.
- **NFT marketplaces:** OpenSea / Magic Eden / Mavis Market -- recent game-NFT collections -> their mint/stake
  contracts (often unaudited at launch).
- **GitHub topic `gamefi`** + recently-pushed game-contract repos.
- **contest_monitor** now has a GameFi/gambling bonus -> alerts first when a GameFi/betting contest launches.
- For deployed-but-fresh: scout now includes Gambling/Luck Games/Yield Lottery/Betting/NFT categories.

## 5. Hunt lens (apply to any game/gamble/predict target)
1. **Outcome integrity:** every randomness/outcome path -> VRF or predictable? front-runnable (MEV)? grindable
   by revert-on-loss? (det_weak_randomness + the commit-reveal/MEV extension).
2. **Reward integrity:** can you earn without playing (no-op activity), double-claim, or farm/Sybil?
3. **Asset integrity:** mint-cap on ALL paths; locked/staked NFTs can't escape; ownership synced cross-contract.
4. **Economy:** emission caps/decay; fee/royalty math; escrow/atomic-swap in the marketplace.
5. **Prediction/betting specifics:** the ORACLE/resolution is the crux -- UMA-style optimistic oracle dispute
   window gameable? token-weighted resolution vote capturable? payout/settlement rounding? (not RNG -- it's
   oracle-resolution + settlement math).
