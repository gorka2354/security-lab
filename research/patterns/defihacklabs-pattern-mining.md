# DeFiHackLabs pattern-mining (2026-06-14) — 751 real hacks → engine upgrades

Fan-out over DeFiHackLabs (6 agents, one per year 2021-2026, ~751 reproduced exploits). 53 patterns extracted.
This is the synthesized, deduped taxonomy → detector-candidates (recon) + invariant-seeds (hypothesize) + L4 lenses.
Cross-year consistency is striking: the SAME root causes recur every year. Source: `hunts/_volume/defihacklabs`.

## The recurring root-cause classes (by cross-year frequency)

### A. Spot-AMM-as-oracle  ⭐ #1 of EVERY year (~100+ hacks)
- **Mechanism:** a value-bearing decision (mint / borrow / collateral / reward / redeem) prices off a SAME-TX
  manipulable source — `getReserves()`, `balanceOf(pair)`, `getAmountsOut`, `pricePerShare()`/`getPricePerFullShare`,
  Curve `get_virtual_price`/`get_dy`, Uni-v3 `slot0()`, cToken `exchangeRate`. Flashloan skews it, protocol reads it, attacker profits, unwinds.
- **Invariant-seed (hypothesize):** pricing a position twice in one tx (before/after an attacker AMM swap or a bare
  transfer-in) must NOT change borrowing power. `price_used_for_settlement == TWAP/Chainlink`, never single-block spot.
- **Detector-candidate:** taint — any of those spot getters flowing into a mint/borrow/reward/collateral expression
  in the same function, with no TWAP/Chainlink read on the path. (built today: `det_spot_oracle`)
- **Hacks:** PancakeBunny $45M, Cream-Oct $130M, EGD, Lodestar, UwuLend, Moonwell, GMX $41M, Makina, Curve-LlamaLend.

### B. Token-side pair-reserve manipulation  ⭐ most frequent BSC class (~30+ hacks 2022-2026)
- **Mechanism:** a custom ERC20's own `_transfer`/public fn burns or moves `balanceOf(pair)`, or calls
  `pair.sync()/skim()` PERMISSIONLESSLY → shrinks the pair's token reserve → constant-product overvalues the attacker's
  tokens → swap dust for the paired asset. Includes reflection/deflationary `burn()/deliver()/reflect()` of a FOREIGN balance.
- **Invariant-seed:** no external caller may reduce a third party's (the pair's) balance or change reserves outside a
  swap; `balanceOf(pair)` changes only via pair-initiated transfers; reserves==balance must hold before swap pricing.
- **Detector-candidate:** public/external fn (or `_transfer` branch) that calls `pair.sync()/skim()` or
  `_burn(pair)/balanceOf(pair)`-mutation from a non-owner path; reflection `burn(addr!=msg.sender)`.
- **Hacks:** BIGFI + 9 reflection-token hacks 2023, LAURA, IPC, WETC/WXC, BYToken (triggerAutoBurn), MTToken, YSDAO.

### C. Donation / balanceOf-in-share-math  (every year)
- **Mechanism:** `exchangeRate`/`pricePerShare`/`totalAssets` reads live `token.balanceOf(this)`; a bare transfer
  (donate) or `skim/sync` inflates it. Beyond ERC4626 first-deposit: Compound/Venus cToken `exchangeRate`, empty
  lending markets, coupled-vault inflation (value routed through 2 vaults so a single-contract invariant never trips).
- **Invariant-seed:** `totalAssets` from internal ledger, never `balanceOf(self)`; an unsolicited transfer must not
  change any redeemable amount; `convertToAssets(convertToShares(x)) <= x`; first deposit mints a dead-shares floor.
- **Detector-candidate:** extend `det_erc4626` → flag ANY rate/share getter reading `balanceOf(address(this))` +
  a reachable `donate()/skim()/sync()`. Coupled-vault leg is reasoning-tier.
- **Hacks:** Spartan, Eleven, MahaLend, WiseLending, Raft, Onyx, Venus-zkSync, ResupplyFi $9.6M, Yield Protocol, Bedrock.

### D. Reward mis-accounting  (every year; egor's GameFi edge)
- **Mechanisms:** (i) reward = spotPrice·staked or instantaneous balance-delta → flashloan-inflate (EGD); (ii) reward
  paid multiple times by shuffling a transferable position token whose transfer hook lacks a checkpoint (Popsicle,
  Visor, Cover); (iii) reward-on-no-op: `transfer(self,self)` double-credits, `emergencyWithdraw` skips reward-settle,
  donate-then-claim (IdolsNFT, SWAPPStaking, BankrollNetwork); (iv) parent/aggregate index × child balance (SNK).
- **Invariant-seed:** `Σ pending_i <= rewardRate·elapsed` and `totalClaimed <= totalFunded`; `transfer(from==to) ⇒ 0
  reward`; `emergencyWithdraw` settles rewards via the same path as `withdraw`; donate can't raise donor's own same-tx claimable.
- **Detector-candidate:** extend `det_reward_formula` → flag a transferable reward-bearing token whose
  `_beforeTokenTransfer`/`_update` lacks an `updateReward/checkpoint` call; `emergencyWithdraw` missing the settle modifier.

### E. Access / authorization
- **Mechanisms:** unprotected `init/initialize` sets owner (DaoMaker, Telcoin, PikeFinance, Renegade); unprotected
  `mint/burn(addr)/setOwner`; ERC2771 trusted-forwarder `_msgSender()`-from-calldata + multicall (TIME); unprotected
  `extMulticall/aggregate` that weaponizes the contract's standing approvals (FloorProtocol drained BAYC/PPG);
  **caller-supplied-authority** — an address decoded from `payload/order/args` used as fund-owner / transferFrom source
  (TrustedVolumes, NewMarketTrading, Ekubo, MAPProtocol — the #1 mechanism of 2026).
- **Invariant-seed:** the debited party MUST be bound to `msg.sender` (or a verified signature over it), never a decoded
  calldata field; `init` one-shot + restricted; multicall must re-scope authority to the original caller.
- **Detector-candidates:** `det_unprotected_init`; ERC2771+multicall; external multicall/aggregate doing low-level call
  to an arbitrary target; fn with an `from/account/onBehalfOf` address param used in `transferFrom` source w/o
  `require(msg.sender==param)`. (extend `det_access`/`det_arbcall`)

### F. Signature gaps
- `ecrecover` result not compared to a stored non-zero signer (or `ecrecover(0)==admin`); `IERC1271(x).isValidSignature`
  where `x` is caller-supplied (MureDistribution); replay (no nonce/used-digest/chainid); vacuous empty proof/sig.
- **Detector-candidate (extend `det_signature`):** ecrecover used without `==address(0)` revert; `isValidSignature` on a
  function parameter; verify path with no nonce-consumed mapping.

### Reasoning-tier invariant-seeds (NOT regex — for hypothesize.py / L4)
- **Read-only reentrancy:** a consumer reads `get_virtual_price/getRate/getUserAccountData` while the SOURCE pool is
  mid-callback (Sturdy, Conic, dForce, Sentiment). Use the pool's reentrancy-safe view / VaultReentrancyLib.
- **Flashloan-governance:** voting weight == current balance, propose+execute atomic, no timelock (Beanstalk, Audius).
  Seed: tokens acquired this tx ⇒ 0 votes; propose→execute can't complete in one block.
- **Wrong-time / stale solvency check** (2025 dominant — Sharwa, Unilend, MIMSpell): health recomputed on a pre-mutation
  snapshot. Seed: after every borrow/decrease/withdraw, recompute health with FRESH state; `debt <= collateral·LTV` post-mutation.
- **Collateral re-use / withdraw-while-debt** (XCarnival, Kashi): `withdrawCollateral` reverts while `order.debt>0`; borrow callee == canonical market.
- **Self-liquidation-as-profit** (UwuLend, Sonne): debt-opener ≠ liquidation-beneficiary within one tx.
- **Bridge unverified-mint** (Nomad empty-root, VerusBridge, MAPProtocol, AdsharesBridge): `sum(minted) <= sum(proven-locked)`,
  `used[txid]` dedup, all value fields bound into the verified hash, acceptableRoot != 0. (recon's `det_mapping_default` = the Nomad leg)
- **Batched rounding amplification** (BalancerV2 $120M): pool invariant K/D monotonic non-decreasing across any swap/batch.
- **Spoofed-callee-return** (Convergence mints uint256.max, Penpie fake Pendle market): an external contract the protocol
  calls is attacker-chosen AND its return feeds value accounting → allowlist the source.
- **Sybil-via-proxy-spawn** (MONA, WUSD): per-address caps bypassed by deploying N helper contracts → entitlements must key on funded contribution.
- **Leftover-approval on cancel** (HedgeyFinance): create grants approval, cancel refunds but doesn't revoke.
- **Unit/decimals confusion** (Bedrock 1 uniBTC per 1 ETH; FutureSwap wad-as-bps): mint amount == msg.value/amountIn with no rate; a value scaled by WAD passed where bps expected.

## Action backlog (priority order)
1. **DONE:** `det_spot_oracle` (class A, #1) + golden tests.
2. **DONE:** `det_pair_reserve_mutation` (B) + `det_self_transfer` (B-self) — forged + golden + **test+tune on real
   on-chain source**: TP-confirmed on BY (pair-reserve, BYToken.sol:197 token-side `_burn(pair)`+`sync`),
   LPC (self-transfer, tuple-cache-via-`_updateBalance` write-back) and GPU (self-transfer, direct cache);
   0 FP on 8 audited/DEX clones (magicswap/eva/kona/mezo/…). Two FP-fixes baked in:
   (a) self-transfer keys on the **write-back tell** (`_balances[x]=<local>.op`) not the cache-read — catches the
   tuple-cache LPC variant AND excludes in-place SafeMath `balances[x]=balances[x].op(v)` (UniswapV2ERC20/OZ);
   (b) pair-reserve flags burn-of-pair always but **sync/skim only inside a reflection token** (markers:
   `_reflectFee`/`_rOwned`/`triggerAutoBurn`/…) — DEX router/pair periphery `.sync()` no longer FPs.
3. Forge next (syntactic): `det_unprotected_init` (E), extend `det_signature`
   (F: ecrecover-0 / isValidSignature-param), `det_caller_supplied_authority` (E).
4. hypothesize.py invariant-seeds: add the reasoning-tier seeds above to the CORE/ECONOMIC/GAMEFI menus (reward-on-no-op +
   self-liquidation + flashloan-governance + read-only-reentrancy + stale-solvency-check + bridge minted<=locked).
5. shadow.py: bench recon against a DeFiHackLabs sample (not just DeFiVulnLabs minimal-repros) to measure real-hack recall.
See [[fanout-triage-workflow-validated]] (the mining невод) + the vault note "Датасеты багов и чек-листы".
