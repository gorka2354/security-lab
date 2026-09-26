# HUNT: levr-bet (Levr Bet) -- wave-14 PRIMARY

Verdict: DIG / PARKED -- LIVE-FUNDED but SOURCE-UNREACHABLE (no verified source, no public repo,
frontend+whitepaper behind AWS WAF captcha). Needs the decompile lane (heimdall/mini-PC) to hunt.
Switched to backup predix-plinko for a source-backed verdict this wave.

## Phase-0 facts
- Chain: Monad mainnet (chainid 143, EVM -- standard Solidity bytecode 0x6080..., NOT EraVM).
- Category: Prediction Market / leveraged sports betting, "up to 5x". DefiLlama listed 2026-09-11, audits=0.
- Oracle: Pyth (levrPythFeed wraps canonical Pyth 0x2880aB155794e7179c9eE2e38200202908C17B43) + a
  LevrMarketFeed (odds/lines feed).
- VALUE (LIVE-FUNDED): LevrMvpDepository vault 0x141B1d9Ebd2E21749d6425CaeBaCc9704aAb9583 holds
  1,905,099.14 USDC (read directly via balanceOf; USDC 0x754704Bc059F8C67012fEd69BC8A327a5aafb603,
  6 decimals). MVP token 0x08Dd3D91e60a6c856D1aeBE02237322aD3Caa583 totalSupply 1,901,632.26 (6dp).
  DefiLlama current TVL datapoint (~2026-09-26) = $1.904M. => FUNDED, current.
- Deployment: 18 contracts deployed together by 0xd05ebdcd4757c75b08d59c16638c5795c8e55004 in blocks
  53362333-53362335 (~2026-02-05). A hub 0xcdb28317a1c83b6e042fb83342ec0c109f77c7f3 is then
  configured with ~20 setter calls (central config/roles). Plus VaultRush 0x8e33446019...5916560
  (older, deployer 0xb57fff..., block 36174319 ~2025-11-17, 2736B).
- Verified source: NONE of the 19 contracts is verified (Etherscan-v2 chain143 getsourcecode = empty
  ContractName/SourceCode; Sourcify v2 = null match). No public source repo: org github.com/LEVR-LABS
  has only 2 FORKS (openzeppelin-relayer, protocols), no contract code. Frontend app.levr.bet +
  whitepaper www.levr.bet/whitepaper are behind AWS WAF "Human Verification" (403/405 to curl AND
  Playwright). Docs mirror (le-dat/chat-service) is marketing-level only.

## System map (roles recovered from bytecode selectors; reach_bytecode.py + 4byte)
- 0xcdb28317..c7f3 (20KB) CONFIG/ROLES: blacklist(address[]), LIQUIDATOR_ROLE, positionFeeBps,
  treasuryBps, getAssetWeight(address), updateMinDepositValue, isGameAdmin, GAME_ADMIN_ROLE, MAX_BPS.
- 0x51fe22aa..4b07 (23KB) MARKET (leveraged position engine): getPositions(bytes32[]),
  userNonce(address), marketName(), pauseUnpause, balanceOf, approve. Signed-order / nonce model.
- 0x141b1d9e..9583 (17KB) LevrMvpDepository VAULT/bankroll: pause/unpause, mint(address,uint256),
  withdrawFees(address,address), claimAllFees, getLatestRound, currentRound. Holds the $1.9M.
- 0x08dd3d91..a583 (3KB) MVP token. 0x26f580f3..9e68 (3KB) levrPythFeed. 0xd42a276d..01c7 (12KB)
  LevrMarketFeed (odds). +12 more (per-market components: likely orderbook/liquidation/settlement/
  referral/fee -- 2.7KB..22.6KB each). Full address list in scratch sysmap.txt.

## Why the gate blocks the hunt
- Bug classes worth chasing (LMSR/odds priced at spot vs integral; leverage payout solvency of the
  shared MVP bankroll; liquidation off a stale/pushed LevrMarketFeed; settlement/void-game
  double-claim; signed-order nonce replay) ALL live in the custom-selector bodies of the Market/
  Config/Feed/settlement contracts. Only 12-21 of 87-180 selectors per contract resolve via 4byte;
  the value-moving ones are custom and un-named.
- To reason at our tier we need function bodies. Path = heimdall decompile of Market(0x51fe22),
  Config(0xcdb283), the odds feed(0xd42a276) and the settlement/liquidation components on the
  mini-PC lane, then reverse the leverage/payout/liquidation math. That is a multi-hour, high-error
  effort -- out of budget for this wave (one of N parallel hunts). ThetaNuts lesson: unverified +
  no-source is the dominant reach blind spot; an honest "not reachable as deployed here" is valid.

## Parked-lead seeds (for when the decompile lane runs)
1. Payout solvency: does a winning 5x leveraged bet pay more than the shared MVP bankroll / a
   per-market exposure cap can cover? (LevrMvpDepository is the single counterparty pool.)
2. Odds/line trust + staleness: LevrMarketFeed(0xd42a276) sets lines; who writes it, is there a
   staleness/heartbeat check, can a keeper push a favorable line same-block as an open?
3. Settlement/void path: cancellation/void-game refund + resolveRound-style settlement -- double
   claim or nonce (userNonce) replay across rounds.
4. Config immediacy: positionFeeBps/treasuryBps/getAssetWeight/minDeposit on the hub are owner-set;
   can a mid-position change on weight/fee extract from open positions?

## Toolkit bugs hit (reported to coordinator; do NOT edit toolkit)
- HOST TLS: python urllib -> api.etherscan.io "certificate has expired" (stale Windows CA). Made
  fetch_source.py say "no verified source" and threat.py "unknown" as FALSE NEGATIVES until
  `export SSL_CERT_FILE=$(python -c 'import certifi;print(certifi.where())')`. Applied for all calls.
- threat.py: reports "EMPTY / PRE-LAUNCH" + "ABANDONED 232d" for the $1.9M vault -- (a) reads only
  native ETH balance, blind to 6-decimal USDC (printed eth 0.0000); (b) Etherscan-v2 txlist on Monad
  (chain 143) is incompletely indexed (returns 1 tx = only the creation), so recency is wrong.
  Confirmed funded via direct eth_call balanceOf. Value/liveness must be read manually on Monad.
- reach_bytecode.py: very slow on Monad (per-selector 4byte network lookups; 20KB contract > 120s,
  backgrounded). Resolves only ~12-21 of 87-180 selectors (custom selectors unresolved) -> role hints
  only, not a hunt surface.
