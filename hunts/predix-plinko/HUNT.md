# HUNT: predix-plinko (PrediX Plinko) -- wave-14 BACKUP (primary levr-bet failed the SOURCE gate)

Verdict: CLEAN (well-evidenced). A rigorously-built, source-verified short-horizon ETH/USD
prediction game on Arbitrum with a centralized-operator trust model. No external-attacker exploit,
no accounting/settlement/oracle/session bug found across all four contracts. Value tiny (~$216).

## Phase-0 facts
- Chain: Arbitrum One (42161). Deployed + VERIFIED on Arbiscan (UUPS proxies + impls):
  - game 0xaA035F511272d214eFcADC844809E9D7Cf97576C -> impl 0x33f451821565e4f45946b29c16889cf9be0d67cd
  - vault 0xA600ad53dcBd8a13F4f2Af3540fCCA2EE424e1bF -> impl 0xc27f666178c062b939a6899ca6e0e127d2595de7
  - priceModule 0x8704751E56Aa6A184079681591258DE664d77BE7 -> impl 0x84da8745aa578eacbd4c8a448bcd40d93c284702
  - USDC 0xaf88d065e77c8cC2239327C5EDb3A432268e5831 (canonical Arbitrum, 6dp)
- Source: github.com/PrediX-Protocol/plinko-contracts (MIT, published for audit). Deployed game impl
  == repo src/PlinkoGame.sol EXACTLY (0-line diff) -> the repo IS the live code. No audit listed.
- VALUE: vault holds 215.90 USDC; reserve 136.78, floatTarget 100, feeBps 0, winFeeBps 200 (2% of
  profit), maxStake 50 USDC, maxPayoutBps 500000 (50x total return cap). LIVE-FUNDED but tiny.
- Mechanism: round id = openTs. Player signs an EIP-712 Order (zone UP/NOW/DOWN, stake, payoutBps,
  nowBand, nonce) with a self-registered session key. Operator quotes odds off-chain; resolver (an
  operator EOA) settles the whole round via resolveRound, pinning open/close prices from Pyth. Vault
  holds all USDC (player balances + house reserve + accruedFees); closure law
  balanceOf + sweptToCold == totalPlayerBalance + reserve + accruedFees.

## What I read (deployed == repo)
- PlinkoVault.sol (594L): deposit, executeWithdraw (player+operator co-sign, unordered nonce,
  deadline, fee read at exec, CEI), debitStake/creditPayout (game-only), fundReserve, sweepToCold/
  collectProfit (operator|owner, floatTarget-guarded), returnFromCold, promo credits (caps).
- PlinkoGame.sol (912L): resolveRound (resolver-only), gas-isolated per-order batch, selfResolveOrder
  (payout math), zoneOf, session wrappers, price-pin, timing/module scheduled switches.
- modules/PythPriceModule.sol (150L): pinPrice via parsePriceFeedUpdatesUnique(data,[feedId],t,t+grace).
- lib/SessionLib.sol (170L): session-key registry, as-of-lock validity, per-UTC-day cap, epoch bump.
- modules/CctpAutoBridgeModule.sol: NOT deployed (not in addresses-42161.json; not referenced by
  game/vault/pyth) -> out of scope for the live target.

## Leads and their fate
- [recon FP] PlinkoVault:310 sweepToCold, :323 collectProfit "UNGATED privileged" -> FALSE POSITIVE:
  both call _checkOperatorOrOwner() (inline auth via an internal helper; recon keys on only*-modifier
  and misses helper-call auth). PlinkoGame:596 revokeSessionKey "ungated" -> BY DESIGN permissionless:
  operates on msg.sender's OWN keys (sessionRegistry.revoke(msg.sender,key)); self-service revoke.
- [hypothesize] collectProfit/accruedFees + creditPlayer/promo* "interleave" -> KILLED: every mover is
  nonReentrant; accruedFees/reserve floors + floatTarget checked before each transfer; caps enforced on
  batch total; day-roll cannot be refreshed by revoke+reregister (spentToday survives register).
- [oracle, class prior] price pinning -> CLEAN: parsePriceFeedUpdatesUnique enforces the FIRST Pyth
  update in [t, t+grace]; expo pinned to -8; price>0; conf gated (conf>0 && conf>maxConfBand reverts).
  Resolver cannot cherry-pick a favorable price nor forge it (Pyth on-chain verify). Open pinned at
  openTs, close at openTs+betSecs+lockSecs; module fixed per round (STARTED keeps RoundRec.module).
- ["priced at spot" class (luxmarket/pulso)] -> DOES NOT APPLY: no permissionless pool/AMM curve. The
  house is the counterparty; reserve only moves via creditPayout (game-only) reached only from
  resolveRound (resolver-only). No self-inclusion -> a player cannot force a payout at unquoted odds.
- [payout solvency] -> CLEAN: creditPayout reverts Insolvent when reserve < payout, so a winning order
  that exceeds the reserve is SKIPPED atomically (its debit unwinds; player not charged). Debit-before-
  credit in one frame. payoutBps in [10000, maxPayoutBps] so credited>=stake -> winFee never underflows.
- [validation-gap / band] -> CLEAN: order.nowBand must == the clamped settle band (BandMismatch skips);
  the band the player signed is the band that decides the zone. zoneOf uses int256 diff, no overflow.
- [session-key / cross-account] -> CLEAN: an order for player P requires a sig by a key P registered
  (keys[account][key]); isValidAt reads state "as of lockTs" via one prev-slot; setTiming bounds
  resolveTtl <= SessionLib.CHANGE_GAP (2h) and > betSecs+lockSecs, so at most ONE key/epoch change
  lands per resolve window -> the one prev-slot always reaches back to lock. Caps are self-set (a
  self-limit), day bucket survives re-registration.
- [withdraw over-draw] -> CLEAN: executeWithdraw needs BOTH player (ERC-1271/ECDSA) and operator
  (ECDSA, EOA-pinned) sigs; balance debited full amount before egress; nonce consumed only on success.

## Residual (documented centralization, NOT a novel finding)
- Owner is a fully-trusted, single-key UUPS upgrade authority with IMMEDIATE (no-timelock) upgrades on
  all three proxies, and setters (fees, caps, band, resolver) take effect at once. setWithdrawFee applies
  to already-signed intents (fee read at execution); minWithdrawFee is unbounded (executeWithdraw clamps
  fee<=amount). So a malicious/compromised owner can confiscate a pending withdrawal via a fee hike, or
  drain via upgrade. The code comments explicitly acknowledge these as accepted trust assumptions /
  own hardening tasks. Operator alone cannot withdraw (needs the player's sig too). Severity: trust,
  not an external exploit. Suggest (courtesy, if ever disclosed): timelock on upgrades + fee policy.

## Toolkit bugs hit (reported to coordinator; do NOT edit toolkit)
- HOST TLS: python urllib -> api.etherscan.io "certificate has expired" -> fetch_source/threat FALSE
  NEGATIVES until `export SSL_CERT_FILE=$(python -c 'import certifi;print(certifi.where())')`. Applied.
- Public Arbitrum RPCs (arb1.arbitrum.io, publicnode, lava, 1rpc) return HTTP 403 to python urllib;
  ankr returns no 'result'. Worked around all eth_call/balance reads via Etherscan-v2 proxy module.
- recon.py precision: flags helper-call auth (_checkOperatorOrOwner) as UNGATED (regex expects an
  only*-modifier) -> 2 FPs here; and flags a self-service (msg.sender) revoke as a privileged-name FP.
