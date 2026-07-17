# HUNT — Cambria (wager PvP + Gold Rush, Abstract chain 2741)

Active on-chain game (risk-to-earn ETH/NFT wagers), the GameFi/gambling focus (gaming/gambling). Sourced via a NEW method;
DuelArenaBattle (the wager contract) deep-dived -> CLEAN (honest negative on a mature, high-volume contract).

## Sourcing win — crack the frontend JS bundle (reusable)

Cambria does NOT expose `/api/contracts` (unlike Gigaverse). Its addresses live only in the SvelteKit frontend
behind Cloudflare. Method that worked: **Playwright MCP** (`browser_navigate` to the app -> `browser_evaluate` /
grep the loaded JS bundle + `browser_network_requests`) -> pulled the per-chain config block (`2741:"0x..."`).
Yielded **7 contracts**: DuelArenaBattle/DuelArenaEscrow, CambriaOps, GoldRush Season / Trade(`settleTrade`) /
TieredCharter, CambriaBattlePass. Generalizes to any Cloudflare-walled web3 game — the addresses MUST reach the
user's wallet, so they're in the bundle/network traffic; read them with a real stealth browser, not curl.

## Target — DuelArenaBattle `0x5F8aBF7F164fBeD5C51F696Ddf3c2C17bcBC8fBB` (Abstract)

PvP wager: two players stake ETH/token/NFT into escrow; an off-chain judge signs the winner; winner claims BOTH
stakes (or either party cancels with a withdrawJudge sig for a mutual refund). **nextBattleId = 585,416** — battle-
tested at 585k-battle scale. on-chain: `owner=0xe4c3...`, battle-contract ETH balance 0 (escrow holds funds).

## Verdict — CLEAN (all wager-drain vectors guarded)

1. **Self-battle blocked.** `initBattle(challenging, ...)` reverts `BattleSelfForbidden` if `msg.sender ==
   challenging` — kills the "be both sides, win against yourself, drain the escrow's pooled balance" class.
2. **Claim / withdraw / nullify are mutually exclusive.** Battle-level flags `!nullified`, `matched`, `!claimed`,
   `!one.hasWithdrawn`, `!two.hasWithdrawn` gate every payout path; `claimProceeds` sets `claimed`, `withdrawStake`
   sets BOTH `hasWithdrawn`, `nullifyBattle` requires `!matched`. No two payout paths fire for one battle -> the
   escrow double-spend is defended even though `DuelArenaEscrow.withdraw` doesn't clear `_deposits` (see smell).
3. **Signature purpose-confusion blocked by SEPARATE keys.** Both `claimProceeds` and `withdrawStake` recover from
   the IDENTICAL EIP-712 hash `getClaimTypedDataHash(Claim({battleId, account: msg.sender}))` — the signed message
   has no win-vs-cancel field. BUT `claimProceeds` checks `signer == judge` and `withdrawStake` checks
   `signer == withdrawJudge`, and on-chain **judge `0x1D28206358d30E84F985ac6EdbC6Ae49F25FfA7F` !=
   withdrawJudge `0xB0e7d4175BE8E83a8075538f2DBe6F87d5a69013`** (different addresses). So a cancel-authorization
   (withdrawJudge sig) FAILS the `== judge` check and can't be replayed to WIN, and vice-versa. The digest uses
   `abi.encode` (length-prefixed — no encodePacked collision) and the EIP-712 domain binds chainid + contract
   (no cross-deployment/cross-chain replay). Double-claim is blocked by the `claimed` guard.

**Code smell (latent, defended):** `DuelArenaEscrow.withdraw(payee, receiver, battleId)` (onlyOwner = the battle
contract) sends `_deposits[payee][battleId]` but does NOT delete it — a re-withdraw primitive IF the same
(payee, battleId) could be withdrawn twice. It can't: the battle-level flags + the self-battle block make every
(payee, battleId) withdrawable at most once. Worth flagging to the team as defense-in-depth (clear the deposit),
but not exploitable as-is.

## Disposition

Honest **CLEAN** verdict on a LIVE, ACTIVE (585k battles), well-guarded wager contract — like dreUSD/Apiary, the
obvious vectors are closed on a mature deployment. Recorded in ledger (`cambria-duelarena`, `known`). The session's
deliverable here is the **sourcing method** (browser-bundle crack) + the disciplined honest negative, not a forced
finding. Other Cambria contracts (GoldRushTrade `settleTrade` marketplace sigs; a possible dungeon/keys-RNG
mechanic) remain un-deep-dived — a quick scan of CambriaOps/GoldRushSeason/TieredCharter showed no obvious
RNG-risk surface (risk mechanic likely off-chain or in a contract outside the 7 sourced).
