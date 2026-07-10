# HUNT — wager-chess (on-chain wagered chess) — HIGH: free promotion

**Repo:** `fenestbuc/wager-chess` (GitHub); the identical `ChessLogic.sol` is in `Kubar-Labs/wager-chess`
(same 20,107-byte file) so BOTH are affected. **Training rep** (egor's edge: wager PvP). PoC: `wager-chess-poc/`
(forge 3/3, on the REAL ChessLogic code). **LIVE-FIRST caveat:** hobby repo — verify on-chain deployment / real
wagers before treating as a live finding; as-is it's a real High-severity logic bug + a training find.

## 🎯 FINDING (HIGH, PoC-proven) — free piece promotion on any non-pawn move → steal the wager

`WagerChessEngine` escrows both players' wagers and pays `totalPot` to whoever the on-chain chess engine
declares the winner. The engine lets a player **promote ANY piece to a Queen on ANY legal move**, so a cheater
spawns a Queen army, checkmates trivially, and steals the opponent's stake in every game.

### Root cause — the `promotion` arg is validated only for pawns, but applied to everything
`isValidMove` (`ChessLogic.sol:196-207`) only forwards `promotion` to the pawn validator:
```solidity
if (pt == 1) ok = _isPawnMove(g, from, to, promotion);   // pawns: promotion IS checked
else if (pt == 2) ok = _isKnightMove(from, to);          // knight/bishop/rook/queen/king:
... // promotion is NEVER looked at
if (_wouldLeaveKingInCheck(g, from, to, pt == 1 ? promotion : NONE)) return false;  // NONE for non-pawns
```
`_isPawnMove` correctly requires `promotion == NONE` off the last rank and `_isValidPromotion` (2–5) on it.
But for every non-pawn piece the `promotion` argument is ignored — the move is accepted for any value.
Then `executeMove` (`ChessLogic.sol:483`) applies it **unconditionally, with no piece-type gate**:
```solidity
g.board[to] = promotion != NONE ? (white ? promotion : promotion + 8) : piece;
```
So a legal knight/bishop/rook move carrying `promotion = 5` places a **Queen** (`WQ = 5`) at the destination
instead of the moved piece.

### Exploit
1. `createGame` / `joinGame` — both stake `wager` (pot = `2 * wager`).
2. Each of your moves: play a legal non-pawn move with `promotion = 5` → that piece becomes a Queen.
   (e.g. `makeMove(gameId, 1, 18, /*promotion*/5)` — knight b1→c3 becomes a Queen.)
3. In a few moves you have several Queens → forced checkmate → `_finalizeGame` sets
   `pendingWithdrawals[you] = totalPot - fees` → `claimPayout` → you take the opponent's wager.
Result: **you win every wagered game you play — theft of the counterparty's stake.**

### Proof (`wager-chess-poc/`, forge 3/3, real ChessLogic)
- `test_KnightMove_IllegallyBecomesQueen`: knight b1(1)→c3(18) with `promotion=5` → `board[18] == 5` (Queen).
- `test_RookMove_AlsoBecomesQueen`: rook a1(0)→a3(16) with `promotion=5` → Queen (generalizes).
- `test_Control_KnightMoveWithoutPromotion_StaysKnight`: same move, no promotion → stays a knight (engine OK).

### Fix
Gate the promotion on piece type + last rank in BOTH places:
- In `isValidMove`, reject `promotion != NONE` unless `pt == 1` (and let `_isPawnMove` enforce the last-rank rule).
- In `executeMove:483`, only apply promotion when `pt == 1` (a pawn reaching the last rank): otherwise write `piece`.

## Also found (Low) — fee double-deduction (`WagerChessEngine.sol:204`)
`payout = totalPot - totalFeesCollected`, but `totalPot` is the wagers only (2·wager) — move fees are paid as
separate `msg.value` into `totalFeesCollected`/`claimableFees`, never added to `totalPot`. So the winner is
underpaid by the fees AND the protocol also withdraws the same fees via `claimableFees` → `totalFeesCollected`
worth of ETH is stranded per game. Fix: pay the winner the full `totalPot` (fees are already taken on top).

## Checked & clean (the disciplined negatives)
- Reentrancy: `claimPayout` / `withdrawUnmatchedWager` / `claimTimeout` all zero state before the `.call` (CEI) +
  pull-payment `pendingWithdrawals`; the `makeMove` refund window is non-exploitable (turn-gating).
- `claimTimeout` insta-steal: **not present** — `lastMoveTimestamp` is initialized in both `createGame` and
  `joinGame`, so a joiner can't claim before the first move (needs a real 1-hour stall).
- `_finalizeGame`'s "gameOver but not checkmate/stalemate → revert" branch is unreachable: the engine only sets
  `gameOver` on checkmate (winner 1/2) or stalemate (winner 0).
