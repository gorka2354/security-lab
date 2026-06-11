# Honeypot / scam-contract genres -> what recon covers (detector-mining note)

Studied `demining/23SolidityVulnerableHoneypots` (17 contracts, read-only, white-hat detector-mining per the
[[scam-games-mine-patterns-not-exploit]] boundary). Key finding: there are **two distinct genres**, and our
`det_rug` class targets only the modern one.

## Genre A — CLASSIC "trap the greedy attacker" (2016-2018, pre-0.8)
The contract LOOKS exploitable to bait an attacker, but a hidden mechanism takes their deposit. Examples:
- **Multiplicator**: `multiplicate()` pays `this.balance + msg.value` only `if (msg.value >= this.balance)` --
  impossible, because `this.balance` ALREADY includes msg.value on entry -> the condition never holds, you
  just donate. Plus a hidden `withdraw() -> Owner.transfer(this.balance)` (inline-owner drain).
- **PRIVATE_BANK / TestBank**: `CashOut` does `call.value()` before the balance write (CEI violation) -- bait
  for a reentrancy attacker who must `Deposit(MinDeposit)` first, then gets trapped.
- **OpenAddressLottery / CryptoRoulette / KingOfTheHill**: rigged RNG / hidden owner win condition.

**recon coverage:** these are **pre-0.8 -> `det_overflow` fired on 16/17** (the era signal). The trap logic
itself is **reasoning-tier** (subtle visibility/ordering/never-true conditions) -- regex can't cleanly call
"this looks exploitable but is a trap" without flagging every CEI/`this.balance` use. `det_reentrancy` already
surfaces the CEI bait (as a normal reentrancy lead). Low modern value -> NOT chasing classic-trap detectors.

## Genre B — MODERN operator backdoors (meme-token / launchpad era, 0.8.x)
The OPERATOR can rug/trap holders via explicit privileged functions. This is what our **`det_rug` class**
targets (built 2026-06-11):
- `det_owner_drain` -- owner-gated sweep/rescue/emergencyWithdraw of the balance (now also catches the inline
  `if(msg.sender==owner)` gate the classics used).
- `det_fee_backdoor` -- set*Fee/set*Tax with no cap -> 100% honeypot.
- `det_honeypot_lever` -- blacklist/setBots/enableTrading/setMaxTx -> freeze/block exits.

The classic corpus is the WRONG validation set for these (different genre) -> they correctly fired 0 on it.
Their precision is pinned by golden tests on the canonical modern patterns.

## Coverage map + follow-up
| genre | mechanism | recon |
|---|---|---|
| classic trap | never-true payout, reentrancy bait, rigged RNG | `det_overflow` (era) + `det_reentrancy`/`det_weak_random` (partial); trap-intent = reasoning-tier |
| modern backdoor | owner-drain / uncapped fee / freeze levers | **`det_rug` class** (det_owner_drain / det_fee_backdoor / det_honeypot_lever) |

**Follow-up (read-only, white-hat):** validate `det_rug` on a MODERN meme-token-honeypot corpus (ERC20 with
blacklist+tax+owner-mint, verified source) -- the right genre. Candidate new rug detectors from that: uncapped
owner-mint, ponzi payout-from-balance (`transfer(address(this).balance)` to users), disable-sells toggle.
Never live exploitation -- pattern study only.
