// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console2} from "forge-std/Test.sol";

// Faithful model of the Ape Church House payout accounting, to test the concurrency angle:
// can N bets, each approved at bet-time against the FULL balance (SpeedCrash:582-588), collectively
// exceed the bankroll and drain/DoS the house when many win?
//
// Real facts modelled:
//  - House.maxPayout() = balance * maxPayoutPerGame / FEE_DENOM            (House.sol:524-526)
//  - SpeedCrash bet check: houseProfit_i <= house.maxPayout()             (SpeedCrash.sol:582-588)
//  - House.payout caps AGAIN at payout-time: send = min(value, maxPayout) (House.sol:841-844)
//  - per-bet stakes are held in the GAME until resolve -> NOT in house balance while pending
uint256 constant FEE_DENOM = 10_000;

contract Receiver {            // stands in for the ClaimManager (where winnings are credited)
    uint256 public received;
    receive() external payable { received += msg.value; }
}

contract House {
    uint256 public maxPayoutPerGame;        // bps of balance, e.g. 200 = 2%
    bool public recap;                      // true = real contract (re-cap at payout time); false = naive
    constructor(uint256 mpg, bool _recap) payable { maxPayoutPerGame = mpg; recap = _recap; }
    function maxPayout() public view returns (uint256) {
        return address(this).balance * maxPayoutPerGame / FEE_DENOM;
    }
    // mirrors House.payout: value = the profit the game asks the house to cover
    function payout(address to, uint256 value) external returns (uint256 sent) {
        uint256 mp = maxPayout();
        sent = recap ? (value >= mp ? mp : value) : value;   // REAL re-caps; NAIVE pays `value` as-is
        (bool ok,) = to.call{value: sent}("");               // reverts if balance < sent (the DoS/insolvency case)
        require(ok, "house insolvent: payout transfer failed");
    }
}

contract ConcurrencyTest is Test {
    uint256 constant MPG = 200;             // 2% max payout per game
    uint256 constant BANKROLL = 100 ether;
    uint256 constant N = 60;                // 60 concurrent max bets: 60 * 2% = 120% of bankroll

    // helper: place N bets that ALL pass the bet-time check (each profit <= maxPayout at full balance),
    // then resolve them ALL as wins, paying each `profit` out of the house. Returns (paid, reverted).
    function _run(bool recap) internal returns (uint256 totalPaid, bool reverted, uint256 firstWinnerPaid, uint256 lastWinnerPaid) {
        House house = new House{value: BANKROLL}(MPG, recap);
        Receiver claim = new Receiver();
        uint256 betTimeMax = house.maxPayout();           // each bet approved against THIS (full balance)
        console2.log("bankroll:", BANKROLL);
        console2.log("maxPayout at bet time (each bet approved up to):", betTimeMax);
        console2.log("N concurrent max bets, sum of approved profits:", betTimeMax * N);

        // PHASE 1 (betting): all N bets are placed while balance is still BANKROLL (pending stakes are held
        // in the GAME, not the house) -> every bet's check `profit <= maxPayout()` is against the SAME full
        // balance, so ALL N are approved. (No state change to assert; the balance is constant during betting.)

        // PHASE 2 (resolution): all N resolve as WINS; the house pays each approved profit.
        for (uint256 i = 0; i < N; i++) {
            try house.payout(address(claim), betTimeMax) returns (uint256 sent) {
                totalPaid += sent;
                if (i == 0) firstWinnerPaid = sent;
                lastWinnerPaid = sent;
            } catch {
                reverted = true;
                console2.log("PAYOUT REVERTED (house insolvent) at winner #", i);
                break;
            }
        }
    }

    function test_concurrency_REAL_withPayoutRecap() public {
        console2.log("=== REAL House (payout re-caps at current balance) ===");
        (uint256 paid, bool reverted, uint256 first, uint256 last) = _run(true);
        console2.log("total paid to winners:", paid);
        console2.log("first winner paid:", first);
        console2.log("last  winner paid:", last);
        console2.log("any payout reverted (DoS/insolvency)?", reverted);
        // The re-cap protects the house: it can NEVER be drained to insolvency or DoS'd by concurrent wins.
        assertFalse(reverted, "REAL: house should never revert/insolvent");
        // BUT later winners are progressively SHORT-CHANGED vs their bet-time approval.
        assertLt(last, first, "REAL: later concurrent winners are capped below earlier ones");
        console2.log("=> concurrency drain/DoS DEFENDED by payout-time re-cap; residual = winners underpaid");
    }

    function test_concurrency_NAIVE_noRecap_drains() public {
        console2.log("=== NAIVE House (pays `value` as-is, no payout-time re-cap) ===");
        (uint256 paid, bool reverted, uint256 first, uint256 last) = _run(false);
        console2.log("total paid before revert:", paid);
        console2.log("first winner paid:", first);
        console2.log("last  winner paid (0 if reverted):", last);
        console2.log("payout reverted (house drained)?", reverted);
        // Without the re-cap, concurrent max bets drain the bankroll and a later winner's payout reverts.
        assertTrue(reverted, "NAIVE: concurrent wins drain the house -> later payout reverts (DoS)");
        console2.log("=> WITHOUT the re-cap, the bet-time-only check WOULD allow a concurrency drain/DoS");
    }
}
