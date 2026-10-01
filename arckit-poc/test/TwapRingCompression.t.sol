// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {PoolId} from "@uniswap/v4-core/src/types/PoolId.sol";
import {ArcTwapOracle, IStateViewSlot0} from "../src/ArcTwapOracle.sol";

/// Pool stand-in: poke() only needs a non-zero sqrtPrice and a tick.
contract MockStateView is IStateViewSlot0 {
    int24 public tick = 1000;

    function setTick(int24 t) external {
        tick = t;
    }

    function getSlot0(PoolId) external view returns (uint160, int24, uint24, uint24) {
        return (uint160(1) << 96, tick, 0, 3000);
    }
}

/// ArcTwapOracle keeps 256 observations per pool, at most one per second, and anyone may poke().
/// ArcLend._borrowPrice (ArcLend.sol:506-511) reverts OracleNotReady when the TWAP covers less than
/// MIN_TWAP_COVERAGE = 20 minutes (ArcLend.sol:39), and every borrow pokes too. 256 observations
/// written faster than every 1200 / 256 = 4.69 s therefore span < 20 minutes: borrow and
/// withdrawCollateral-with-debt revert for as long as the pokes keep coming.
contract TwapRingCompressionTest is Test {
    uint32 constant TWAP_WINDOW = 30 minutes; // ArcLend.sol:38
    uint32 constant MIN_TWAP_COVERAGE = 20 minutes; // ArcLend.sol:39

    MockStateView sv;
    ArcTwapOracle oracle;
    PoolId pool = PoolId.wrap(bytes32(uint256(1)));

    function setUp() public {
        vm.warp(1_790_000_000);
        sv = new MockStateView();
        oracle = new ArcTwapOracle(sv);
        // healthy history: a keeper pokes once a minute for 40 minutes
        for (uint256 i = 0; i < 40; i++) {
            oracle.poke(pool);
            vm.warp(block.timestamp + 60);
        }
    }

    function test_baseline_keeperCadenceCoversTheWindow() public view {
        (, uint32 covered) = oracle.twapTick(pool, TWAP_WINDOW);
        assertEq(covered, TWAP_WINDOW, "a once-a-minute keeper fills the 30-min window");
        assertGe(covered, MIN_TWAP_COVERAGE, "borrow is allowed");
    }

    function test_pokeEvery4s_dropsCoverageBelowBorrowMinimum() public {
        for (uint256 i = 0; i < 256; i++) {
            vm.warp(block.timestamp + 4);
            oracle.poke(pool);
        }
        (, uint32 covered) = oracle.twapTick(pool, TWAP_WINDOW);
        emit log_named_uint("coverage after 256 pokes 4 s apart (s)", covered);
        assertEq(covered, 255 * 4, "only the last 256 observations count: 1020 s");
        assertLt(covered, MIN_TWAP_COVERAGE, "ArcLend borrow / withdrawCollateral -> OracleNotReady");

        // it stays down while the pokes continue (one more hour)
        for (uint256 i = 0; i < 900; i++) {
            vm.warp(block.timestamp + 4);
            oracle.poke(pool);
        }
        (, covered) = oracle.twapTick(pool, TWAP_WINDOW);
        assertLt(covered, MIN_TWAP_COVERAGE, "still blocked an hour later");
    }

    function test_samePokeRateFromOrdinaryUse_alsoBlocksBorrows() public {
        // no attacker: a borrow every 4 s (each borrow pokes) has the same effect, so a busy market
        // locks itself out of new borrows once 256 observations fit inside 20 minutes
        for (uint256 i = 0; i < 300; i++) {
            vm.warp(block.timestamp + 4);
            oracle.poke(pool); // what ArcLend._borrowPrice does before its coverage check
            (, uint32 covered) = oracle.twapTick(pool, TWAP_WINDOW);
            if (covered < MIN_TWAP_COVERAGE) {
                emit log_named_uint("borrow #n that hits OracleNotReady", i + 1);
                assertLe(i + 1, 300);
                return;
            }
        }
        fail("expected the coverage check to trip");
    }

    function test_compressedRing_letsAPriceHeld17minOwnTheLiquidationTwap() public {
        // liquidate() prices at the TWAP with NO coverage check (ArcLend.sol:308-311). With a healthy
        // ring a distorted tick held for 1020 s weighs 1020/1800 of the 30-min TWAP; once the ring
        // is compressed to 1020 s it IS the whole TWAP.
        int24 honest = sv.tick();
        int24 distorted = honest - 5000;
        sv.setTick(distorted);
        for (uint256 i = 0; i < 256; i++) {
            vm.warp(block.timestamp + 4);
            oracle.poke(pool);
        }
        (int24 twap, uint32 covered) = oracle.twapTick(pool, TWAP_WINDOW);
        emit log_named_int("twap tick (honest 1000, distorted -4000)", twap);
        assertEq(covered, 1020);
        assertEq(twap, distorted, "the 30-min TWAP collapses to a 17-min one fully at the distorted tick");
    }
}
