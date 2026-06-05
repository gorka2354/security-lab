// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {YoOracle} from "../src/YoOracle.sol";

address constant VAULT = address(0xBEEF);
uint64 constant WINDOW = 1 days;
uint64 constant MAXBPS = 10_000_000; // 1e7 / 1e9 = 1% (matches the docstring "1%")
uint256 constant BPS = 1_000_000_000;

/// The fuzzer drives this: the updater pushes prices WITHIN maxBps of the current
/// anchor (so they pass), and warps time so the anchor rotates — letting drift
/// accumulate. This is the honest, protocol-specific handler.
contract OracleHandler is Test {
    YoOracle public oracle;
    address public updater;
    uint256 public initialPrice;

    constructor(YoOracle _o, address _updater) {
        oracle = _o;
        updater = _updater;
    }

    function pushPrice(uint256 seed, bool up) public {
        (, uint256 anchor,,,, uint64 mb) = oracle.oracleData(VAULT);
        uint256 maxB = mb != 0 ? mb : oracle.DEFAULT_MAX_CHANGE_BPS();
        uint256 base = anchor == 0 ? 1e18 : anchor;
        uint256 delta = base * bound(seed, 0, maxB) / BPS;
        uint256 price = up ? base + delta : (delta < base ? base - delta : 1);
        if (price == 0) price = 1;
        vm.prank(updater);
        try oracle.updateSharePrice(VAULT, price) {
            if (initialPrice == 0) initialPrice = price;
        } catch {}
    }

    function warp(uint256 dt) public {
        skip(bound(dt, 1 hours, 2 days));
    }
}

contract YoOracleInvariants is Test {
    YoOracle oracle;
    OracleHandler handler;
    address updater = address(0xABCD);

    function setUp() public {
        vm.warp(1_700_000_000);
        oracle = new YoOracle(updater, WINDOW, MAXBPS);
        handler = new OracleHandler(oracle, updater);
        bytes4[] memory sel = new bytes4[](2);
        sel[0] = OracleHandler.pushPrice.selector;
        sel[1] = OracleHandler.warp.selector;
        targetContract(address(handler));
        targetSelector(FuzzSelector({addr: address(handler), selectors: sel}));
    }

    /// I1 (CORE GUARANTEE, derived from the code's intent):
    /// latest is always within maxChangeBps of the anchor. SHOULD HOLD.
    function invariant_I1_latest_within_maxchange_of_anchor() public view {
        (uint256 latest, uint256 anchor,,,, uint64 mb) = oracle.oracleData(VAULT);
        if (anchor == 0 || latest == 0) return;
        uint256 maxB = mb != 0 ? mb : oracle.DEFAULT_MAX_CHANGE_BPS();
        uint256 diff = latest > anchor ? latest - anchor : anchor - latest;
        uint256 diffBps = diff * BPS / anchor;
        assertLe(diffBps, maxB, "I1 BROKEN: latest deviates from anchor > maxChangeBps");
    }

    /// I2 (NAIVE expectation): latest within maxChangeBps of the INITIAL price.
    /// EXPECTED TO FAIL — anchor rotation lets the price drift cumulatively far
    /// beyond maxChangeBps. The fuzzer reveals what naive reasoning misses.
    function invariant_I2_no_cumulative_drift() public view {
        uint256 init = handler.initialPrice();
        if (init == 0) return;
        (uint256 latest,,,,,) = oracle.oracleData(VAULT);
        if (latest == 0) return;
        uint256 diff = latest > init ? latest - init : init - latest;
        uint256 driftBps = diff * BPS / init;
        assertLe(driftBps, oracle.DEFAULT_MAX_CHANGE_BPS(),
            "I2 (naive) BROKEN: cumulative drift exceeds maxChangeBps");
    }
}
