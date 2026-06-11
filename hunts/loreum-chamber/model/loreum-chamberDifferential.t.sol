// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
// import {loreum-chamber} from "../src/loreum-chamber.sol";   // TODO: fix path

// Foundry DIFFERENTIAL test for loreum-chamber: a clean REFERENCE reimplementation of ONE suspect formula,
// fuzzed against the live contract. assertEq(reference(x), target.f(x)) for ALL x -> any divergence
// is a bug in one of them. No RPC needed when you have the source. The Ledgity method, in-repo.
//   run (WSL/CI): forge test --mc loreum-chamberDifferential

library loreum-chamberReference {
    // TODO: reimplement the suspect function from the SPEC (not by copying the contract).
    function f(uint256 x) internal pure returns (uint256) {
        return x; // <-- replace with the spec-faithful formula
    }
}

contract loreum-chamberDifferential is Test {
    // loreum-chamber internal target;

    function setUp() public {
        // target = new loreum-chamber(/* concrete ctor args */);
    }

    function testFuzz_diff(uint256 x) public {
        x = bound(x, 0, 1e30);
        // assertEq(loreum-chamberReference.f(x), target.f(x), "DIVERGENCE -> a bug in the contract or the ref");
    }
}
