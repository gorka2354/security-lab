// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

// Standalone (no imports) so Slither compiles it with bare solc in CI.
// Used to PROVE hypothesize.py's Grade B (Slither dataflow) engages and is
// transitive: setA writes `a` THROUGH an internal helper -> all_state_variables_written
// must attribute `a` to setA (the call-graph closure a regex would miss).
contract StateGraph {
    uint256 public a;
    uint256 public b;

    function setA(uint256 x) external {
        _writeA(x);
    }

    function _writeA(uint256 x) internal {
        a = x;
    }

    function setBoth(uint256 x) external {
        a = x;
        b = x;
    }
}
