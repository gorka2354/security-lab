// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

// Minimal stub (PoC): the executor only calls SafeApprove.safeApprove in the else branch.
library SafeApprove {
    function safeApprove(address token, address spender, uint256 amount) internal {
        IERC20(token).approve(spender, amount);
    }
}
