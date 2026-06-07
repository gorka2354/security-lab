// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IERC20} from "../IERC20.sol";

// Minimal SafeERC20 stub (PoC) - same surface the real executor uses.
library SafeERC20 {
    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        require(token.transfer(to, value), "SafeERC20: transfer failed");
    }

    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
        require(token.transferFrom(from, to, value), "SafeERC20: transferFrom failed");
    }

    function forceApprove(IERC20 token, address spender, uint256 value) internal {
        token.approve(spender, value);
    }
}
