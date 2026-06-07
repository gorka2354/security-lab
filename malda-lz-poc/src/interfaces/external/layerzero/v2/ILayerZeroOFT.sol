// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {MessagingReceipt, MessagingFee} from "./ILayerZeroEndpointV2.sol";

// Minimal stub: only the surface the real executor uses.
struct SendParam {
    uint32 dstEid;
    bytes32 to;
    uint256 amountLD;
    uint256 minAmountLD;
    bytes extraOptions;
    bytes composeMsg;
    bytes oftCmd;
}

interface ILayerZeroOFT {
    function send(SendParam calldata sendParam, MessagingFee calldata fee, address refundTo)
        external
        payable
        returns (MessagingReceipt memory, bytes memory);
}

interface ILayerZeroOFTWrapper {
    function deposit(address to, uint256 amount) external;
}
