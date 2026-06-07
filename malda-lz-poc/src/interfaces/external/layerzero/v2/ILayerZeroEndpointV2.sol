// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Minimal stub: only the structs the real executor + IOftMessageExecutor need.
struct MessagingFee {
    uint256 nativeFee;
    uint256 lzTokenFee;
}

struct MessagingReceipt {
    bytes32 guid;
    uint64 nonce;
    MessagingFee fee;
}
