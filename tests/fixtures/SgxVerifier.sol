// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Minimal SgxVerifier-style trust anchor — the Taiko/Raiko key-leak class (June 2026, ~$1.7M). Educational fixture.
/// registerInstance trusts ANY enclave whose measurement == the stored mrSigner; any registered instance's
/// signature finalizes a state root. No M-of-N quorum, no revocation -> one leaked enclave key forges everything.
contract SgxVerifier {
    bytes32 public mrSigner;                       // the single off-chain trust anchor (leaked .pem in raiko)
    mapping(address => bool) public trustedInstance;

    function registerInstance(bytes32 measurement, address instance) external {
        require(measurement == mrSigner, "bad enclave");   // any matching enclave becomes trusted
        trustedInstance[instance] = true;
    }

    function verifyProof(address prover, bytes32 stateRoot, bytes calldata sig) external view returns (bool) {
        require(trustedInstance[prover], "unknown prover");
        return _recover(stateRoot, sig) == prover;          // a lone trusted prover finalizes the root
    }

    function _recover(bytes32 h, bytes calldata sig) internal pure returns (address) {
        return address(uint160(uint256(h) ^ sig.length));
    }
}
