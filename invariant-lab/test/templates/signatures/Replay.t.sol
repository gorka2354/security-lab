// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";

// ============================================================================
// TEMPLATE — research/patterns/signatures/cross-chain-and-aa.md  (Pattern 06)
//
// Property (§5): a signature valid under chainId A must be INVALID under chainId B.
// A cached EIP-712 domain separator (never recomputed when block.chainid changes) makes
// signatures replay across a fork / sibling chain (zkMarkets class).
//
// NOTE: this is a deterministic PROPERTY test (vm.chainId + vm.sign), not a stateful
// fuzz — signature binding is not sequence-shaped. The same shape covers nonce-reuse:
// add a nonce, consume it, assert the second use reverts.
//
// HOW TO USE: copy this file, replace MockPermit.domainSeparator() with your target's
// EIP-712 path; the test_fixed_* cases are the regression you want to keep green.
// ============================================================================

/// buggy=true caches the domain separator at deploy and never rebinds it to the live
/// chainId. buggy=false recomputes it whenever block.chainid changes (the OZ EIP712 fix).
contract MockPermit {
    bool public buggy;
    bytes32 internal immutable cachedSep;
    uint256 internal immutable cachedChainId;
    bytes32 internal constant TYPEHASH = keccak256("Permit(address owner,uint256 value,uint256 nonce)");

    constructor(bool _b) {
        buggy = _b;
        cachedChainId = block.chainid;
        cachedSep = _build();
    }

    function _build() internal view returns (bytes32) {
        return keccak256(abi.encode(keccak256("EIP712Domain(uint256 chainId)"), block.chainid));
    }

    function domainSeparator() public view returns (bytes32) {
        if (buggy) return cachedSep; // never rebinds -> replayable after a fork
        return block.chainid == cachedChainId ? cachedSep : _build();
    }

    function digestOf(address owner, uint256 value, uint256 nonce) public view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(TYPEHASH, owner, value, nonce));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function verify(address owner, uint256 value, uint256 nonce, uint8 v, bytes32 r, bytes32 s)
        public
        view
        returns (bool)
    {
        return ecrecover(digestOf(owner, value, nonce), v, r, s) == owner;
    }
}

contract ReplaySelfCheck is Test {
    uint256 internal constant PK = 0xA11CE;

    function _signOnOrigin(MockPermit p) internal returns (uint8 v, bytes32 r, bytes32 s, address owner) {
        owner = vm.addr(PK);
        bytes32 digest = p.digestOf(owner, 100, 0); // signed on the origin chain
        (v, r, s) = vm.sign(PK, digest);
    }

    function test_buggy_signatureReplaysAcrossFork() public {
        MockPermit p = new MockPermit(true);
        (uint8 v, bytes32 r, bytes32 s, address owner) = _signOnOrigin(p);
        assertTrue(p.verify(owner, 100, 0, v, r, s), "valid on the origin chain");
        vm.chainId(999); // a fork / different chain
        assertTrue(p.verify(owner, 100, 0, v, r, s), "BUG: same sig still valid after chainId change");
    }

    function test_fixed_signatureRejectedAfterFork() public {
        MockPermit p = new MockPermit(false);
        (uint8 v, bytes32 r, bytes32 s, address owner) = _signOnOrigin(p);
        assertTrue(p.verify(owner, 100, 0, v, r, s), "valid on the origin chain");
        vm.chainId(999);
        assertFalse(p.verify(owner, 100, 0, v, r, s), "fixed: sig rejected after chainId change");
    }

    /// The fixed separator rebinds for ANY other chain, not just one.
    function testFuzz_fixed_rejectedOnAnyOtherChain(uint64 newChain) public {
        vm.assume(newChain != 1 && newChain != 0); // origin chainId in forge is 1
        MockPermit p = new MockPermit(false);
        (uint8 v, bytes32 r, bytes32 s, address owner) = _signOnOrigin(p);
        vm.chainId(newChain);
        assertFalse(p.verify(owner, 100, 0, v, r, s), "fixed: must reject on every other chain");
    }
}
