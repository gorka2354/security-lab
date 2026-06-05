// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// Minimal, faithful reproduction of the Nomad Bridge bug (Aug 2022, ~$190M).
/// Strips away the real Merkle/proxy machinery and keeps ONLY the vulnerable
/// trust logic, so the bug is visible in a few lines. Educational PoC.

// ─── A tiny token the bridge "holds" ──────────────────────────────
contract MockERC20 {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amt) external {
        balanceOf[to] += amt;
    }

    function transfer(address to, uint256 amt) external returns (bool) {
        require(balanceOf[msg.sender] >= amt, "insufficient");
        balanceOf[msg.sender] -= amt;
        balanceOf[to] += amt;
        return true;
    }
}

// ─── The vault that releases funds when a message is "proven" ──────
contract Bridge {
    MockERC20 public token;
    address public replica;

    constructor(MockERC20 _token) {
        token = _token;
    }

    function setReplica(address _replica) external {
        replica = _replica;
    }

    function release(address to, uint256 amount) external {
        require(msg.sender == replica, "only replica");
        token.transfer(to, amount);
    }
}

// ─── The VULNERABLE Replica (message authenticator) ───────────────
contract Replica {
    // messageHash => the Merkle root that proved it. 0 == never proven.
    mapping(bytes32 => bytes32) public messages;
    // Merkle root => timestamp it became acceptable. 0 == not acceptable.
    mapping(bytes32 => uint256) public confirmAt;

    Bridge public bridge;
    bytes32 constant PROCESSED = bytes32(uint256(2));

    constructor(Bridge _bridge) {
        bridge = _bridge;
        // ---------------- THE FATAL UPGRADE ----------------
        // A Replica deployed next to an EMPTY Home has an empty Merkle tree,
        // whose root is bytes32(0). The upgrade marked that root "acceptable".
        // One innocent line that turns the guard below into require(true).
        confirmAt[bytes32(0)] = 1;
        // ---------------------------------------------------
    }

    function acceptableRoot(bytes32 _root) public view returns (bool) {
        uint256 _time = confirmAt[_root];
        if (_time == 0) return false;        // unknown root -> reject
        return block.timestamp >= _time;     // otherwise accept
    }

    function process(bytes calldata message) external returns (bool) {
        bytes32 messageHash = keccak256(message);
        // The ONLY guard. For a forged (never-proven) message,
        // messages[messageHash] is 0  ->  acceptableRoot(0) is true.
        require(acceptableRoot(messages[messageHash]), "!proven");
        messages[messageHash] = PROCESSED;

        (address recipient, uint256 amount) = abi.decode(message, (address, uint256));
        bridge.release(recipient, amount);
        return true;
    }
}

// ─── The FIXED Replica (one defensive line) ───────────────────────
contract ReplicaFixed {
    mapping(bytes32 => bytes32) public messages;
    mapping(bytes32 => uint256) public confirmAt;
    Bridge public bridge;
    bytes32 constant PROCESSED = bytes32(uint256(2));

    constructor(Bridge _bridge) {
        bridge = _bridge;
        confirmAt[bytes32(0)] = 1; // even WITH the buggy init...
    }

    function acceptableRoot(bytes32 _root) public view returns (bool) {
        if (_root == bytes32(0)) return false;   // ...this line neutralises the class
        uint256 _time = confirmAt[_root];
        if (_time == 0) return false;
        return block.timestamp >= _time;
    }

    function process(bytes calldata message) external returns (bool) {
        bytes32 messageHash = keccak256(message);
        require(acceptableRoot(messages[messageHash]), "!proven");
        messages[messageHash] = PROCESSED;
        (address recipient, uint256 amount) = abi.decode(message, (address, uint256));
        bridge.release(recipient, amount);
        return true;
    }
}
