// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Test, console2} from "forge-std/Test.sol";
import {Stash} from "../src/Stash.sol";
import {IStashFactory} from "../src/interfaces/IStashFactory.sol";
import {ICryptoPunks} from "../src/interfaces/ICryptoPunks.sol";
import {IWETH} from "../src/interfaces/IWETH.sol";
import {Order, PunkBid} from "../src/helpers/Struct.sol";
import {OrderType} from "../src/helpers/Enum.sol";

/*//////////////////////////////////////////////////////////////
                 ADVERSARIAL MAINNET-FORK PoC
   Target: Stash (Yuga Labs / Lightyear "Stash") CryptoPunks terminal
   Goal:   CONFIRM-OR-KILL the 4 bid/liquidity economic leads by trying
           HARD to break conservation on a real ethereum-mainnet fork.
//////////////////////////////////////////////////////////////*/

// Minimal whitelisted-auction stand-in. The Stash only ever calls
// bidConfig() and finalized() on an auction, plus receives ETH/WETH on
// processOrder. We stand in for a factory-whitelisted auction (the
// whitelist itself is faked via vm.mockCall on the real factory).
contract MockAuction {
    address public immutable paymentToken;
    OrderType public immutable orderTypeVal;
    bool public finalizedVal;

    constructor(address pt, OrderType ot) {
        paymentToken = pt;
        orderTypeVal = ot;
    }

    function bidConfig() external view returns (address, OrderType) {
        return (paymentToken, orderTypeVal);
    }

    function finalized() external view returns (bool) {
        return finalizedVal;
    }

    function setFinalized(bool f) external {
        finalizedVal = f;
    }

    // The auction pulls its locked funds from the Stash. processOrder pays msg.sender.
    function pull(Stash stash, uint80 costPerUnit, uint16 units) external {
        stash.processOrder(costPerUnit, units);
    }

    receive() external payable {}
}

// Reentrant filler used to prove CEI-safety of the final payout call.
contract ReentrantFiller {
    Stash public stash;
    PunkBid internal storedBid;
    bytes internal storedSig;
    bytes32[] internal storedProof;
    uint256 public storedPunk;

    bool public reentered;
    bool public reentrySucceeded;
    uint256 public received;

    function arm(
        Stash _stash,
        PunkBid calldata bid,
        uint256 punkIndex,
        bytes calldata sig,
        bytes32[] calldata proof
    ) external {
        stash = _stash;
        storedBid = bid;
        storedPunk = punkIndex;
        storedSig = sig;
        for (uint256 i = 0; i < proof.length; i++) storedProof.push(proof[i]);
    }

    function attack() external {
        stash.processPunkBid(storedBid, storedPunk, storedSig, storedProof);
    }

    receive() external payable {
        received += msg.value;
        if (!reentered) {
            reentered = true;
            // Re-enter with the SAME bid. If CEI is respected the nonce is
            // already burned, so this inner call MUST revert.
            try stash.processPunkBid(storedBid, storedPunk, storedSig, storedProof) {
                reentrySucceeded = true;
            } catch {
                reentrySucceeded = false;
            }
        }
    }
}

contract StashForkTest is Test {
    // -------- mainnet addresses --------
    address constant STASH_FACTORY = 0x000000000000A6fA31F5fC51c1640aAc76866750;
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant CRYPTOPUNKS = 0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB;

    // -------- EIP-712 typehashes (mirror Stash.sol) --------
    bytes32 constant ORDER_TYPEHASH = keccak256("Order(uint16 numberOfUnits,uint80 pricePerUnit,address auction)");
    bytes32 constant PUNK_BID_TYPEHASH = keccak256(
        "PunkBid(Order order,uint256 accountNonce,uint256 bidNonce,uint256 expiration,bytes32 root)Order(uint16 numberOfUnits,uint80 pricePerUnit,address auction)"
    );
    bytes32 constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(uint256 chainId,address verifyingContract)");

    uint256 constant OWNER_PK = 0xA11CE;
    address owner;

    IStashFactory factory = IStashFactory(STASH_FACTORY);
    ICryptoPunks punks = ICryptoPunks(CRYPTOPUNKS);
    IWETH weth = IWETH(WETH);

    Stash stash;

    // real, EOA-owned, unwrapped punks found on the fork (for the for-sale branch)
    uint256[] eoaPunks;
    mapping(uint256 => address) punkOwner;

    function setUp() public {
        string memory url = vm.envOr("FORK_URL", string("https://ethereum-rpc.publicnode.com"));
        uint256 blk = vm.envOr("FORK_BLOCK", uint256(25755766));
        vm.createSelectFork(url, blk);

        owner = vm.addr(OWNER_PK);
        vm.label(owner, "STASH_OWNER");
        vm.label(CRYPTOPUNKS, "CryptoPunks");
        vm.label(WETH, "WETH");

        // Deploy a real Stash proxy for `owner` via the live factory (permissionless).
        address s = factory.deployStash(owner);
        stash = Stash(payable(s));
        vm.label(s, "STASH");
        assertEq(stash.owner(), owner, "owner set by factory");

        // Find a few EOA-owned, unwrapped punks so we can exercise the real
        // for-sale (buyPunk) branch. Scan a window of indices.
        for (uint256 i = 0; i < 250 && eoaPunks.length < 4; i++) {
            address o = punks.punkIndexToAddress(i);
            if (o == address(0)) continue;
            if (o.code.length != 0) continue; // skip wrapper/marketplace contracts -> keep true EOAs
            eoaPunks.push(i);
            punkOwner[i] = o;
        }
        require(eoaPunks.length >= 2, "need >=2 EOA-owned punks on fork");
    }

    /*//////////////////////////////////////////////////////////////
                              HELPERS
    //////////////////////////////////////////////////////////////*/

    function _digest(PunkBid memory bid) internal view returns (bytes32) {
        bytes32 orderHash =
            keccak256(abi.encode(ORDER_TYPEHASH, bid.order.numberOfUnits, bid.order.pricePerUnit, bid.order.auction));
        bytes32 hashStruct = keccak256(
            abi.encode(PUNK_BID_TYPEHASH, orderHash, bid.accountNonce, bid.bidNonce, bid.expiration, bid.root)
        );
        bytes32 domainHash = keccak256(abi.encode(DOMAIN_TYPEHASH, block.chainid, address(stash)));
        return keccak256(abi.encodePacked("\x19\x01", domainHash, hashStruct));
    }

    function _sign(PunkBid memory bid) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, _digest(bid));
        return abi.encodePacked(r, s, v);
    }

    // A collection-wide bid (root == 0 -> merkle check skipped -> ANY punk).
    function _mkBid(uint80 price, uint16 units, uint256 bidNonce) internal view returns (PunkBid memory bid) {
        bid.order = Order({numberOfUnits: units, pricePerUnit: price, auction: CRYPTOPUNKS});
        bid.accountNonce = stash.punkAccountNonce();
        bid.bidNonce = bidNonce;
        bid.expiration = 0; // never expires
        bid.root = bytes32(0); // collection bid
    }

    function _listForSaleToStash(uint256 punkIndex, uint256 minValue) internal {
        vm.prank(punkOwner[punkIndex]);
        punks.offerPunkForSaleToAddress(punkIndex, minValue, address(stash));
    }

    function _fundOwnerWeth(uint256 amount, uint256 allowance) internal {
        deal(WETH, owner, amount);
        vm.prank(owner);
        weth.approve(address(stash), allowance);
    }

    function _whitelistAuction(address auction) internal {
        vm.mockCall(
            STASH_FACTORY, abi.encodeWithSelector(IStashFactory.isAuction.selector, auction), abi.encode(true)
        );
    }

    // place an auction order as if `owner` initiated it through the auction
    function _placeOrder(MockAuction auction, uint80 price, uint16 units) internal {
        vm.prank(address(auction), owner); // msg.sender = auction, tx.origin = owner
        stash.placeOrder(price, units);
    }

    /*//////////////////////////////////////////////////////////////
      LEAD 1 -- FILLER ECONOMICS: total ETH out == bidPrice exactly;
                a malicious filler cannot extract more than bidPrice-minValue.
    //////////////////////////////////////////////////////////////*/

    function test_Lead1_FillerEconomics_ConservesToBidPrice() public {
        uint256 punkIndex = eoaPunks[0];
        uint80 bidPrice = 5 ether;
        uint256 minValue = 1 ether;

        vm.deal(address(stash), 100 ether);
        _listForSaleToStash(punkIndex, minValue);

        PunkBid memory bid = _mkBid(bidPrice, 1, 1);
        bytes memory sig = _sign(bid);
        bytes32[] memory proof = new bytes32[](0);

        // arbitrary, unrelated filler EOA (NOT the owner)
        address filler = makeAddr("MALICIOUS_FILLER");

        uint256 stashBefore = address(stash).balance;
        uint256 fillerBefore = filler.balance;
        uint256 sellerPendingBefore = punks.pendingWithdrawals(punkOwner[punkIndex]);

        vm.prank(filler);
        stash.processPunkBid(bid, punkIndex, sig, proof);

        uint256 stashOut = stashBefore - address(stash).balance;
        uint256 fillerGain = filler.balance - fillerBefore;
        uint256 sellerCredited = punks.pendingWithdrawals(punkOwner[punkIndex]) - sellerPendingBefore;

        // CONSERVATION: exactly bidPrice leaves the stash, split between seller(minValue) and filler(rest).
        assertEq(stashOut, bidPrice, "stash pays exactly bidPrice");
        assertEq(fillerGain, bidPrice - minValue, "filler gets exactly bidPrice - minValue");
        assertEq(sellerCredited, minValue, "seller credited exactly minValue");
        assertEq(stashOut, sellerCredited + fillerGain, "no free surplus / no leak");
        // owner actually received the punk it paid for
        assertEq(punks.punkIndexToAddress(punkIndex), owner, "owner received the punk");
    }

    // minValue > bidPrice must revert (cannot be forced to overpay a listed punk).
    function test_Lead1_MinValueAboveBid_Reverts() public {
        uint256 punkIndex = eoaPunks[0];
        uint80 bidPrice = 3 ether;

        vm.deal(address(stash), 100 ether);
        _listForSaleToStash(punkIndex, 4 ether); // listed ABOVE the signed bid

        PunkBid memory bid = _mkBid(bidPrice, 1, 7);
        bytes memory sig = _sign(bid);
        bytes32[] memory proof = new bytes32[](0);

        address filler = makeAddr("FILLER2");
        vm.prank(filler);
        vm.expectRevert(Stash.CannotTransferMoreThanBidAmount.selector);
        stash.processPunkBid(bid, punkIndex, sig, proof);
    }

    // Self-listed cheap punk (minValue == 0): filler pockets full bidPrice, but the
    // stash STILL pays only bidPrice total -> no over-extraction beyond signed intent.
    function test_Lead1_SelfListedZeroMinValue_NoOverExtraction() public {
        uint256 punkIndex = eoaPunks[0];
        uint80 bidPrice = 5 ether;

        vm.deal(address(stash), 100 ether);
        _listForSaleToStash(punkIndex, 0); // filler self-lists at 0

        PunkBid memory bid = _mkBid(bidPrice, 1, 9);
        bytes memory sig = _sign(bid);
        bytes32[] memory proof = new bytes32[](0);

        address filler = punkOwner[punkIndex]; // the lister IS the filler (worst case)
        uint256 stashBefore = address(stash).balance;

        vm.prank(filler);
        stash.processPunkBid(bid, punkIndex, sig, proof);

        assertEq(stashBefore - address(stash).balance, bidPrice, "stash still pays only bidPrice");
    }

    /*//////////////////////////////////////////////////////////////
      LEAD 2 -- TWO-RESERVATION DOUBLE-SPEND: an open ETH auction order
      LOCKS ETH; a punk bid tops up from WETH; the locked ETH must remain
      fully available to the auction (no double-spend across the systems).
    //////////////////////////////////////////////////////////////*/

    function test_Lead2_AuctionLockSurvivesPunkBid_NoDoubleSpend() public {
        MockAuction auction = new MockAuction(address(0), OrderType.UNREPLACEABLE);
        _whitelistAuction(address(auction));

        // Stash has only 5 ETH. Lock 4 ETH in an ETH auction order.
        vm.deal(address(stash), 5 ether);
        _placeOrder(auction, 4 ether, 1);
        assertEq(stash.totalLocked(address(0)), 4 ether, "4 ETH locked");
        assertEq(stash.availableLiquidity(address(0)), 1 ether, "1 ETH free");

        // A 5 ETH punk bid: availableETH(1) < 5 -> must top up 4 ETH from owner's WETH.
        _fundOwnerWeth(4 ether, type(uint256).max);

        uint256 punkIndex = eoaPunks[0];
        _listForSaleToStash(punkIndex, 5 ether); // minValue == bidPrice -> whole bid goes to seller

        PunkBid memory bid = _mkBid(5 ether, 1, 21);
        bytes memory sig = _sign(bid);
        bytes32[] memory proof = new bytes32[](0);

        address filler = makeAddr("FILLER_L2");
        vm.prank(filler);
        stash.processPunkBid(bid, punkIndex, sig, proof);

        // Invariant: after the punk bid, the stash STILL holds exactly the 4 ETH
        // locked by the auction order. The punk was funded purely from WETH top-up.
        assertEq(address(stash).balance, 4 ether, "locked 4 ETH untouched by punk bid");
        assertEq(stash.totalLocked(address(0)), 4 ether, "order still locks 4 ETH");
        assertEq(stash.availableLiquidity(address(0)), 0, "no free ETH");

        // The auction can still fully pull its 4 ETH -> the same ETH was NOT double-spent.
        // (measure delta: the mock's deterministic address may hold pre-existing fork dust)
        uint256 auctionBefore = address(auction).balance;
        auction.pull(stash, 4 ether, 1);
        assertEq(address(auction).balance - auctionBefore, 4 ether, "auction pulled its full locked ETH");
        assertEq(address(stash).balance, 0, "stash drained to exactly zero");
    }

    // The kill-shot for the double-spend theory: if the WETH top-up is NOT available,
    // the punk bid MUST revert rather than dip into ETH locked by the auction order.
    function test_Lead2_CannotSpendLockedETH_WhenNoWethTopUp() public {
        MockAuction auction = new MockAuction(address(0), OrderType.UNREPLACEABLE);
        _whitelistAuction(address(auction));

        vm.deal(address(stash), 5 ether);
        _placeOrder(auction, 4 ether, 1); // locks 4 ETH, 1 ETH free

        // Owner has NO usable WETH (no balance, no allowance) -> top-up impossible.
        _fundOwnerWeth(0, 0);

        uint256 punkIndex = eoaPunks[0];
        _listForSaleToStash(punkIndex, 5 ether);

        PunkBid memory bid = _mkBid(5 ether, 1, 22);
        bytes memory sig = _sign(bid);
        bytes32[] memory proof = new bytes32[](0);

        address filler = makeAddr("FILLER_L2B");
        vm.prank(filler);
        vm.expectRevert(); // WETH.transferFrom reverts -> cannot touch the locked 4 ETH
        stash.processPunkBid(bid, punkIndex, sig, proof);

        // Locked ETH is fully intact and still claimable.
        assertEq(address(stash).balance, 5 ether, "no ETH left the stash");
        uint256 auctionBefore = address(auction).balance;
        auction.pull(stash, 4 ether, 1);
        assertEq(address(auction).balance - auctionBefore, 4 ether, "auction lock honored");
    }

    /*//////////////////////////////////////////////////////////////
      LEAD 4 -- WETH OVER-PULL: _swapWETH pulls only the shortfall (bounded
      by allowance) and never consumes WETH locked by a WETH-denominated order.
    //////////////////////////////////////////////////////////////*/

    function test_Lead4_SwapWeth_PreservesWethOrderLock_AndPullsOnlyShortfall() public {
        MockAuction wethAuction = new MockAuction(WETH, OrderType.UNREPLACEABLE);
        _whitelistAuction(address(wethAuction));

        // Stash holds 6 WETH, 0 ETH. Lock 4 WETH in a WETH-denominated order -> 2 WETH free.
        deal(WETH, address(stash), 6 ether);
        _placeOrder(wethAuction, 4 ether, 1);
        assertEq(stash.totalLocked(WETH), 4 ether, "4 WETH locked");
        assertEq(stash.availableLiquidity(WETH), 2 ether, "2 WETH free");

        // 5 ETH punk bid, stash ETH = 0 -> shortfall 5. Free WETH covers 2, owner must supply 3.
        deal(WETH, owner, 10 ether); // owner has plenty
        vm.prank(owner);
        weth.approve(address(stash), type(uint256).max);
        uint256 ownerWethBefore = weth.balanceOf(owner);

        uint256 punkIndex = eoaPunks[0];
        _listForSaleToStash(punkIndex, 5 ether);

        PunkBid memory bid = _mkBid(5 ether, 1, 41);
        bytes memory sig = _sign(bid);
        bytes32[] memory proof = new bytes32[](0);

        address filler = makeAddr("FILLER_L4");
        vm.prank(filler);
        stash.processPunkBid(bid, punkIndex, sig, proof);

        // Owner supplied EXACTLY the 3 ETH shortfall (not more).
        assertEq(ownerWethBefore - weth.balanceOf(owner), 3 ether, "owner over-pull bounded to shortfall (3)");
        // The 4 WETH locked by the WETH order is fully preserved in the stash.
        assertEq(weth.balanceOf(address(stash)), 4 ether, "WETH order lock untouched");
        assertEq(stash.totalLocked(WETH), 4 ether, "WETH order still locks 4");

        // The WETH auction can still pull its full 4 WETH -> not double-spent.
        wethAuction.pull(stash, 4 ether, 1);
        assertEq(weth.balanceOf(address(wethAuction)), 4 ether, "WETH auction pulled full lock");
        assertEq(weth.balanceOf(address(stash)), 0, "stash WETH drained to zero");
    }

    // Allowance-bounded: if the owner approves less than the shortfall, the pull
    // (and the whole bid) reverts -> cannot over-pull owner WETH.
    function test_Lead4_AllowanceBoundsThePull() public {
        vm.deal(address(stash), 1 ether); // availableETH = 1
        // shortfall for a 5 ETH bid = 4; owner has WETH but approves only 3 (< 4).
        deal(WETH, owner, 100 ether);
        vm.prank(owner);
        weth.approve(address(stash), 3 ether);

        uint256 punkIndex = eoaPunks[0];
        _listForSaleToStash(punkIndex, 5 ether);

        PunkBid memory bid = _mkBid(5 ether, 1, 42);
        bytes memory sig = _sign(bid);
        bytes32[] memory proof = new bytes32[](0);

        address filler = makeAddr("FILLER_L4B");
        vm.prank(filler);
        vm.expectRevert(); // WETH.transferFrom exceeds allowance -> revert
        stash.processPunkBid(bid, punkIndex, sig, proof);
    }

    /*//////////////////////////////////////////////////////////////
      LEAD 3 -- NONCE / REPLAY: cancel wins over process; multi-use is
      bounded by numberOfUnits; a used single-use bid cannot be replayed.
    //////////////////////////////////////////////////////////////*/

    function test_Lead3_CancelBeatsProcess() public {
        vm.deal(address(stash), 100 ether);
        uint256 punkIndex = eoaPunks[0];
        _listForSaleToStash(punkIndex, 1 ether);

        PunkBid memory bid = _mkBid(5 ether, 1, 31);
        bytes memory sig = _sign(bid);
        bytes32[] memory proof = new bytes32[](0);

        // owner cancels the bid nonce
        vm.prank(owner);
        stash.cancelPunkBid(31);

        address filler = makeAddr("FILLER_L3");
        vm.prank(filler);
        vm.expectRevert(Stash.BidCanceled.selector);
        stash.processPunkBid(bid, punkIndex, sig, proof);
    }

    function test_Lead3_SingleUseCannotReplay() public {
        vm.deal(address(stash), 100 ether);
        uint256 p0 = eoaPunks[0];
        _listForSaleToStash(p0, 1 ether);

        PunkBid memory bid = _mkBid(5 ether, 1, 33);
        bytes memory sig = _sign(bid);
        bytes32[] memory proof = new bytes32[](0);

        address filler = makeAddr("FILLER_L3B");
        vm.prank(filler);
        stash.processPunkBid(bid, p0, sig, proof); // first (and only) use

        // replay the exact same signed bid -> reverts at the burned-nonce check
        // (L304, before any punk interaction), so no re-listing is required.
        vm.prank(filler);
        vm.expectRevert(Stash.BidCanceled.selector);
        stash.processPunkBid(bid, p0, sig, proof);
    }

    function test_Lead3_MultiUseBoundedByNumberOfUnits() public {
        require(eoaPunks.length >= 2, "need 2 punks");
        vm.deal(address(stash), 100 ether);

        uint256 p0 = eoaPunks[0];
        uint256 p1 = eoaPunks[1];

        // multi-use bid: numberOfUnits = 2 -> exactly two fills allowed.
        PunkBid memory bid = _mkBid(5 ether, 2, 35);
        bytes memory sig = _sign(bid);
        bytes32[] memory proof = new bytes32[](0);

        address filler = makeAddr("FILLER_L3C");

        _listForSaleToStash(p0, 1 ether);
        vm.prank(filler);
        stash.processPunkBid(bid, p0, sig, proof); // use 1/2
        assertEq(stash.punkBidNonceUsesRemaining(35), 1, "1 use remaining");

        _listForSaleToStash(p1, 1 ether);
        vm.prank(filler);
        stash.processPunkBid(bid, p1, sig, proof); // use 2/2
        assertTrue(stash.usedPunkBidNonces(35), "nonce burned after 2 uses");

        // third attempt must revert -> cannot exceed numberOfUnits
        vm.prank(owner);
        punks.offerPunkForSaleToAddress(p0, 1 ether, address(stash));
        vm.prank(filler);
        vm.expectRevert(Stash.BidCanceled.selector);
        stash.processPunkBid(bid, p0, sig, proof);
    }

    /*//////////////////////////////////////////////////////////////
      CLAIM D -- CEI SAFETY: the final payout to the filler cannot be
      re-entered to double-fill the same nonce.
    //////////////////////////////////////////////////////////////*/

    function test_ClaimD_ReentrancyOnPayout_IsBlockedByBurnedNonce() public {
        vm.deal(address(stash), 100 ether);
        uint256 punkIndex = eoaPunks[0];
        uint256 minValue = 1 ether;
        uint80 bidPrice = 5 ether;
        _listForSaleToStash(punkIndex, minValue);

        PunkBid memory bid = _mkBid(bidPrice, 1, 51);
        bytes memory sig = _sign(bid);
        bytes32[] memory proof = new bytes32[](0);

        ReentrantFiller evil = new ReentrantFiller();
        evil.arm(stash, bid, punkIndex, sig, proof);

        uint256 stashBefore = address(stash).balance;
        evil.attack();

        assertTrue(evil.reentered(), "filler re-entered on payout");
        assertFalse(evil.reentrySucceeded(), "re-entrant fill MUST fail (nonce already burned)");
        // Filler was paid exactly once: bidPrice - minValue.
        assertEq(evil.received(), bidPrice - minValue, "single payout only");
        // Stash lost exactly bidPrice total (one fill), not two.
        assertEq(stashBefore - address(stash).balance, bidPrice, "exactly one bidPrice left the stash");
    }
}
