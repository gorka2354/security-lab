// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "forge-std/Test.sol";

interface IFWA {
    function listings(uint256) external view returns (address,address,address,uint256,uint256,uint256,uint256,uint256,uint256,uint64,uint8);
    function nextListingId() external view returns (uint256);
    function quoteAcquisitionPrice() external view returns (uint256,uint256,uint256);
    function acquire(address,uint256,uint256,uint256,uint256) external payable returns (uint256[] memory);
    function withdrawListing(uint256) external;
    function updateBacking(uint256,uint256) external payable;
    function claimTopSpot(uint256) external;
    function kickListing(uint256) external;
    function unsettledAcquisitionCount() external view returns (uint256);
    function acquisitions(uint256) external view returns (address,uint256,uint256,uint256,uint8);
    function rawFulfillRandomWords(uint256, uint256[] calldata) external;
    function vrfCoordinatorAndSubId() external view returns (address, uint256);
    function isPurchaseBlackout() external view returns (bool);
    function processAcquisitions(uint256) external returns (uint256);
    function totalWeight() external view returns (uint256);
    function weightedBackingTotal() external view returns (uint256);
    function activateListings(uint256) external;
}

contract LockCheck is Test {
    IFWA constant F = IFWA(0x958C41181182e76F221331b2755b77D9e1426A98);
    bytes4 constant WITHDRAW_LOCKED = bytes4(keccak256("WithdrawLocked()"));

    function _findActive() internal view returns (uint256 id, address dep, uint256 val) {
        uint256 n = F.nextListingId();
        for (uint256 i = n - 1; i > n - 400; i--) {
            (, address d,,,, uint256 v,,,,, uint8 st) = F.listings(i);
            if (st == 1) return (i, d, v);
        }
        revert("no active listing found");
    }

    function test_postRevealPoolIsFrozen() public {
        vm.txGasPrice(2 gwei);
        if (F.isPurchaseBlackout()) vm.warp(block.timestamp + 20 minutes);
        (uint256 L, address D, uint256 V) = _findActive();
        uint256 tw0 = F.totalWeight();
        uint256 wv0 = F.weightedBackingTotal();
        emit log_named_uint("active listing probed", L);

        uint256 u0 = F.unsettledAcquisitionCount(); // live in-flight requests at the fork block
        emit log_named_uint("pre-existing unsettled", u0);
        address P = makeAddr("purchaser");
        (,, uint256 total) = F.quoteAcquisitionPrice();
        vm.deal(P, 10 ether);
        vm.prank(P);
        uint256[] memory ids = F.acquire{value: total * 2}(P, 2, 0, 0, 1000);
        assertEq(F.unsettledAcquisitionCount(), u0 + 2, "two more unsettled");

        // Reveal the SECOND word first: it is cached (Ready=5) but cannot be processed out of order.
        (address coord,) = F.vrfCoordinatorAndSubId();
        uint256[] memory w = new uint256[](1);
        w[0] = uint256(keccak256("word-2"));
        vm.prank(coord);
        F.rawFulfillRandomWords(ids[1], w);
        (,,,, uint8 st1) = F.acquisitions(ids[1]);
        assertEq(st1, 5, "second word cached as Ready, not processed");
        if (u0 == 0) assertEq(F.processAcquisitions(10), 0, "head still pending -> nothing processable");
        else F.processAcquisitions(10); // may settle live Ready heads; our #1 is still Pending -> #2 must wait
        (,,,, uint8 st1b) = F.acquisitions(ids[1]);
        assertEq(st1b, 5, "#2 still Ready (cannot jump the queue)");

        // With a revealed word outstanding, every pool-shaping action of a depositor must revert.
        vm.startPrank(D);
        vm.expectRevert(WITHDRAW_LOCKED); F.withdrawListing(L);
        vm.expectRevert(WITHDRAW_LOCKED); F.updateBacking(L, V + 1);
        vm.expectRevert(WITHDRAW_LOCKED); F.updateBacking(L, V / 2 > 0.01 ether ? V / 2 : V - 1);
        vm.expectRevert(WITHDRAW_LOCKED); F.claimTopSpot(L);
        vm.stopPrank();
        F.activateListings(50); // no-op while unsettled
        assertEq(F.totalWeight(), tw0, "tree weight unchanged after reveal");
        assertEq(F.weightedBackingTotal(), wv0, "EV unchanged after reveal");

        // Now reveal the head: fast path settles it; then the ordered processor settles #2.
        w[0] = uint256(keccak256("word-1"));
        vm.prank(coord);
        F.rawFulfillRandomWords(ids[0], w);
        vm.roll(block.number + 40); // let any live Pending head (no callback on a fork) expire in order
        F.processAcquisitions(20);
        (,,, uint256 l0, uint8 s0) = F.acquisitions(ids[0]);
        (,,, uint256 l1, uint8 s1) = F.acquisitions(ids[1]);
        emit log_named_uint("req1 status", s0); emit log_named_uint("req1 listing", l0);
        emit log_named_uint("req2 status", s1); emit log_named_uint("req2 listing", l1);
        assertEq(F.unsettledAcquisitionCount(), 0, "all settled");
        // Replay of a word after terminal status is ignored (no re-roll).
        vm.prank(coord);
        F.rawFulfillRandomWords(ids[1], w);
        (,,, uint256 l1b, uint8 s1b) = F.acquisitions(ids[1]);
        assertEq(l1b, l1); assertEq(s1b, s1);
    }
}
