// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// H1 PoC: can permissionless rebalance() leave a HEALTHY vault liquidatable?
// Mechanism under test: _collateralScaledByLiqLTV1e8 includes intermediateVault.cash() in the
// invariant target (isRebalancing=true) but NOT in the liquidation check (isRebalancing=false).
// Reachable only when twyneLiqLTV > floor (chosen leg > floor) AND cash() is large enough that the
// cash-inflated dynamic leg exceeds the chosen leg -> min() switches to chosen -> invariant drops
// below totalAssets -> excess credit -> rebalance() releases it. We then re-check canLiquidate().

import {EulerTestBase} from "./EulerTestBase.t.sol";
import {console2} from "../MainnetBase.t.sol";
import {IEVC} from "ethereum-vault-connector/interfaces/IEthereumVaultConnector.sol";
import {IEVault} from "euler-vault-kit/EVault/IEVault.sol";
import {EulerCollateralVault} from "src/twyne/EulerCollateralVault.sol";
import {CollateralVaultFactory, VaultType} from "src/TwyneFactory/CollateralVaultFactory.sol";
import {IERC20} from "openzeppelin-contracts/token/ERC20/IERC20.sol";
import {Math} from "openzeppelin-contracts/utils/math/Math.sol";

contract H1_RebalanceHealth is EulerTestBase {

    function _logState(string memory tag, EulerCollateralVault v) internal {
        uint ta = v.totalAssetsDepositedOrReserved();
        uint mr = v.maxRelease();
        uint cash = v.intermediateVault().cash();
        console2.log(tag);
        console2.log("  totalAssetsDepositedOrReserved:", ta);
        console2.log("  maxRelease (C_LP debt):", mr);
        console2.log("  userColl (ta-maxRelease):", ta - mr);
        console2.log("  intermediateVault.cash():", cash);
        console2.log("  twyneLiqLTV:", v.twyneLiqLTV());
        try v.canRebalance() returns (uint ex) { console2.log("  canRebalance excess:", ex); }
        catch { console2.log("  canRebalance: REVERT (no excess)"); }
        try v.canLiquidate() returns (bool b) { console2.log("  canLiquidate:", b); }
        catch { console2.log("  canLiquidate: REVERT"); }
    }

    function test_H1_cashSpikeThenRebalance() public noGasMetering {
        address collateralAsset = eulerWETH;
        // Bob seeds the intermediate vault
        e_creditDeposit(collateralAsset);

        uint16 highLTV = twyneVaultManager.maxTwyneLTVs(intermediateVaultFor[collateralAsset]); // 0.93e4
        // floor = extLiqLTV * buffer / MAXFACTOR ; require highLTV in band
        uint16 extLiq = IEVault(eulerUSDC).LTVLiquidation(collateralAsset);
        uint16 buffer = twyneVaultManager.externalLiqBuffers(intermediateVaultFor[collateralAsset]);
        require(uint(extLiq) * uint(buffer) <= uint(highLTV) * MAXFACTOR, "ltv below floor");

        // Alice creates a vault at the MAX twyne LTV (chosen leg > floor -> cash term matters)
        vm.startPrank(alice);
        alice_collateral_vault = EulerCollateralVault(
            collateralVaultFactory.createCollateralVault({
                _vaultType: VaultType.EULER_V2,
                _intermediateVault: intermediateVaultFor[collateralAsset],
                _targetVault: eulerUSDC,
                _liqLTV: highLTV,
                _targetAsset: address(0)
            })
        );
        vm.label(address(alice_collateral_vault), "alice_collateral_vault");

        // deposit collateral + borrow a conservative amount (well within health)
        IERC20(collateralAsset).approve(address(alice_collateral_vault), type(uint).max);

        uint oneEther = 1 ether;
        uint borrowAmountInETH = oneEther * uint(IEVault(eulerUSDC).LTVLiquidation(collateralAsset)) * uint(buffer) / (MAXFACTOR * MAXFACTOR) / 2; // half of floor-LTV cap = conservative
        uint borrowValueInUSD = eulerOnChain.getQuote(borrowAmountInETH, collateralAsset, USD);
        uint USDCPrice = eulerOnChain.getQuote(1, USDC, USD);
        uint borrowAmountInUSDC = borrowValueInUSD / USDCPrice;

        IEVC.BatchItem[] memory items = new IEVC.BatchItem[](2);
        items[0] = IEVC.BatchItem({ targetContract: address(alice_collateral_vault), onBehalfOfAccount: alice, value: 0,
            data: abi.encodeCall(alice_collateral_vault.deposit, (COLLATERAL_AMOUNT)) });
        items[1] = IEVC.BatchItem({ targetContract: address(alice_collateral_vault), onBehalfOfAccount: alice, value: 0,
            data: abi.encodeCall(alice_collateral_vault.borrow, (borrowAmountInUSDC, alice)) });
        evc.batch(items);
        vm.stopPrank();

        _logState("[t0] after open (high LTV)", alice_collateral_vault);
        bool h0 = alice_collateral_vault.canLiquidate();
        require(!h0, "precondition: vault must start healthy");

        // --- Spike intermediate vault cash() via a large Bob deposit ---
        vm.startPrank(bob);
        IERC20(collateralAsset).approve(intermediateVaultFor[collateralAsset], type(uint).max);
        uint bobBal = IERC20(collateralAsset).balanceOf(bob);
        IEVault(intermediateVaultFor[collateralAsset]).deposit(bobBal, bob);
        vm.stopPrank();

        _logState("[t1] after cash spike", alice_collateral_vault);

        // If now rebalanceable, a third party exercises it
        bool rebalanceable;
        try alice_collateral_vault.canRebalance() returns (uint ex) { rebalanceable = ex > 0; } catch { rebalanceable = false; }
        if (!rebalanceable) {
            emit log("INCONCLUSIVE: cash spike did not create excess credit (rebalance window not reached)");
            return;
        }

        vm.prank(eve);
        alice_collateral_vault.rebalance();

        _logState("[t2] after permissionless rebalance by eve", alice_collateral_vault);
        bool h1 = alice_collateral_vault.canLiquidate();

        if (!h0 && h1) emit log("H1 CONFIRMED: permissionless rebalance() flipped healthy -> liquidatable");
        assertFalse(!h0 && h1, "H1: permissionless rebalance made a healthy vault liquidatable");
    }
}
