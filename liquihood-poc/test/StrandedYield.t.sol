// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

import "../src/InterestRateModel.sol";
import "../src/MarketHoursPolicy.sol";
import "../src/InsuranceFund.sol";
import "../src/OracleRouter.sol";
import "../src/HealthFactorEngine.sol";
import "../src/IsolatedMarketController.sol";
import "../src/LiquidationManager.sol";
import "../src/LendingPool.sol";
import "../src/LHToken.sol";
import "../src/DebtToken.sol";

contract MockERC20 is ERC20 {
    constructor(string memory n, string memory s) ERC20(n, s) {}
    function mint(address to, uint256 amt) external { _mint(to, amt); }
}

/// @notice PoC: LendingPool's supplier accounting (`userCollateral`, the
///         withdraw()/health-factor source of truth) is never reconciled with
///         LHToken's interest-accruing scaled-balance ledger. Interest genuinely
///         collected from borrowers (via repay()) becomes permanently unclaimable
///         by suppliers -- the promised supply APY is fictitious, and
///         InsuranceFund.coverShortfall's documented bad-debt backstop is dead
///         code (never invoked by LendingPool).
contract StrandedYieldPoC is Test {
    LendingPool pool;
    OracleRouter oracle;
    HealthFactorEngine hfe;
    IsolatedMarketController imc;
    LiquidationManager lm;
    MarketHoursPolicy mhp;
    InsuranceFund fund;
    InterestRateModel irm;

    MockERC20 usdg; // supply asset (lender side)
    MockERC20 weth; // collateral asset (borrower side)

    address lp; // the honest supplier
    address borrower;

    function setUp() public {
        lp = makeAddr("lp");
        borrower = makeAddr("borrower");
        address deployer = address(this);

        irm = new InterestRateModel(deployer, 8e26, 0, 65e23, 6e26, 1e26); // 80% kink, 0 base, 6.5%/60% slopes, 10% RF
        mhp = new MarketHoursPolicy(deployer, deployer);
        fund = new InsuranceFund(deployer);
        oracle = new OracleRouter(deployer, deployer);
        hfe = new HealthFactorEngine(deployer);
        imc = new IsolatedMarketController(deployer);
        lm = new LiquidationManager(deployer);

        pool = new LendingPool(deployer, address(oracle), address(hfe), address(lm), address(imc), address(mhp), address(fund));
        fund.setLendingPool(address(pool));
        hfe.setLendingPool(address(pool));
        lm.setLendingPool(address(pool));
        imc.setLendingPool(address(pool));

        usdg = new MockERC20("USDG", "USDG");
        weth = new MockERC20("WETH", "WETH");

        oracle.configureAsset(address(usdg), OracleRouter.SourceType.FIXED, address(0), 1e8, 1 days);
        oracle.configureAsset(address(weth), OracleRouter.SourceType.FIXED, address(0), 3000e8, 1 days);

        hfe.configureAsset(address(usdg), 9e26, 95e25, 5e25);   // 90% LTV / 95% LT / 5% bonus
        hfe.configureAsset(address(weth), 75e25, 8e26, 8e25);   // 75% LTV / 80% LT / 8% bonus

        pool.addReserve(address(usdg), address(irm), false, "Liquihood USDG", "lhUSDG", "Liquihood Debt USDG", "dUSDG");
        pool.addReserve(address(weth), address(irm), false, "Liquihood WETH", "lhWETH", "Liquihood Debt WETH", "dWETH");

        usdg.mint(lp, 100_000e18);
        weth.mint(borrower, 100e18);

        vm.prank(lp);
        usdg.approve(address(pool), type(uint256).max);
        vm.prank(borrower);
        weth.approve(address(pool), type(uint256).max);
        vm.prank(borrower);
        usdg.approve(address(pool), type(uint256).max); // for repay
    }

    function test_supplierYieldIsStrandedForever() public {
        // 1. LP supplies 100,000 USDG.
        vm.prank(lp);
        pool.supply(address(usdg), 100_000e18);

        // 2. Borrower posts 100 WETH ($300k) and borrows 80,000 USDG (80% utilization -> juicy rate).
        vm.prank(borrower);
        pool.supply(address(weth), 100e18);
        vm.prank(borrower);
        pool.borrow(address(usdg), 80_000e18);

        // 3. A full year passes; interest compounds on the debt.
        vm.warp(block.timestamp + 365 days);

        // 4. Borrower repays in full -- this genuinely pulls extra USDG (principal + interest) INTO the pool.
        (, LHToken lhUSDG, DebtToken dUSDG, , , , , , ) = pool.reserves(address(usdg));

        // Nudge the index (a real state-changing call is required -- balanceOf is a
        // view and won't reflect elapsed-time interest until _accrueInterest runs).
        vm.prank(borrower);
        pool.repay(address(usdg), 1);

        uint256 owed = dUSDG.balanceOf(borrower);
        assertGt(owed, 80_000e18, "sanity: interest must have accrued on the debt");
        usdg.mint(borrower, owed); // generous top-up so borrower can repay principal+interest
        vm.prank(borrower);
        pool.repay(address(usdg), owed);

        uint256 poolBalanceAfterRepay = usdg.balanceOf(address(pool));
        console.log("USDG physically held by pool after full repay :", poolBalanceAfterRepay);
        console.log("LP's lhUSDG true underlying value (index-based):", lhUSDG.balanceOfUnderlying(lp));
        console.log("LP's actual redeemable balance (userCollateral) :", pool.getUserCollateral(lp, address(usdg)));

        // The pool is DEFINITELY holding more than the LP's original principal --
        // that surplus is the interest the borrower just paid.
        assertGt(poolBalanceAfterRepay, 100_000e18, "pool must be holding the collected interest");

        // Yet the LP's WITHDRAWABLE balance (the only thing withdraw() checks) never moved.
        assertEq(pool.getUserCollateral(lp, address(usdg)), 100_000e18, "userCollateral never grew");

        // 5. LP withdraws every last unit withdraw() will let them claim.
        vm.prank(lp);
        pool.withdraw(address(usdg), 100_000e18);
        assertEq(usdg.balanceOf(lp), 100_000e18, "LP only ever recovers principal, 0 yield");

        // 6. Their lhUSDG NatSpec promises "an increasing amount of the underlying" --
        //    but there is no function anywhere the LP (or anyone who buys their
        //    "composable, freely transferable" lhUSDG) can call to redeem it now.
        uint256 strandedScaled = lhUSDG.balanceOf(lp);
        uint256 strandedUnderlying = lhUSDG.balanceOfUnderlying(lp);
        console.log("lhUSDG scaled dust left in LP's wallet   :", strandedScaled);
        console.log("...worth this much underlying, forever stuck:", strandedUnderlying);
        assertGt(strandedUnderlying, 0, "the accrued interest is real value, permanently stranded");

        // Confirm it's truly stuck: LP has 0 userCollateral left, so ANY further withdraw() reverts.
        vm.prank(lp);
        vm.expectRevert(bytes("LP: insufficient collateral"));
        pool.withdraw(address(usdg), 1);

        // And the documented bad-debt backstop is dead code: InsuranceFund never
        // received a cent of the reserve factor this whole time.
        assertEq(fund.balanceOf(address(usdg)), 0, "InsuranceFund.depositReserves is never called by LendingPool");
    }
}
