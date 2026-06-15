// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title TiziRebaseModel
/// @notice Faithful, minimal reimplementation of Tizi's cross-chain rebase accounting (the "Ledgity method":
///         verbatim arithmetic, NOT a guess). It mirrors the exact split-brain writers of `netAsset`:
///           - mint(deposit)  -> netAsset += amount               [TiziDollar.sol:119]
///           - burn(withdraw) -> netAsset -= amount               [TiziDollar.sol:133]
///           - updateYield    -> newNetAsset = NAV - nftQueueUSDC*1e12 ; addYield(delta) ; netAsset = newNetAsset
///                                                                  [TiziDollar.sol:172-198]
///         NAV = MainTokenStats.calculateTotalChainValues(): an OFF-CHAIN snapshot (incl. USDC.balanceOf(vault))
///         taken when the admin ran strategiesStats, and STALE until the next stat  [MainTokenStats.sol:259-276,311-348].
///         Liquid withdrawal pays USDC out of the vault (backing drops) with NO compensating term; the NFT path
///         records nftQueueUSDC += amount which updateYield subtracts -> compensated  [DepositHelper.sol:377].
/// @dev    Units: TD / netAsset / NAV = 1e18 ; USDC = 1e6 ; PRECISION_DELTA (PD) = 1e12.
contract TiziRebaseModel {
    uint256 internal constant PD = 1e12; // USDC(6dp) -> TD(18dp)

    // --- TiziDollar ---
    uint256 public tdSupply; // total TD in existence
    uint256 public netAsset; // SPLIT-BRAIN var: live += / -= (mint/burn) AND wholesale-overwritten by updateYield
    uint256 public stTDPool; // TD held by the staking pool == stTD totalAssets proxy

    // --- vault / withdrawal queue ---
    uint256 public vaultUSDC;     // real USDC backing (6dp) held in MainVault
    uint256 public nftQueueUSDC;  // pending NFT-withdrawal USDC (6dp)

    // --- MainTokenStats NAV snapshot ---
    uint256 public navSnapshot;   // calculateTotalChainValues() (1e18); set at strategiesStats, STALE between snapshots

    /// deposit `usdc` (6dp) -> mint usdc*PD TD ; netAsset += that  [DepositHelper.deposit + TiziDollar.mint]
    function deposit(uint256 usdc) external {
        vaultUSDC += usdc;
        uint256 td = usdc * PD;
        tdSupply += td;
        netAsset += td; // TiziDollar.sol:119
    }

    /// admin snapshots the cross-chain NAV (here: just the vault USDC; strategies omitted) [MainTokenStats._addVaultInfo]
    function strategiesStats() external {
        navSnapshot = vaultUSDC * PD;
    }

    /// LIQUID withdrawal of `td` TD: burn, netAsset -=, and pay the USDC OUT of the vault (real backing drops).
    /// There is NO compensating term in updateYield for this path -> the bug.  [DepositHelper liquid branch]
    function withdrawLiquid(uint256 td) external {
        tdSupply -= td;
        netAsset -= td;        // TiziDollar.sol:133
        vaultUSDC -= td / PD;  // USDC leaves the vault; navSnapshot is NOT refreshed -> stale-high
    }

    /// NFT (illiquid) withdrawal of `td` TD: burn, netAsset -=, and record nftQueueUSDC += (the compensator).
    function withdrawNFT(uint256 td) external {
        tdSupply -= td;
        netAsset -= td;            // TiziDollar.sol:133
        nftQueueUSDC += td / PD;   // DepositHelper.sol:377 (updateYield subtracts this -> compensated)
    }

    /// updateYield -- the EXACT arithmetic of TiziDollar.updateYield (the positive-rebase branch). [TiziDollar.sol:172-198]
    function updateYield() external {
        uint256 oldNetAsset = netAsset;
        uint256 newNetAsset = navSnapshot - (nftQueueUSDC * PD); // TiziDollar.sol:174
        if (newNetAsset > oldNetAsset) {
            uint256 delta = newNetAsset - oldNetAsset;
            // addYield(delta,false) -> mintForYield mints fresh TD into the staking pool [StakedTD.addYield/TiziDollar.mintForYield]
            tdSupply += delta;
            stTDPool += delta;
        }
        netAsset = newNetAsset; // TiziDollar.sol:198
    }

    /// solvency check: is the real USDC backing (in TD units) >= TD supply?
    function solvent() external view returns (bool) {
        return vaultUSDC * PD >= tdSupply;
    }
}
