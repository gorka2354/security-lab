// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// PoC for the oracle-staleness class (Exactly EXA-36 / EXA-15).
/// A lending pool values ETH collateral via a Chainlink-style feed.
/// The vulnerable pool trusts the price blindly; the safe pool checks it.

// ─── Borrowable asset (6 decimals, like USDC) ─────────────────────
contract MockUSDC {
    uint8 public constant decimals = 6;
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 a) external { balanceOf[to] += a; }

    function transfer(address to, uint256 a) external returns (bool) {
        require(balanceOf[msg.sender] >= a, "insufficient");
        balanceOf[msg.sender] -= a;
        balanceOf[to] += a;
        return true;
    }
}

// ─── Chainlink-style price feed we can freeze / break ─────────────
contract MockFeed {
    int256 private _answer;
    uint8 private _decimals;
    uint256 private _updatedAt;
    uint80 private _round;

    constructor(uint8 d, int256 initial) {
        _decimals = d;
        _answer = initial;
        _updatedAt = block.timestamp;
        _round = 1;
    }

    function decimals() external view returns (uint8) { return _decimals; }

    // Refresh the price (bumps updatedAt to "now").
    function update(int256 a) external { _answer = a; _updatedAt = block.timestamp; _round++; }

    function latestRoundData()
        external view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)
    {
        return (_round, _answer, _updatedAt, _updatedAt, _round);
    }
}

interface IFeed {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
    function decimals() external view returns (uint8);
}

// ─── VULNERABLE pool ──────────────────────────────────────────────
contract LendingPool {
    MockUSDC public usdc;
    IFeed public ethFeed;
    uint256 public constant LTV = 50; // borrow up to 50% of collateral value

    mapping(address => uint256) public collateralEth; // wei (1e18)
    mapping(address => uint256) public debtUsdc;       // 1e6

    constructor(MockUSDC _usdc, IFeed _feed) { usdc = _usdc; ethFeed = _feed; }

    function depositCollateral() external payable {
        collateralEth[msg.sender] += msg.value;
    }

    // BUG: no staleness check, no price>0 check, decimals hardcoded to 1e8.
    function _collateralUsdc(address u) internal view returns (uint256) {
        (, int256 price, , , ) = ethFeed.latestRoundData();
        uint256 usd18 = collateralEth[u] * uint256(price) / 1e8; // assumes 8 decimals
        return usd18 / 1e12;                                      // 1e18 -> 1e6
    }

    function borrow(uint256 amountUsdc) external {
        uint256 maxDebt = _collateralUsdc(msg.sender) * LTV / 100;
        require(debtUsdc[msg.sender] + amountUsdc <= maxDebt, "undercollateralized");
        debtUsdc[msg.sender] += amountUsdc;
        usdc.transfer(msg.sender, amountUsdc);
    }
}

// ─── SAFE pool (same logic + the 3 oracle checks) ─────────────────
contract LendingPoolSafe {
    MockUSDC public usdc;
    IFeed public ethFeed;
    uint256 public constant LTV = 50;
    uint256 public constant MAX_STALENESS = 1 hours;

    mapping(address => uint256) public collateralEth;
    mapping(address => uint256) public debtUsdc;

    constructor(MockUSDC _usdc, IFeed _feed) { usdc = _usdc; ethFeed = _feed; }

    function depositCollateral() external payable {
        collateralEth[msg.sender] += msg.value;
    }

    function _collateralUsdc(address u) internal view returns (uint256) {
        (uint80 roundId, int256 price, , uint256 updatedAt, uint80 answeredInRound)
            = ethFeed.latestRoundData();
        require(price > 0, "bad price");                                  // not zero/negative
        require(block.timestamp - updatedAt <= MAX_STALENESS, "stale price"); // fresh enough
        require(answeredInRound >= roundId, "stale round");              // current round
        uint256 usd18 = collateralEth[u] * uint256(price) / (10 ** ethFeed.decimals()); // read decimals
        return usd18 / 1e12;
    }

    function borrow(uint256 amountUsdc) external {
        uint256 maxDebt = _collateralUsdc(msg.sender) * LTV / 100;
        require(debtUsdc[msg.sender] + amountUsdc <= maxDebt, "undercollateralized");
        debtUsdc[msg.sender] += amountUsdc;
        usdc.transfer(msg.sender, amountUsdc);
    }
}
