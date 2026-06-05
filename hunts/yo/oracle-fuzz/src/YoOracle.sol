// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

// Self-contained copy of YO Protocol's YoOracle for invariant fuzzing.
// The ONLY change vs the real src/YoOracle.sol is replacing the OpenZeppelin
// Ownable/Ownable2Step import with the minimal local shim below — the oracle
// LOGIC is verbatim. (real repo: github.com/yoprotocol/core)

abstract contract Ownable {
    address public owner;
    constructor(address o) { owner = o; }
    modifier onlyOwner() { require(msg.sender == owner, "!owner"); _; }
}
abstract contract Ownable2Step is Ownable {}

interface IYoOracle {
    struct AssetOracleData {
        uint256 latestPrice;
        uint256 anchorPrice;
        uint64 anchorTimestamp;
        uint64 latestTimestamp;
        uint64 windowSeconds;
        uint64 maxChangeBps;
    }
    error NotUpdater();
    error InvalidConfig();
    error PriceChangeTooBig(address vault, uint256 newPrice, uint256 anchorPrice, uint256 diffBps, uint256 maxChangeBps);
    event UpdaterChanged(address indexed oldUpdater, address indexed newUpdater);
    event SharePriceUpdated(address indexed vault, uint256 price, uint64 timestamp);
    event AssetConfigUpdated(address indexed vault, uint32 windowSeconds, uint32 maxChangeBps);
    function getLatestPrice(address _vault) external view returns (uint256 sharePrice, uint64 timestamp);
}

contract YoOracle is Ownable2Step, IYoOracle {
    uint64 public immutable DEFAULT_WINDOW_SECONDS;
    uint64 public immutable DEFAULT_MAX_CHANGE_BPS;
    uint64 public constant BPS_DENOMINATOR = 1_000_000_000;

    address public updater;
    mapping(address vault => AssetOracleData oracleData) public oracleData;

    constructor(address _updater, uint64 _defaultWindowSeconds, uint64 _defaultMaxChangeBps) Ownable(msg.sender) {
        require(_updater != address(0), InvalidConfig());
        updater = _updater;
        DEFAULT_WINDOW_SECONDS = _defaultWindowSeconds;
        DEFAULT_MAX_CHANGE_BPS = _defaultMaxChangeBps;
    }

    function getLatestPrice(address _vault) external view returns (uint256 price, uint64 timestamp) {
        AssetOracleData storage d = oracleData[_vault];
        return (d.latestPrice, d.latestTimestamp);
    }

    function getAnchor(address _vault) external view returns (uint256 price, uint64 timestamp) {
        AssetOracleData storage d = oracleData[_vault];
        return (d.anchorPrice, d.anchorTimestamp);
    }

    function setUpdater(address _updater) external onlyOwner {
        require(_updater != address(0), InvalidConfig());
        emit UpdaterChanged(updater, _updater);
        updater = _updater;
    }

    function setAssetConfig(address _vault, uint32 _windowSeconds, uint32 _maxChangeBps) external onlyOwner {
        AssetOracleData storage d = oracleData[_vault];
        d.windowSeconds = _windowSeconds;
        d.maxChangeBps = _maxChangeBps;
        emit AssetConfigUpdated(_vault, _windowSeconds, _maxChangeBps);
    }

    function updateSharePrice(address _vault, uint256 _sharePrice) external {
        require(msg.sender == updater, NotUpdater());

        AssetOracleData storage d = oracleData[_vault];
        uint64 windowSeconds = d.windowSeconds != 0 ? d.windowSeconds : DEFAULT_WINDOW_SECONDS;
        uint64 maxChangeBps = d.maxChangeBps != 0 ? d.maxChangeBps : DEFAULT_MAX_CHANGE_BPS;

        uint64 nowTs = uint64(block.timestamp);

        // first update
        if (d.latestPrice == 0) {
            d.latestPrice = _sharePrice;
            d.latestTimestamp = nowTs;
            d.anchorPrice = _sharePrice;
            d.anchorTimestamp = nowTs;
            emit SharePriceUpdated(_vault, _sharePrice, nowTs);
            return;
        }

        // this check should never fail
        if (d.anchorPrice > 0) {
            uint256 ref = d.anchorPrice;
            uint256 diff = _sharePrice > ref ? _sharePrice - ref : ref - _sharePrice;
            uint256 diffBps = (diff * BPS_DENOMINATOR) / ref;

            if (diffBps > maxChangeBps) {
                revert PriceChangeTooBig(_vault, _sharePrice, ref, diffBps, maxChangeBps);
            }
        }

        d.latestPrice = _sharePrice;
        d.latestTimestamp = nowTs;

        // rotate anchor if window passed
        if (nowTs - d.anchorTimestamp >= windowSeconds) {
            d.anchorPrice = _sharePrice;
            d.anchorTimestamp = nowTs;
        }

        emit SharePriceUpdated(_vault, _sharePrice, nowTs);
    }
}
