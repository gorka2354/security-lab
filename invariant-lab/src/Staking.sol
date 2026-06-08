// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// Synthetix-style staking rewards with a PLANTED accounting bug (educational).
/// `buggy = true` bumps the reward RATE up by 1 wei/sec, so the contract
/// commits to paying out rate*duration > the amount it was funded with →
/// it slowly becomes insolvent. An invariant fuzzer catches what eyes can't.

contract MockERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 a) external {
        balanceOf[to] += a;
    }

    function approve(address s, uint256 a) external returns (bool) {
        allowance[msg.sender][s] = a;
        return true;
    }

    function transfer(address to, uint256 a) external returns (bool) {
        _move(msg.sender, to, a);
        return true;
    }

    function transferFrom(address f, address to, uint256 a) external returns (bool) {
        uint256 al = allowance[f][msg.sender];
        if (al != type(uint256).max) allowance[f][msg.sender] = al - a;
        _move(f, to, a);
        return true;
    }

    function _move(address f, address to, uint256 a) internal {
        require(balanceOf[f] >= a, "insufficient");
        balanceOf[f] -= a;
        balanceOf[to] += a;
    }
}

contract StakingRewards {
    MockERC20 public immutable stakingToken;
    MockERC20 public immutable rewardToken;
    bool public immutable buggy;

    uint256 public duration = 7 days;
    uint256 public finishAt;
    uint256 public updatedAt;
    uint256 public rewardRate; // reward tokens per second
    uint256 public rewardPerTokenStored; // scaled 1e18
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public userRewardPerTokenPaid;
    mapping(address => uint256) public rewards;

    constructor(MockERC20 s, MockERC20 r, bool _buggy) {
        stakingToken = s;
        rewardToken = r;
        buggy = _buggy;
    }

    function lastTimeApplicable() public view returns (uint256) {
        return finishAt < block.timestamp ? finishAt : block.timestamp;
    }

    function rewardPerToken() public view returns (uint256) {
        if (totalSupply == 0) return rewardPerTokenStored;
        return rewardPerTokenStored + (rewardRate * (lastTimeApplicable() - updatedAt) * 1e18) / totalSupply;
    }

    function earned(address a) public view returns (uint256) {
        uint256 acc = balanceOf[a] * (rewardPerToken() - userRewardPerTokenPaid[a]); // scaled 1e18
        return acc / 1e18 + rewards[a];
    }

    modifier update(address a) {
        rewardPerTokenStored = rewardPerToken();
        updatedAt = lastTimeApplicable();
        if (a != address(0)) {
            rewards[a] = earned(a);
            userRewardPerTokenPaid[a] = rewardPerTokenStored;
        }
        _;
    }

    function stake(address a, uint256 amt) external update(a) {
        stakingToken.transferFrom(a, address(this), amt);
        balanceOf[a] += amt;
        totalSupply += amt;
    }

    function withdraw(address a, uint256 amt) external update(a) {
        balanceOf[a] -= amt;
        totalSupply -= amt;
        stakingToken.transfer(a, amt);
    }

    function getReward(address a) external update(a) {
        uint256 r = rewards[a];
        if (r != 0 && rewardToken.balanceOf(address(this)) >= r) {
            rewards[a] = 0;
            rewardToken.transfer(a, r);
        }
    }

    function notifyReward(uint256 amount) external update(address(0)) {
        rewardToken.transferFrom(msg.sender, address(this), amount);
        if (block.timestamp >= finishAt) rewardRate = amount / duration;
        else rewardRate = (amount + (finishAt - block.timestamp) * rewardRate) / duration;
        // THE BUG: bump the rate up -> commits to distributing rate*duration,
        // which now exceeds `amount`. The contract promises more than it holds.
        if (buggy) rewardRate += 1;
        finishAt = block.timestamp + duration;
        updatedAt = block.timestamp;
    }
}
