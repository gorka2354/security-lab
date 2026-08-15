# EquiVault - permissionless rebalance keeper is over-reimbursed via a hardcoded $5000/gas-token rebate

**Target:** EquiVaults (`github.com/EquiVaults/equivaults-contracts`), pre-launch.
**Component:** `src/RebalanceLib.sol:71-74` (`computeRebate`) + `src/EquiVault.sol:538-571` (`rebalance`).
**Class:** value leak / mispriced incentive (chain-blind constant vs live oracle).
**Verdict:** **CONFIRMED** (reproduces, caller-tunable, paid out of depositor TVL) - **scoped**: only *profitable* when the chain's gas token trades below the ~$2000 break-even (see below). Bounded to `MAX_GAS_REBATE` = 5 settlement units per drift event.
**Severity:** **Low** (permissionless + repeatable + direct depositor loss, but capped at ~$5/event and gated on the gas-token price). Worth fixing pre-launch; the fix is cheap.

---

## Mechanism

`rebalance()` is permissionless once `measureDrift() > driftThresholdBps` and pays the caller a gas rebate straight out of the vault's settlement asset (depositor TVL):

```solidity
// EquiVault.rebalance() (abridged)
uint256 startGas = gasleft();                 // L549
uint256 nav = totalAssets();
uint256[] memory weightsBefore = RebalanceLib.weightsBpsOf(this, nav);
uint256 soldValueSettlement = RebalanceLib.sellOverweight(this, nav, params.minAmountsOut);
uint256 gasRebate = RebalanceLib.computeRebate(startGas - gasleft());   // L560
IERC20 settlement = settlementAsset;
uint256 pool = settlement.balanceOf(address(this));
if (gasRebate > pool) gasRebate = pool;
if (gasRebate > 0) settlement.safeTransfer(_msgSender(), gasRebate);    // L564  <-- out of TVL
```

```solidity
// RebalanceLib.computeRebate
uint256 constant MAX_GAS_REBATE = 5e6;                 // 5 settlement units
uint256 constant ETH_SETTLEMENT_PRICE_CAP = 5_000e6;  // HARDCODED $5000 per gas-token, never updated
function computeRebate(uint256 gasUsed) external view returns (uint256) {
    uint256 rebateSettlement = gasUsed * tx.gasprice * ETH_SETTLEMENT_PRICE_CAP / 1e18;
    return rebateSettlement > MAX_GAS_REBATE ? MAX_GAS_REBATE : rebateSettlement;
}
```

Two defects interact:

1. **Chain-blind constant price.** The keeper's gas (`gasUsed * tx.gasprice`, in gas-token wei) is valued at a hardcoded **$5000 per gas-token**, never at the live `AssetRegistry.getPrice` oracle the vault already runs for its basket. On any chain whose gas token trades below $5000 (i.e. every chain other than ETH-when-ETH>$5000: Polygon POL ~$0.4, Avalanche AVAX ~$30, BNB ~$500, Fantom/Gnosis/Celo/..., and ETH itself whenever it is below the break-even) the keeper is reimbursed **more settlement than the gas is worth**.

2. **`tx.gasprice` is caller-controlled.** The keeper freely picks `tx.gasprice`, so it can always drive `gasUsed * tx.gasprice` up to the `MAX_GAS_REBATE` cap and collect the maximum $5 per event, regardless of prevailing gas.

The rebate is transferred out of the settlement received from the sell leg, so it is drawn straight out of `totalAssets()` - every depositor's claimable value falls by the rebate.

## The honest catch (why this is Low, not High)

The reimbursed `gasUsed` is measured **only around the sell leg** (`startGas` at L549, `computeRebate` at L560). It **excludes** the pre-`startGas` work (`paused()` and `measureDrift()` - both loop the basket calling `getPrice`) and the **entire** `buyUnderweight()` leg after L560, plus the 21k intrinsic. Measured on a 2-asset basket:

| quantity | gas |
|---|---|
| reimbursed `gasUsed` (sell leg only) | 153,748 |
| keeper's real total tx gas | 383,112 |
| ratio | **2.49x** |

So the vault reimburses only ~40% of the keeper's real gas. That partly cancels the $5000 over-valuation. Net break-even gas-token price:

```
P_breakeven = $5000 * reimbursedGas / totalGas = 5000 * 153748 / 383112 = ~$2006
```

The keeper **profits only when the real gas-token price is below ~$2006**, and loses money above it.

## Profit tables (PoC output, 6-dec settlement units per call)

Near-cap sub-cap attack: `tx.gasprice` = 6.37 gwei, rebate = **4.90** units, keeper real gas = 0.002442 gas-token. `TVL drop == rebate` (verified). Break-even ~$2006.

| gas-token price (USD) | keeper real cost | keeper profit |
|---|---|---|
| $1   (cheap L1/L2)     | 0.0024 | **+4.898** |
| $30  (AVAX-like)       | 0.073  | **+4.827** |
| $500 (BNB-like)        | 1.221  | **+3.679** |
| $1500                  | 3.663  | **+1.237** |
| $3000 (ETH mainnet)    | 7.326  | -2.426 (loss) |
| $4500                  | 10.99  | -6.089 (loss) |

At the hard cap (`tx.gasprice` = 7.15 gwei, rebate = **5.00** = `MAX_GAS_REBATE`):

| gas-token price (USD) | keeper profit |
|---|---|
| $1    | +5.00 |
| $30   | +4.92 |
| $500  | +3.63 |
| $1500 | +0.89 |
| $3000 | -3.22 (loss) |
| $4500 | -7.33 (loss) |

The cap is reachable at a fully realistic **~7 gwei**, not an absurd gas price.

## Scope / when it bites

- **Active bug**: any deployment on a chain whose gas token is priced below ~$2000 - Polygon, BNB Chain, Avalanche, Fantom, Cronos, Gnosis, Celo, etc. There a permissionless keeper extracts up to `MAX_GAS_REBATE` (5 units) of depositor value per drift event, tunable to always hit the cap.
- **Latent bug** on Ethereum mainnet + ETH-gas L2s while ETH > ~$2000: the sell-leg-only gas measurement coincidentally neutralizes the over-valuation. It becomes active if ETH falls below ~$2000 (as it was for most of pre-2021 and 2022-2023). (Note: on ETH L2s the dominant L1 data fee is not captured by `tx.gasprice` at all, which only makes the keeper's real cost higher, i.e. less favorable to the attacker.)
- No cooldown, rate-limit, or keeper allowlist: the leak recurs on every natural drift event; cumulative loss is unbounded over time even though each event is capped at 5 units.

## PoC

`equivaults-poc/` (local Foundry, no fork/network). Compiles the **actual** target contracts (`EquiVault`, `RebalanceLib`, `AssetRegistry`) via a symlink remap into `lib/` (`lib/equivaults-src` -> the clone's `src`, plus its pinned `forge-std` / `openzeppelin-contracts` submodules). Mocks (`MockToken`, `MockOracle`, `MockOracleRoute` with **zero** DEX fee so the only value leaving the basket is the rebate) mirror the target's own test mocks.

`test/OverRebate.t.sol`:
- `test_1_mispricing_and_breakeven` - proves the rebate books the measured sell-leg gas at exactly $5000/token (`rebate*3000 == reimbursedCost@$3000 * 5000`), measures reimbursed-vs-total gas (2.49x), derives break-even ~$2006.
- `test_2_profit_table_and_tvl_drain` - near-cap attack; asserts `keeperGain == rebate`, `totalAssets` and Alice's claimable value each drop by ~rebate, and profit is positive below / negative above break-even.
- `test_3_cap_reachable_and_max_profit` - the hard `MAX_GAS_REBATE` cap is reached at ~7 gwei; honest max-profit table.

Run:
```
source toolkit/env.sh          # forge on PATH; forge auto-installs solc 0.8.30
cd equivaults-poc && forge test -vv
```
Result: `3 passed`.

## Fix recommendation

Value the measured gas at a **live oracle** for the gas token instead of the hardcoded `ETH_SETTLEMENT_PRICE_CAP`, e.g. register the wrapped gas token in the `AssetRegistry` and price it via `getPrice(gasToken, settlement)` with the same freshness gates as basket assets; keep `MAX_GAS_REBATE` as the absolute settlement backstop. If an on-chain gas-token feed is not available on a target chain, denominate the rebate purely in settlement from a governance-set, oracle-bounded per-chain parameter rather than a single hardcoded $5000 - and cap `tx.gasprice`'s contribution (e.g. clamp to `block.basefee`-derived value) so a caller cannot self-select the price used for reimbursement.
