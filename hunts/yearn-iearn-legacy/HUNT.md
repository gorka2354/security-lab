# HUNT — Yearn iEarn v1 (legacy.py lane) — 2026-06-24

**Why:** point legacy.py at a protocol that MIGRATED but left funds (v1 still funded), not one drained by a
hack (Indexed was empty). Yearn iEarn v1 stablecoin vaults -- superseded by v2, users who never exited left
residual balances. White-hat: read-only on-chain classification.
**Result: 1 LEGACY-FUNDED candidate (yUSD) -> PARKED for a deep read.** The lane found a real dormant-funded
contract that scout/contest_monitor structurally can't surface.

## Run — `legacy.py check` (--dormant-days 120, with ETHERSCAN_API_KEY)
| Contract | totalSupply | lastTx | verdict |
|---|---|---|---|
| yDAI v1 `0xACd43E62...B31a6F952` | 338,301 | 2d | ACTIVE-FUNDED (still live) |
| yUSDC v1 `0x597aD1e0...c0233522e` | 133,092 | 57d | ACTIVE-FUNDED |
| yUSDT v1 `0x2f08119C...789FAf18` | 117,901 | 17d | ACTIVE-FUNDED |
| yCRV `0x5dbcf33d...91bca25c` | 18,701,400 | 14d | ACTIVE-FUNDED |
| **yUSD `0x4b5bfd52...88d2533d3`** | **373,278** | **259d** | **LEGACY-FUNDED** |

## The candidate — yUSD `0x4b5bfd52124784745c1071dcb244c6688d2533d3`
- Dormant 259d, but 373,278 outstanding supply -> forgotten-but-funded (the Thetanuts shape).
- `code=45B` = an EIP-1167 minimal proxy (NOT a 7702 EOA -- a real contract) -> logic lives in the impl;
  resolve it (bytes 10..29 of the proxy code) before reading.

## NOT a finding -- a sourcing lead. To pursue (next session):
1. Resolve the 1167 impl -> `fetch_source.py` it -> `recon.py` (det_vault_share_math / det_erc4626 /
   det_precision) on the share/redemption math; check the near-empty-supply window.
2. Confirm REAL backing value (supply>0 != assets held) -> `activity.py --token` / read the vault's assets.
3. Confirm SCOPE: Yearn is active w/ a bounty, but deprecated v1 may be out of scope -> verify before any disclosure.

## Lane verdict
legacy.py works end-to-end and surfaced a genuine LEGACY-FUNDED on the first migrated-protocol target -- the
gap scout/contest miss. (Indexed was fully drained = 0 hits; Yearn iEarn = 1 dormant-funded candidate.)
