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

## Deep read (2026-06-25) -> RESOLVED: NO FINDING
- Resolved the EIP-1167 impl: proxy code `363d3d373d3d3d363d73` + `a696a63cc78dffa1a63e9e50587c197387ff6c7e`
  -> impl `0xa696a63cc78dffa1a63e9e50587c197387ff6c7e`. fetch_source -> **a Vyper contract**:
  `# @version 0.2.11`, `@title Yearn Token Vault`, `@author yearn.finance`. yUSD is a **1167 clone of the
  canonical Yearn V2 Vault.vy** -- one of the most-audited contracts in DeFi.
- **Verdict: NO FINDING.** The Thetanuts class (custom share-math, no floor) does NOT apply: Yearn v2
  `_issueSharesForAmount` handles `totalSupply==0`, gov-controlled, seeded. Gate H (publicly-known/audited)
  + gate C (intentional). The recon hits (ecrecover L761, domain-sep L239) = the standard audited EIP-2612
  permit. Sourcing lane did its job (real dormant-funded contract); VERIFY correctly killed it.

## Engine gap this read surfaced (and FIXED) -- the real value
- **recon was Solidity-only and gave a misleading all-clear on the Vyper impl** (false-clean = silent miss,
  the worst outcome). Yearn v2 / Curve / many vaults are Vyper. Added `recon.is_vyper` -> recon now SKIPS +
  loudly WARNS on Vyper files instead of emitting 0s that read as "safe." (+2 asserts, 380 passed.)
- Backlog: real Vyper detector support (or a vyper->normalized pass) so the lane isn't blind to that ecosystem.

## Lane verdict
legacy.py works end-to-end and surfaced a genuine LEGACY-FUNDED on the first migrated-protocol target -- the
gap scout/contest miss. (Indexed was fully drained = 0 hits; Yearn iEarn = 1 dormant-funded candidate.)
