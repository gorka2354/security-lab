# HUNT — Indexed Finance (legacy.py lane demo) — 2026-06-24

**Why:** first live end-to-end run of the new `legacy.py` deprecated-but-funded lane, on an abandoned
index-vault protocol (Indexed Finance / NDX, hacked Oct 2021, since abandoned). White-hat: read-only on-chain
classification, nothing touched.
**Verdict: NO TARGET (all drained).** But the lane ran end-to-end and self-calibrated twice on live data.

## Reach
- Known pools (full addrs via Etherscan): DEFI5 `0xfa6de269...43565ea41`, CC10 `0x17ac188e...b0ccfadf3`,
  NDX `0x86772b14...e238e5f83`. Deployer EOA `0x236eccab...3ce4d46` (via getcontractcreation).

## Run
- `legacy.py check` DEFI5/CC10/NDX -> all ACTIVE-FUNDED (lastTx 1-15d: the ERC20s still trade).
- `legacy.py from-deployer 0x236eccab...` -> enumerated **43** contracts, age-classified each:
  - **42 EMPTY** (drained, totalSupply==0, lastTx 800-2030 days ago) -> the old controllers/pools/staking,
    emptied after the 2021 hack + abandonment -> nothing at stake.
  - **1 ACTIVE-FUNDED** (NDX gov token, 15d).
  - **0 LEGACY-FUNDED.** Unlike Thetanuts (deprecated vault still held $2.1M), Indexed's were drained long ago.
- 0 false positives: no dead contract mis-read as active, no live token mis-read as dormant.

## Live calibrations this run forced into the tool (the real value)
1. **EIP-7702 EOAs**: vitalik.eth (23-byte `0xef0100` delegation) mis-read as a contract -> added `is_7702` skip.
2. **Age, not count**: a tx COUNT can't tell "busy" from "20 lifetime txns since 2021" -> dormancy now gates on
   `last_tx_age_days` (Etherscan txlist desc [0] timeStamp) + `--dormant-days` (default 90).

## Known limitation (backlog)
- `from-deployer` reads the deployer EOA's normal txlist -> contracts created by a FACTORY (internal txns) are
  invisible to it. Factory-spawned pools need a separate enumeration (logs of the factory's Created event).

## Next (to actually find a LEGACY-FUNDED)
- Run `from-deployer` on deployers of protocols that MIGRATED but left funds (v1 still funded), not ones fully
  drained by a past hack. Or feed `check` a hand-built seed list of known-deprecated funded contracts.
