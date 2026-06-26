# HUNT — bridge sector recon (playbook shakedown) — 2026-06-26

First pass with the new `research/patterns/bridge/bridge-sector-playbook.md`. White-hat: read-only landscape
+ off-chain secret scan, nothing touched.

## Landscape (DefiLlama /protocols, category Bridge/Cross-Chain)
- **311** bridge-category protocols. Top TVL = audited or custodial/canonical (LayerZero $7.4B audited;
  Coinbase/Binance/Arbitrum/Base/Optimism/Linea bridges -- `audits=0` is a DefiLlama metadata gap, they ARE
  audited; their code = known OP-Stack/Orbit/Nitro forks -> the angle is `forkdrift` on the DRIFT, not the core).
- **Novel / less-picked surface = wrapped-BTC bridges** (custom code, genuinely fresh): Function FBTC $644M,
  SolvBTC $387M (12ch), Lorenzo enzoBTC $368M, Merlin's Seal $359M, Unit, Lighter, Aster.

## Sourcing gap found (backlog)
- `scout.py` has NO bridge zone -> 0 bridges in its ranked queue (all lending/yield/vault/RWA). Add
  bridge/cross-chain/portal/relay/messenger/teleport keywords to the zone scorer (matches playbook §4).

## Target glanced: Lorenzo (enzoBTC $368M + sUSD1+ $162M, audits=0 on DefiLlama)
- Reach: public org `Lorenzo-Protocol` (29 repos) is mostly the Cosmos appchain + off-chain components; the EVM
  contract repos (enzoBTC_contract / stBTC-bridge) are NOT public -> reachability stop for contract recon.
  enzoBTC is also audited (org `audit-report` repo) -> gate H; the on-chain angle would be post-audit drift /
  the integration code, not the core.
- **Playbook §F/§5.6 move (the distinctive bridge check): `secrets.py` over the off-chain `lorenzo-relayer`
  (60 commits) + `lorenzo-btcstaking-submitter` (104 commits), tree + git history -> CLEAN.** No committed
  keys -> good opsec, NOT the Taiko key-leak class. (Bonus: secrets.py is language-agnostic -- worked on the
  Go/Cosmos repos, not just Solidity.)
- **Verdict: no finding; clean recon.** Demonstrated the bridge playbook's off-chain-custody lens end-to-end.

## Next (if pursued)
- A new-L2 canonical bridge fork (CDK/OP-Stack/Orbit) -> `forkdrift` vs canon, hunt the gas-token/decimals/DA
  drift (the ZKFair shape). Or a LayerZero/CCIP integration's `_lzReceive`/`_ccipReceive` authority check.
- Build the backlog detectors the playbook named: `det_decimal_scale`, bridge mint-authority / double-claim.
