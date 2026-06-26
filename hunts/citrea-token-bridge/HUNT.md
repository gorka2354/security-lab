# HUNT — Citrea token-bridge (LayerZero OFT) — 2026-06-26

First bridge hunt via the new pipeline: `scout` (now surfaces bridges) -> bridge-playbook lens -> secrets +
recon + L4. White-hat: read-only public source. Target: `chainwayxyz/token-bridge` (Citrea's stablecoin bridge,
surfaced as "Citrea Bridge" $4.8M after the scout bridge-zone fix).

## What it is
LayerZero v2 OFT mint-and-burn bridge for USDC/USDT/WBTC between Ethereum (source, locks) and Citrea (dest,
mint/burn). Conforms to **Circle's Bridged USDC Standard** (for future native-USDC takeover). 121 .sol files;
nearly identical to **USDT0** (already on mainnet, audited); repo has an `auditors_guide.md` (under audit).

## Pipeline run
- **secrets.py** (tree + history): CLEAN — no committed keys (good opsec; not the Taiko layer-A class).
- **recon (src/):** [!] hits ALL in vendored `usdt0/Tether/*` (EIP-3009 raw ecrecover w/ its own nonce/auth
  state, pre-0.8 pragma) -> known Tether/USDT0 code, gate H / FP, NOT Citrea's custom logic.
- **L4 read** of the highest-EV custom surface = `for_circle_takeover/SourceOFTAdapterForTakeover.sol`
  (the migration/burn logic; playbook §C mint-authority + §3 conservation):
  - `burnLockedUSDC()` onlyCircle burns `min(destUSDCSupply, balance)`; `setDestUSDCSupply(S)` whenPaused
    onlyDestUSDCSupplySetter; `_debit`/`_credit` whenNotPaused; pause/unpause onlyOwner.
  - Conservation (locked L1 == minted dest) holds; `min()` guards an over-reported supply (the code even
    comments the "extra minter" edge case).

## Verdict: NO FINDING
Everything breakable needs a TRUSTED ROLE (onlyCircle / onlyDestUSDCSupplySetter / onlyOwner) or operational
mis-ordering of the takeover -> **gate E (admin-trust)**, not a permissionless exploit. Code is solid, follows
Circle's standard, mirrors audited USDT0. Minor robustness note (not a finding): `burnLockedUSDC` isn't
`whenPaused`-gated, but `min(destUSDCSupply,balance)` + `onlyCircle` make it safe.

## Pipeline win (the real takeaway)
The end-to-end bridge pipeline worked on a fresh, real target: the scout bridge-zone fix surfaced Citrea ->
reached its repo -> playbook lens routed straight to the custom takeover surface -> secrets/recon/L4 gave a
fast, honest clean. Engine gap noted: recon has no OFT/LayerZero-specific patterns (the custom adapters were
recon-silent; the L4 read carried it) -> possible backlog (OFT _credit/_debit authority + LD/SD decimals).

## Next (if pursued)
- The WBTC `OFTFee`/`OFTFeeAdapter` fee math + LD<->SD shared-decimals conversion (dust/precision, 8-dec WBTC).
- `USDCRolesHolder` (the role-transfer intermediary during Circle takeover) + the destination mint authority.
