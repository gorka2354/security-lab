# HUNT: Syntropia (DefiLlama deployed-unaudited) -- forkdrift CLEAN in minutes (3rd Lagoon v0.5.0 fork)

scout v2 (DefiLlama, Yield Aggregator, audits=0, ~$4.2M, Ethereum). Stablecoin yield aggregator, 3 ERC4626
vaults (Syntropia USDC / Boosted / USDC Core). **Reachability via the DefiLlama-Adapters unlock** (see below) ->
core vault addrs `0xd17049ed... / 0x8df3deba... / 0x1b2cb79a...` (Sourcify-verified, 17 .sol). Clone gitignored
`hunts/_volume/syntropia`.

## forkdrift triage -> CLEAN (verbatim Lagoon v0.5.0, permissionless, patch moot)
- `forkdrift fingerprint` -> **Lagoon / Hopper v0.5.0** (4 sigs, `erc7201:hopper.storage`, via version()). The
  SAME base as RockSolid. (Lagoon-vault-as-a-service is being deployed by multiple yield protocols.)
- `forkdrift diff` vs canonical: the only substantive delta is the v0.5.0->v0.5.1 **whitelist-hardening patch**
  Syntropia is missing (`_doubleWhitelistedCheck` on claim paths + `InvalidController`); everything else is
  cosmetic (pragma + `protocol-v1`->`protocol` import rename). Strict Vault.sol diff confirms **NO custom
  yield-aggregator logic** -- the core is byte-equivalent Lagoon v0.5.0.
- **On-chain decider (same as RockSolid):** all 3 vaults' `Whitelistable.isActivated` (ERC-7201 slot ...4801)
  = `0x00` -> **permissionless**. So `isWhitelisted()` returns true for everyone and the missing v0.5.1
  double-checks have ZERO effect -> the patch is **MOOT**. No custom drift + moot patch -> **no finding.**

## Reachability METHOD WIN (wire this into scout)
DefiLlama listed NO address for Syntropia (closed-source, no github). The unlock: **DefiLlama's own TVL
adapter is open-source** and lists the CORE contracts it reads. Fetched
`raw.githubusercontent.com/DefiLlama/DefiLlama-Adapters/main/projects/<module>/index.js` (module from the
/protocols API `module` field) -> the exact vault addresses (not a gov token). This is a far more reliable
reachability source than the protocol's `github`/`address` field -> TODO: add `--source defillama-adapter`
(or fold into resolve_core_repo) so scout emits the adapter's core addrs for closed-source protocols.
(Validated live: Avalon Superearn 0xf297230f.../0x38a95844..., Syntropia 0xd17049ed..., Nerona 0xD48e5655...)

## Status -- CLEAN (no finding). forkdrift triaged a 3rd Lagoon fork in ~6 commands (vs the hours RockSolid
## took manually). Ledger: known (verbatim Lagoon v0.5.0, permissionless, v0.5.1 patch moot).
