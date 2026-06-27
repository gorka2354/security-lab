#!/usr/bin/env python3
"""Golden-fixture regression tests for the toolkit detectors + ledger.

Pins the behaviour of each recon detector (and the 12 precision fixes) so a future
tweak can't silently regress another detector. No pytest needed - pure asserts:

    python tests/test_detectors.py     # exits 1 if any fail (CI-friendly)

Each fixture is a tiny Solidity snippet with a KNOWN expected outcome.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "toolkit"))
import recon  # noqa: E402
import ledger  # noqa: E402

_p, _f = 0, 0


def check(cond, msg):
    global _p, _f
    if cond:
        _p += 1
    else:
        _f += 1
        print("  FAIL:", msg)


def flagged(detector, code, name_substr=None):
    leads = detector(code, "src/Fix.sol")
    if name_substr is None:
        return bool(leads)
    return any(name_substr in (l[2] or "") for l in leads)


print("== det_access (access control + inline-auth fixes) ==")
check(flagged(recon.det_access, "contract C{function setFee(uint x) external { fee=x; }}", "setFee"),
      "ungated privileged setFee is flagged")
check(not flagged(recon.det_access, "contract C{function setFee(uint x) external onlyOwner { fee=x; }}"),
      "onlyOwner setFee NOT flagged")
check(not flagged(recon.det_access, "contract C{function setFee(uint x) external { requireGovernanceOnly(); fee=x; }}"),
      "fix#12: requireGovernanceOnly() inline-auth NOT flagged")
check(not flagged(recon.det_access, "contract C{function setSwapFee(uint f) external { _checkController(); _swapFee=f; }}", "setSwapFee"),
      "fix#34: _checkController() inline auth NOT flagged (Balancer/PowerPool BPool, found on the PIPT read)")
check(flagged(recon.det_access, "contract C{function setSwapFee(uint f) external { _checkAmount(f); _swapFee=f; }}", "setSwapFee"),
      "fix#34 scope: _checkAmount() is an input validator, NOT auth -> setSwapFee still flagged (no over-suppression)")
check(not flagged(recon.det_access,
      "contract C{function updateRewards(P p) external { uint a; uint b; uint c; _verifySignatures(m,h,p.s); root=p.r; }}"),
      "fix#11: deep _verifySignatures gate NOT flagged")
check(not flagged(recon.det_access, "contract C{function setX(uint x) external { require(msg.sender==owner); x_=x; }}"),
      "msg.sender comparison guard NOT flagged")
check(flagged(recon.det_access, "contract C{function setFee(uint x) external { emit Set(msg.sender,x); fee=x; }}", "setFee"),
      "fix: trailing emit(msg.sender) does NOT mask a real ungated setter")
check(not flagged(recon.det_access,
      "contract C{function claimRewards(uint[] ids) external { for(uint i;i<ids.length;i++){ accrue(ids[i]); uint a; uint b; uint c; pay(userStakes[msg.sender][ids[i]].liq); } }}", "claimRewards"),
      "fix#26: self-scope userStakes[msg.sender] DEEP in the body (past 280 chars) NOT flagged (MagicSwap claimRewards)")
check(not flagged(recon.det_access, "contract C is Auth{function setSnapshotHook(address h) external auth { hook=h; }}"),
      "fix#27: ward-model `external auth` modifier NOT flagged (MakerDAO/Centrifuge)")
check(not flagged(recon.det_access, "contract C{function notifyPool(uint id) external payable { _isManager(id); send(id); }}"),
      "fix#27: inline `_isManager(id)` predicate gate NOT flagged (Centrifuge Hub)")
check(flagged(recon.det_access, "contract C{function setFee(uint x) external { fee=x; }}", "setFee"),
      "fix#27 guard: a genuinely ungated setter (no auth/only) is STILL flagged (no over-suppression)")
check(not flagged(recon.det_access, "contract C{function setConfig(uint x) external restricted { cfg=x; }}"),
      "fix#32: OZ AccessManager `external restricted` modifier NOT flagged (Royco V2 / OZ v5 AccessManaged)")
check(not flagged(recon.det_access, "contract C{function seizeShares(address f,address t,uint s) external restricted { _move(f,t,s); }}", "seizeShares"),
      "fix#32: `restricted`-gated privileged fn (Royco RoycoVaultTranche.seizeShares) NOT flagged")
check(flagged(recon.det_access, "contract C{function setRestrictedFlag(bool v) external { isRestricted=v; }}", "setRestrictedFlag"),
      "fix#32 guard: a setter that merely NAMES 'restricted' (no `restricted` modifier) is STILL flagged (word-boundary, no over-suppression)")
check(not flagged(recon.det_access, "contract C{function decreaseTroveColl(address b,uint c) external { _requireCallerIsBorrowerOperations(); coll[b]=c; }}"),
      "fix#33: Liquity/Threshold inline `_requireCallerIsBorrowerOperations()` caller-auth NOT flagged (Mezo MUSD fork; killed ~13 TroveManager FPs)")
check(bool(recon.INLINE_AUTH.search("_requireCallerIsStabilityPool();")) and bool(recon.INLINE_AUTH.search("_requireCallerIsBOorTroveMorSP();")),
      "fix#33: INLINE_AUTH matches the _requireCallerIs<X>() helper family")
check(flagged(recon.det_access, "contract C{function setFee(uint x) external { fee=x; }}", "setFee"),
      "fix#33 guard: a genuinely ungated setter (no _requireCaller*/only) is STILL flagged (no over-suppression)")
check(not flagged(recon.det_access, "contract C{function updateAllowedChain(uint x) external { _onlyAdminOrRole(R); allowed[x]=true; }}"),
      "fix#14: inline _onlyAdminOrRole() auth-helper call NOT flagged")
check(not flagged(recon.det_access, "contract C{function slash(address a) external checkAccess(this.slash.selector) { x=a; }}"),
      "fix#15: checkAccess(this.fn.selector) selector-gating NOT flagged (Cap pattern)")
check(not flagged(recon.det_access, "contract C{function withdrawAll(address t) external { LibDiamond.enforceIsContractOwner(); pay(t); }}"),
      "fix#18: Diamond library auth LibDiamond.enforceIsContractOwner() NOT flagged (Crypto Unicorns facet)")
check(not flagged(recon.det_access, "contract C{function mintUNIM(address t,uint a) external { LibUNIMController.enforceIsController(); _mint(t,a); }}", "mintUNIM"),
      "fix#18: enforceIsController() Diamond auth NOT flagged")
_deleg = recon.det_access("contract C{function setConfig(uint t) external { LibCfg.setConfig(t); }}", "src/Facet.sol")
check(bool(_deleg) and _deleg[0][4] == 1 and "delegator" in _deleg[0][3],
      "fix#19: thin facet delegator (LibCfg.setConfig) downgraded [!]->[.] prio 1 + noted (Crypto Unicorns/Chikn leaf-gating FP)")
check(recon.det_access("contract C{function setFee(uint x) external { fee=x; }}", "src/C.sol")[0][4] == 0,
      "fix#19: genuinely ungated non-delegating setter stays [!] prio 0")

print("== det_sibling (regression technique + initializer) ==")
sib = ("contract C{function setA(uint x) external onlyOwner { a=x; }"
       " function setB(uint x) external { b=x; }}")
check(flagged(recon.det_sibling, sib, "setB"), "ungated setB flagged next to gated setA")
check(not flagged(recon.det_sibling, "contract C{function setA(uint x) external onlyOwner { a=x; }}"),
      "single gated fn: no sibling lead")
_capsib = ("contract C{function setA(uint x) external checkAccess(this.setA.selector) { a=x; }"
           " function distributeRewards(address t) external { b=t; }}")
check(flagged(recon.det_sibling, _capsib, "distributeRewards"),
      "fix#15: lone ungated sibling flagged among checkAccess-gated siblings (the real Cap signal)")

print("== det_mint (supply integrity, _msgSender fix) ==")
check(flagged(recon.det_mint, "contract C{function mint(address t,uint a) external { _mint(t,a); }}", "mint"),
      "public mint flagged")
check(recon.det_mint("contract C{function mint(uint a) external onlyMinter { _mint(msg.sender,a); }}", "src/Fix.sol")[0][4] != 0
      if recon.det_mint("contract C{function mint(uint a) external onlyMinter { _mint(msg.sender,a); }}", "src/Fix.sol") else True,
      "gated mint is lower priority (not prio-0)")
check(not (recon.det_mint("contract C{function mint(uint a) external { require(_msgSender()==backingManager); _mint(a); }}", "src/Fix.sol")
          and recon.det_mint("contract C{function mint(uint a) external { require(_msgSender()==backingManager); _mint(a); }}", "src/Fix.sol")[0][4] == 0),
      "fix#12: _msgSender() gate on mint -> not prio-0")
_capmint = recon.det_mint("contract C{function mint(address t,uint a) external checkAccess(this.mint.selector) { _mint(t,a); }}", "src/Fix.sol")
check(bool(_capmint) and "GATED" in _capmint[0][3],
      "fix#16: checkAccess(this.mint.selector) mint recognized as GATED, not 'PUBLIC mint' (Cap CCAToken)")
_selfburn = recon.det_mint("contract C{function burn(uint a) external { _burn(_msgSender(), a); }}", "src/Fix.sol")
check(bool(_selfburn) and _selfburn[0][4] != 0 and "self-burn" in _selfburn[0][3],
      "fix#35: public self-burn `_burn(_msgSender(), a)` -> 'self-burn safe', NOT prio-0 (the #1 ERC20Burnable FP; Pepu token)")
check(recon.det_mint("contract C{function mint(address t,uint a) external { _mint(t,a); }}", "src/Fix.sol")[0][4] == 0,
      "fix#35 scope: a real ungated mint(to,amt) is STILL prio-0 (self-burn fix doesn't over-suppress mint)")
_mw = recon.det_mint("contract C{function mintRogues(uint n) external { for(uint i;i<n;i++){ mintRogue(); } }"
                     " function mintRogue() public { require(openForMint||auth[msg.sender]); _mint(msg.sender,1); }}", "src/Fix.sol")
_mr = [l for l in _mw if "mintRogues" in l[2]][0]
check(_mr[4] == 1 and "WRAPPER" in _mr[3],
      "fix#25: mint wrapper delegating to a gated sibling -> [.] not [!] (EtherOrcs mintRogues)")
check(recon.det_mint("contract C{function mint(address t,uint a) external { _mint(t,a); }}", "src/Fix.sol")[0][4] == 0,
      "fix#25: a real ungated mint calling the _mint primitive stays [!] (not a wrapper)")
_mas = recon.det_mint("contract C{function mintAllocatedShares(address a,uint v) external { allocated -= v; mint(a, v); }"
                      " function mint(address a,uint v) public onlyVaultOrQueue { _mintShares(a,v); }}", "src/SM.sol")
_masw = [l for l in _mas if "mintAllocatedShares" in l[2]][0]
check(_masw[4] == 1 and "WRAPPER" in _masw[3],
      "fix#31: mint wrapper calling a bare gated sibling mint() -> [.] (Mellow ShareManager.mintAllocatedShares)")
_wm = recon.det_mint("contract C{function mint(address to,uint v) public override { super.mint(to,v); _onTransfer(to,v); }}", "src/ShareToken.sol")
check(bool(_wm) and "GATED" in _wm[0][3],
      "fix#27: mint override delegating to super.mint (parent gate) recognized as GATED (Centrifuge ShareToken)")
_am = recon.det_mint("contract C is Auth{function mint(address t,uint a) external auth { _mint(t,a); }}", "src/Fix.sol")
check(bool(_am) and "GATED" in _am[0][3], "fix#27: ward `external auth` mint recognized as GATED, not PUBLIC")
_vc = recon.det_mint("contract C{function mint(uint shares,address controller) external { _validateController(controller); m.mint(shares); }}", "src/V.sol")
check(bool(_vc) and "GATED" in _vc[0][3], "fix#30: _validateController gate -> mint GATED (MagicSwap AsyncVault)")
check(bool(recon.INLINE_AUTH.search("_authorize(from, receiver, asset)")), "fix#30: INLINE_AUTH matches _authorize() EIP-712 gate (DRE mintFrom)")
check(not recon.INLINE_AUTH.search("_validateAmount(x);") and not recon.INLINE_AUTH.search("_validateDeadline(d);"),
      "fix#30 guard: input validators (_validateAmount/_validateDeadline) NOT treated as auth")

print("== det_unchecked (silent transfer, super. fix) ==")
check(flagged(recon.det_unchecked, "x.transferFrom(a, b, c);"), "bare transferFrom flagged")
check(not flagged(recon.det_unchecked, "x.safeTransfer(to, amt);"), "safeTransfer NOT flagged")
check(not flagged(recon.det_unchecked, "super.transfer(to, amt);"), "fix#9: super.transfer NOT flagged")
check(not flagged(recon.det_unchecked, "payable(to).transfer(amt);"), "ETH payable.transfer NOT flagged")
check(not flagged(recon.det_unchecked, "bool ok = token.transfer(to, amt);"), "captured-return transfer NOT flagged")
check(not flagged(recon.det_unchecked, "try IERC20(innerToken).transfer(to, amount) returns (bool success) { return success; }"),
      "fix#29: try X.transfer(...) returns(bool) captures the return NOT flagged (dreUSD dreShareOFTAdapter)")

print("== det_signature / det_upgrade / det_oracle ==")
check(flagged(recon.det_signature, "contract C{ function f() external { a = ecrecover(h,v,r,s); } }"),
      "raw ecrecover (no guards) flagged")
# class-F extension: ERC-1271 caller-supplied verifier = a decoded calldata STRUCT FIELD (MureDistribution class)
check(flagged(recon.det_signature, "contract C{function claim(Order calldata o,bytes sig) external { require(IERC1271(o.signer).isValidSignature(hash,sig)==0x1626ba7e); }}", "isValidSignature"),
      "det_signature: ERC-1271 isValidSignature on a struct-field verifier (o.signer) -> flagged")
check(flagged(recon.det_signature, "contract C{function claim(Req calldata r,bytes sig) external { require(SignatureChecker.isValidSignatureNow(r.signer,hash,sig)); }}", "isValidSignature"),
      "det_signature: isValidSignatureNow with a struct-field signer -> flagged")
check(not flagged(recon.det_signature, "contract C{function claim(Order calldata o,bytes sig) external { require(o.signer==trustedSigner); require(IERC1271(o.signer).isValidSignature(hash,sig)==0x1626ba7e); }}", "isValidSignature"),
      "det_signature guard: struct-field verifier compared (== trustedSigner) -> bound -> NOT flagged")
check(not flagged(recon.det_signature, "contract C{function permit(address owner,bytes sig) external { require(SignatureChecker.isValidSignatureNow(owner,hash,sig)); }}", "isValidSignature"),
      "det_signature scope: bare-param verifier (EIP-2612 permit shape) is reasoning-tier -> NOT flagged (avoids the permit FP)")
# class-F extension: a nonce that is declared/read but never consumed -> still replayable
_sign = recon.det_signature("contract C{mapping(address=>uint) nonces; function f(address u) external { uint n=nonces[u]; address s=ecrecover(h,v,r,s); require(s!=address(0)); } }", "src/C.sol")
check(any("never consumed" in (t[3] or "").lower() for t in _sign),
      "det_signature: nonce declared but never consumed -> 'still replayable' note")
_sigc = recon.det_signature("contract C{mapping(address=>uint) nonces; function f(address u) external { address s=ecrecover(h,v,r,s); require(s!=address(0)); nonces[u]++; } }", "src/C.sol")
check(not any("never consumed" in (t[3] or "").lower() for t in _sigc),
      "det_signature: a CONSUMED nonce (nonces[u]++) does not raise the never-consumed note")
_sigi = recon.det_signature("contract C{mapping(address=>Counters.Counter) _nonces; function permit(address o) external { uint n=_nonces[o].current(); address s=ecrecover(h,v,r,s); require(s==o); _nonces[o].increment(); } }", "src/C.sol")
check(not any("never consumed" in (t[3] or "").lower() for t in _sigi),
      "det_signature: OZ Counters _nonces[o].increment() counts as consumed (Apiary/OZ-permit FP fix)")
check(flagged(recon.det_upgrade, "contract C{function _authorizeUpgrade(address) internal override {}}"),
      "empty _authorizeUpgrade flagged")
check(not flagged(recon.det_upgrade, "contract C{function _authorizeUpgrade(address) internal override onlyOwner {}}"),
      "onlyOwner _authorizeUpgrade NOT flagged")
check(not flagged(recon.det_upgrade, "contract C{function _authorizeUpgrade(address) internal view override checkAccess(bytes4(0)) {}}"),
      "fix#17: checkAccess(bytes4(0)) _authorizeUpgrade NOT flagged (Cap selector-gating)")
check(flagged(recon.det_oracle, "contract C{ function p() external { (,int a,,,)=feed.latestRoundData(); } }"),
      "latestRoundData with missing guards flagged")

print("== det_pyth_oracle (Pyth/pull-oracle missing guards; Vena 2026 class) ==")
check(flagged(recon.det_pyth_oracle, "contract C{function v(bytes32 id) public { Price p=pyth.getPriceUnsafe(id); x=uint(int(p.price)); }}", "getPriceUnsafe"),
      "naive getPriceUnsafe with no price>0/.conf/staleness -> flagged")
check(recon.det_pyth_oracle("contract C{function v(bytes32 id) public { Price p=pyth.getPriceUnsafe(id); x=uint(int(p.price)); }}", "src/C.sol")[0][4] == 0,
      "naive getPriceUnsafe is high-priority [!] (price>0 + staleness missing)")
check(not flagged(recon.det_pyth_oracle, "contract C{function v(bytes32 id) public { Price p=pyth.getPriceNoOlderThan(id,60); require(p.price>0,'InvalidPrice'); require(p.conf<maxConf,'wide'); }}"),
      "guarded Pyth (getPriceNoOlderThan + price>0 + .conf) NOT flagged (no FP)")
check(not flagged(recon.det_pyth_oracle, "contract C{ function p() external { (,int a,,uint u,)=feed.latestRoundData(); require(a>0); } }"),
      "Chainlink latestRoundData NOT flagged by det_pyth (that's det_oracle's job; no overlap-noise)")

print("== det_multicall_value (payable-multicall / msg.value reuse) ==")
_MCV_POS = ("contract C{ function multicall(bytes[] calldata d) external payable { "
            "for(uint i;i<d.length;i++){ address(this).delegatecall(d[i]); } } "
            "function deposit() external payable { bal[msg.sender]+=msg.value; } }")
check(flagged(recon.det_multicall_value, _MCV_POS, "function multicall"),
      "payable delegatecall-multicall + payable deposit reading msg.value -> value-reuse flagged")
check(recon.det_multicall_value(_MCV_POS, "src/C.sol")[0][4] == 0, "value-reuse is high-priority [!]")
check(not flagged(recon.det_multicall_value, "contract C{ function multicall(bytes[] calldata d) external { for(uint i;i<d.length;i++){ address(this).delegatecall(d[i]); } } function setX(uint x) external { x_=x; } }"),
      "multicall with NO payable msg.value consumer NOT flagged (no FP)")
check(not flagged(recon.det_multicall_value, "contract C{ function deposit() external payable { bal[msg.sender]+=msg.value; } }"),
      "plain payable deposit (no multicall) NOT flagged")
check(flagged(recon.det_multicall_value, "contract C{ function airdrop(address[] calldata to) external payable { for(uint i;i<to.length;i++){ payable(to[i]).transfer(msg.value); } } }", "for("),
      "msg.value read inside a loop -> per-iteration credit flagged")

print("== det_trust_anchor (Taiko/Raiko SGX key-leak class) ==")
_TA_POS = "contract V{bytes32 mrSigner; mapping(address=>bool) ti; function registerInstance(bytes32 m,address i) external { require(m==mrSigner); ti[i]=true; }}"
check(flagged(recon.det_trust_anchor, _TA_POS, "registerInstance"),
      "single-anchor registerInstance (mrSigner, no quorum/revoke) -> flagged")
check(recon.det_trust_anchor(_TA_POS, "src/V.sol")[0][4] == 0,
      "det_trust_anchor: no quorum + no revocation -> [!] high priority (0)")
check(not flagged(recon.det_trust_anchor, "uint threshold; " + _TA_POS),
      "det_trust_anchor: a quorum/threshold marker bounds the leak -> NOT flagged (gate the FP)")
_TA_REV = "contract V{bytes32 mrSigner; mapping(address=>bool) ti; function registerInstance(bytes32 m,address i) external { require(m==mrSigner); ti[i]=true; } function revokeInstance(address i) external { ti[i]=false; }}"
_ta_rev = recon.det_trust_anchor(_TA_REV, "src/V.sol")
check(_ta_rev and _ta_rev[0][4] == 0 and "reactive revocation" in (_ta_rev[0][3] or ""),
      "det_trust_anchor: revocation present -> STILL [!] (0), note flags it reactive (Taiko had deleteInstances, drained anyway)")
check(not flagged(recon.det_trust_anchor, "contract C{function setFee(uint x) external onlyOwner { fee=x; }}"),
      "det_trust_anchor: an ordinary contract with no trust-anchor vocabulary -> NOT flagged")
check(not flagged(recon.det_trust_anchor,
      "contract FflonkVerifier{ address prover; function verifyProof(bytes calldata proof, uint[1] calldata pubSignals) public view returns (bool){ /* fflonk pairing snark */ return true; }}"),
      "det_trust_anchor: a pure zk-SNARK verifier (fflonk/pairing/pubSignals, no TEE/signature) -> NOT flagged (verifying key is PUBLIC; ZKFair FflonkVerifier FP)")
check(flagged(recon.det_trust_anchor,
      "contract SgxVerifier{ function verifyProof(address prover, bytes calldata sig) external { require(trustedInstance[prover]); /* sgx attestation pairing */ }}", "verifyProof"),
      "det_trust_anchor: a TEE verifier that also mentions pairing is STILL flagged (TEE/signature trust present -> leakable key)")

print("== det_vault_share_math (Thetanuts: custom-vault share-price rounding) ==")
_VS = "contract V{uint totalSupply; uint backing; function redeem(uint amount) external { uint payout = backing * amount / totalSupply; totalSupply-=amount; }}"
check(flagged(recon.det_vault_share_math, _VS),
      "det_vault_share_math: custom vault `backing*amount/totalSupply` with no floor -> flagged")
check(not flagged(recon.det_vault_share_math,
      "contract V{uint constant MINIMUM_SHARES=1e3; uint totalSupply; uint backing; function redeem(uint amount) external { uint p = backing * amount / totalSupply; }}"),
      "det_vault_share_math: a MINIMUM_SHARES permanent floor -> NOT flagged")
check(not flagged(recon.det_vault_share_math,
      "contract V is ERC4626{ uint totalSupply; uint backing; function redeem(uint a) external { uint p = backing * a / totalSupply; }}"),
      "det_vault_share_math: an ERC4626 vault is ceded to det_erc4626 -> NOT flagged here")
check(not flagged(recon.det_vault_share_math,
      "contract C{function f(uint a,uint b,uint c) external pure returns(uint){ return a * b / c; }}"),
      "det_vault_share_math: plain a*b/c (no totalSupply division, no vault fn) -> NOT flagged")

print("== secrets lane (Taiko layer-A: committed keys, incl. git history) ==")
import secrets as _secrets  # noqa: E402
check(bool(_secrets.scan_text("-----BEGIN RSA PRIVATE KEY-----\nMIIx\n-----END RSA PRIVATE KEY-----", "k.pem")),
      "secrets: PEM private-key block flagged")
check(any(l[2].startswith("AWS") for l in _secrets.scan_text("aws=AKIAIOSFODNN7EXAMPLE", "c")),
      "secrets: AWS access key id flagged")
check(bool(_secrets.scan_text('apiKey = "sk_live_9f8e7d6c5b4a3210"', "c")),
      "secrets: a real secret literal flagged")
check(not _secrets.scan_text("apiKey = process.env.API_KEY", "c")
      and not _secrets.scan_text('password = "your-password-here"', "c"),
      "secrets: env-indirection + placeholder are NOT flagged (FP gate)")
check(not _secrets.scan_text("bytes32 h = 0x" + "a" * 64 + ";", "c"),
      "secrets: a bare bytes32 hash (no key-context) is NOT flagged (the bytes32 FP gate)")
check(any("PRIVATE KEY" not in l[3] and l[4] == 0 for l in _secrets.scan_filename("config/enclave-key.pem")),
      "secrets: a .pem filename is a [!] lead by path alone")
check(not _secrets.scan_filename(".env.example") and not _secrets.scan_filename("src/Vault.sol"),
      "secrets: .env.example + ordinary source files are NOT flagged")
check(_secrets.redact("AKIAIOSFODNN7EXAMPLE").startswith("AKIA") and "20 chars" in _secrets.redact("AKIAIOSFODNN7EXAMPLE"),
      "secrets: redact() masks the middle (proves the hit without re-leaking it)")

print("== legacy lane (Thetanuts: deprecated-but-funded sourcing) ==")
import legacy as _legacy  # noqa: E402
# dormancy is the AGE of the last tx, NOT a tx count (the live-run lesson: 20 lifetime txns from 2021 != active)
check(_legacy.classify_legacy(5000, -1, 10**18, None, 5000, 400)[0] == "LEGACY-FUNDED",
      "legacy: value + last tx 400d ago -> LEGACY-FUNDED (age drives it, even with events unknown)")
check(_legacy.classify_legacy(5000, -1, 0, 5_000_000, None, 400)[0] == "LEGACY-FUNDED",
      "legacy: HELD ERC20 (token_bal>0) + 0 ETH + dormant -> LEGACY-FUNDED (the Pepu-dig fix: bridges lock tokens, not ETH)")
check(_legacy.classify_legacy(5000, -1, 10**18, None, 5000, 10)[0] == "ACTIVE-FUNDED",
      "legacy: value + last tx 10d ago -> ACTIVE-FUNDED (recent => live, not the legacy class)")
check(_legacy.classify_legacy(5000, 0, 0, 0, 0, 400)[0] == "EMPTY",
      "legacy: 0 value -> EMPTY regardless of age (nothing at stake)")
check(_legacy.classify_legacy(5000, -1, 10**18, None, 5000, None)[0] == "UNKNOWN",
      "legacy: no age (no key) AND event query failed -> UNKNOWN, never a false dormancy verdict")
check(_legacy.classify_legacy(0, 0, 0, None, None, 400)[0] == "NO-CODE"
      and _legacy.classify_legacy(-1, 0, 0, None, None, 400)[0] == "UNKNOWN",
      "legacy: code==0 -> NO-CODE; code<0 (rpc null) -> UNKNOWN")
check(_legacy.is_7702("0xef0100" + "ab" * 20) and not _legacy.is_7702("0x60806040"),
      "legacy: is_7702 detects the 23-byte 0xef0100 delegation (a wallet, not a contract); real bytecode is not 7702")
_facrows = [{"type": "create", "from": "0xFAC", "contractAddress": "0xAAA"},
            {"type": "create2", "from": "0xfac", "contractAddress": "0xBBB"},
            {"type": "call", "from": "0xFAC", "contractAddress": ""},
            {"type": "create", "from": "0xOTHER", "contractAddress": "0xCCC"},
            {"type": "create", "from": "0xFAC", "contractAddress": "0xAAA"}]
check(_legacy._creations_from_internal(_facrows, "0xfac") == ["0xAAA", "0xBBB"],
      "legacy: from-factory parser -> only create/create2 BY the factory, de-duped (the clones txlist can't see)")
check(_legacy._load_addrs(None, "0xAAA, 0xbbb ,0xAAA # dup") == ["0xAAA", "0xbbb"],
      "legacy: sweep _load_addrs parses a comma list, strips '#' comments, de-dups case-insensitively")
_sw = [{"verdict": "EMPTY", "eth": 0.0, "supply": 0}, {"verdict": "LEGACY-FUNDED", "eth": 1.0, "supply": 5},
       {"verdict": "ACTIVE-FUNDED", "eth": 9.0, "supply": 9}]
check([r["verdict"] for r in sorted(_sw, key=_legacy._value_key)] == ["LEGACY-FUNDED", "ACTIVE-FUNDED", "EMPTY"],
      "legacy: sweep _value_key ranks LEGACY-FUNDED first (then active, then empty) regardless of ETH size")

print("== recon Vyper guard (yUSD/Yearn-v2 lesson: never a false-clean on Vyper) ==")
check(recon.is_vyper("# @version 0.2.11\n@external\ndef deposit(_amount: uint256) -> uint256:\n    pass"),
      "recon.is_vyper: a Vyper contract (# @version / @external / def) is detected")
check(not recon.is_vyper("pragma solidity ^0.8.20;\ncontract C{function f() external { x=1; } }"),
      "recon.is_vyper: ordinary Solidity is NOT flagged as Vyper")

print("== INLINE_AUTH regex ==")
check(bool(recon.INLINE_AUTH.search("requireGovernanceOnly();")), "INLINE_AUTH matches requireGovernanceOnly")
check(bool(recon.INLINE_AUTH.search("_verifySignatures(a,b,c)")), "INLINE_AUTH matches _verifySignatures")
check(bool(recon.INLINE_AUTH.search("if (msg.sender == owner)")), "INLINE_AUTH matches msg.sender comparison")
check(not recon.INLINE_AUTH.search("_balances[msg.sender] += x;"), "INLINE_AUTH does NOT match bare msg.sender use")

print("== ledger (grouping + silencing) ==")
check(ledger.signature("t", "f.sol", "sibling", "fn") == ledger.signature("t", "f.sol", "access", "fn"),
      "sibling and access share group 'ac' (one verdict silences both)")
check(ledger.signature("t", "f.sol", "oracle", "fn") != ledger.signature("t", "f.sol", "sibling", "fn"),
      "different detector groups do NOT collide")
check(ledger.is_silenced({"verdict": "fp"}) and ledger.is_silenced({"verdict": "known"}),
      "fp/known silence")
check(not ledger.is_silenced({"verdict": "todo"}) and not ledger.is_silenced({"verdict": "real"}),
      "todo/real stay visible")
# round-trip add/load on a temp file (no pollution of the real ledger)
_tmp = os.path.join(tempfile.gettempdir(), "test-ledger.json")
if os.path.exists(_tmp):
    os.remove(_tmp)
ledger.add("tgt", "a.sol", 10, "sibling", "function f(...)", "fp", "why", "2026-01-01", path=_tmp)
_idx = ledger.load(_tmp)
check(ledger.is_silenced(ledger.verdict_for(_idx, "tgt", "a.sol", "access", "function f(...)")),
      "added sibling fp suppresses the access lead for the same fn (grouped)")
os.remove(_tmp)

print("== hypothesize universality (storage accessor: state. + diamond s.) ==")
import hypothesize  # noqa: E402
check(bool(hypothesize.STATE.search("state.data.users[a]=b")), "STATE matches state. (Size/Rheo)")
check(bool(hypothesize.STATE.search("s.aavegotchis[id].collateral=c")), "STATE matches diamond s. (Aavegotchi)")
check(bool(hypothesize.STATE.search("ds.layout=x")), "STATE matches ds. (diamond storage)")
check("s.foo" in hypothesize.direct_writes("s.foo = 1;"), "direct_writes captures a diamond s. write")
check("state.data.x" in hypothesize.direct_writes("state.data.x = 1;"), "direct_writes captures a state. write")
check(hypothesize.find_getters("function gs() internal pure returns (GameStorage storage) {}") == {"gs"},
      "find_getters detects a gs() AppStorage accessor fn (Dark Forest)")
_dsre = hypothesize.build_state_re({"gs", "ws"})
check(bool(_dsre.search("gs().planets[id].owner")) and bool(_dsre.search("ws().whitelist[a]")),
      "build_state_re matches gs()/ws() getter-style storage (Dark Forest gap fixed)")
check("gs().planetIds" in hypothesize.direct_writes("gs().planetIds = x; gs().count += 1;", _dsre),
      "direct_writes captures a gs() getter-style write when given the dynamic regex")
check("s.foo" in hypothesize.direct_writes("s.foo = 1;", _dsre),
      "dynamic regex still captures the base s. accessor (no regression)")

print("== hypothesize bridge + auto-propose (recon -> hypothesizer; deterministic, NO API) ==")
_fft = hypothesize.flags_from_text("contract C{function setFee(uint x) external { fee=x; }}", "src/C.sol")
check("setFee" in _fft and "access" in _fft["setFee"],
      "bridge: recon flags an ungated setFee and flags_from_text surfaces it to the hypothesizer")
_rt = hypothesize.auto_propose({"deposit": ["deposit"], "withdraw": ["withdraw"]}, {("deposit", "withdraw")}, [], {}, [])
check(any("ROUND-TRIP" in p for p in _rt), "auto_propose drafts a round-trip hypothesis from an inverse pair")
_em = hypothesize.auto_propose({}, set(), [("state.shares", {"a", "b", "c"})], {"a": {"reward"}}, [])
check(any("EMERGENT+RECON" in p and "reward" in p for p in _em),
      "auto_propose fuses a recon flag + shared state into an emergent hypothesis (the bridge)")
check(any("INVARIANT-GAP" in p for p in hypothesize.auto_propose({}, set(), [], {}, [])),
      "auto_propose proposes the missing-invariant complement when their harness declares none")
check(hypothesize._is_gated("(uint x) external onlyOwner", "fee=x;") and hypothesize._is_gated("(uint x) external auth", "fee=x;"),
      "controllability: only*/ward `auth` -> gated (NOT attacker-reachable)")
check(not hypothesize._is_gated("(uint x) external", "balances[msg.sender]+=x;"),
      "controllability: self-scoped mapping[msg.sender] fn is attacker-reachable (NOT gated)")
check(any("EMERGENT-OPEN" in p for p in hypothesize.auto_propose({}, set(), [("s.pot", {"a", "b"})], {}, [], {"a", "b"})),
      "auto_propose: 2 attacker-reachable writers -> EMERGENT-OPEN (no auth needed to interleave)")
check(any("EMERGENT+RECON+OPEN" in p for p in hypothesize.auto_propose({}, set(), [("s.pot", {"a", "b"})], {"a": {"reward"}}, [], {"a", "b"})),
      "auto_propose: attacker-reachable + recon-flagged writer -> hottest EMERGENT+RECON+OPEN")
check(not any("EMERGENT-OPEN" in p for p in hypothesize.auto_propose({}, set(), [("s.cfg", {"a", "b", "c"})], {}, [], set())),
      "auto_propose: all-gated root (no open writers) is NOT EMERGENT-OPEN (cold, admin-only)")

print("== hypothesize INVARIANT_MENU (DeFiHackLabs reasoning-tier seeds, CI-gated) ==")
_menu_groups = {g for g, _ in hypothesize.INVARIANT_MENU}
check(_menu_groups == {"CORE", "ECONOMIC (DeFi)", "GAMEFI / NFT (egor's edge)", "BRIDGE / CROSS-CHAIN"},
      "INVARIANT_MENU has the 4 sector groups (incl the new BRIDGE / CROSS-CHAIN)")
_all_seeds = " || ".join(s for _, seeds in hypothesize.INVARIANT_MENU for s in seeds)
for _kw in ["caller-supplied-authority", "stale-solvency-check", "read-only-reentrancy", "flashloan-governance",
            "self-liquidation-as-profit", "reward-on-no-op", "minted <= proven-locked", "spoofed-callee-return",
            "split-brain accounting"]:
    check(_kw in _all_seeds, f"INVARIANT_MENU carries the '{_kw}' reasoning-tier seed")

print("== fetch_source (live-first: etherscan source parsing, no network) ==")
import fetch_source  # noqa: E402
check(fetch_source.parse_etherscan_source("contract C{}", "MyToken") == {"MyToken.sol": "contract C{}"},
      "flat source -> single ContractName.sol")
_sj = fetch_source.parse_etherscan_source(
    '{{"sources":{"src/A.sol":{"content":"contract A{}"},"src/B.sol":{"content":"contract B{}"}}}}')
check(_sj.get("src/A.sol") == "contract A{}" and _sj.get("src/B.sol") == "contract B{}",
      "standard-json {{..}} double-wrap -> multi-file map keyed by path")
check(fetch_source.parse_etherscan_source('{"sources":{"X.sol":{"content":"contract X{}"}}}').get("X.sol") == "contract X{}",
      "single-brace standard-json also parsed")
check(fetch_source.parse_etherscan_source("") == {}, "empty SourceCode -> empty map (graceful)")
check(fetch_source.impl_from_eip1167("0x363d3d373d3d3d363d73" + "ab" * 20 + "5af43d82803e903d91602b57fd5bf3")
      == "0x" + "ab" * 20, "EIP-1167 minimal-proxy: impl address parsed from bytecode")
check(fetch_source.impl_from_eip1167("0x6080604052348015") is None, "non-proxy bytecode -> None (no false impl)")

print("== det_l2_footgun (zkSync / native-AA EOA-assumption footguns) ==")
check(flagged(recon.det_l2_footgun, "function isContract(address a) internal view returns(bool){uint s; assembly{s:=extcodesize(a)} return s>0;}"),
      "extcodesize + custom isContract flagged (zkSync AA footgun, from zkMarkets)")
check(flagged(recon.det_l2_footgun, "function verify(address signer,bytes sig) public { if (signer.code.length==0){ ECDSA.recover(h,sig); } }"),
      "address.code.length EOA-check flagged (AA footgun)")
check(not flagged(recon.det_l2_footgun, "function transfer(address to, uint x) external { balances[to]+=x; }"),
      "ordinary code NOT flagged by det_l2_footgun")

print("== det_erc4626 (fix#20: balance-based totalAssets = direct donation vector) ==")
_bb = recon.det_erc4626("contract V is ERC4626 { function totalAssets() public view returns(uint){ return asset.balanceOf(address(this)); } }", "src/V.sol")
check(bool(_bb) and "balance-based" in _bb[0][3], "fix#20: balance-based totalAssets -> dStake-flavor note")
check(not flagged(recon.det_erc4626, "contract V is ERC4626 { function _decimalsOffset() internal pure returns(uint8){return 3;} }"),
      "ERC4626 with _decimalsOffset NOT flagged (mitigation)")
check(flagged(recon.det_erc4626, "contract V is ERC4626 { function totalAssets() public view returns(uint){ return _internalBal; } }"),
      "unprotected ERC4626 with internal-accounting totalAssets still flagged (generic note)")

print("== det_reward (pattern 03: double-claim / late marker) ==")
check(flagged(recon.det_reward, "contract C{function claimRewards() external { token.transfer(msg.sender, amt); }}", "claimRewards"),
      "reward payout with NO claimed-marker flagged [!]")
check(not flagged(recon.det_reward, "contract C{function claimRewards() external { claimed[msg.sender]=true; token.safeTransfer(msg.sender, amt); }}"),
      "claimed-marker written BEFORE transfer NOT flagged (safe)")
_late = recon.det_reward("contract C{function claimRewards() external { token.safeTransfer(msg.sender, amt); claimed[msg.sender]=true; }}", "src/C.sol")
check(bool(_late) and _late[0][4] == 1 and "AFTER" in _late[0][3], "marker AFTER transfer -> [.] CEI double-claim lead")
check(not flagged(recon.det_reward, "contract C{function harvest() external onlyKeeper { token.safeTransfer(treasury, amt); }}"),
      "keeper-gated harvest NOT flagged (no per-user double-claim surface)")
check(not flagged(recon.det_reward, "contract C{function setFee(uint x) external { fee=x; }}"),
      "non-reward function NOT flagged")
check(not flagged(recon.det_reward, "contract C{function claimSettlementFee(address t,uint256 a,address r) external { require(msg.sender==feeClaimer); claimableFee[t] -= a; SafeTransferLib.safeTransfer(t,r,a); }}"),
      "fix#21: claimable decremented (-=) before transfer NOT flagged (Morpho Midnight admin fee-claim)")

print("== det_index (pattern 04: Aave-fork interest-index inflation) ==")
check(flagged(recon.det_index, "contract P{function f() external { reserve.liquidityIndex = newIndex; cumulateToLiquidityIndex(amt); }}"),
      "liquidityIndex write + cumulateToLiquidityIndex flagged")
_gi = recon.det_index("contract P{uint MIN_LIQUIDITY=1e3; function f() external { liquidityIndex = x; }}", "src/P.sol")
check(bool(_gi) and _gi[0][4] == 1, "min-liquidity guard present -> downgraded to [.]")
check(not flagged(recon.det_index, "contract C{function f() external { balances[msg.sender]+=1; }}"),
      "non-Aave-fork file NOT flagged")

print("== det_domain (pattern 06: cached EIP-712 separator, fork replay) ==")
check(flagged(recon.det_domain, "contract C{ bytes32 public DOMAIN_SEPARATOR; constructor(){ DOMAIN_SEPARATOR = keccak256(abi.encode(TYPEHASH, block.chainid, address(this))); } }"),
      "cached DOMAIN_SEPARATOR with block.chainid, no recompute -> flagged [!]")
check(not flagged(recon.det_domain, "contract C is EIP712 { function f() internal view { bytes32 d = _domainSeparatorV4(); } }"),
      "OZ _domainSeparatorV4 (recomputes on chainid change) NOT flagged")
check(not flagged(recon.det_domain, "contract C{ function transfer(address to,uint a) external { bal[to]+=a; } }"),
      "no EIP-712 at all NOT flagged")

print("== det_liquidation (pattern 05: self-liq / rounding surfacer) ==")
_ul = recon.det_liquidation("contract C{function liquidate(address u) external { seizeCollateral(u); }}", "src/C.sol")
check(bool(_ul) and _ul[0][4] == 0 and "self-liquidation" in _ul[0][3], "unguarded liquidate -> [!] + self-liq note")
_gl = recon.det_liquidation("contract C{function liquidate(address u) external { require(u != msg.sender); if(!isHealthy(u)) _seize(u); }}", "src/C.sol")
check(bool(_gl) and _gl[0][4] == 1, "self-guard + health recheck -> surfaced at [.] not [!]")
check(not flagged(recon.det_liquidation, "contract C{function deposit(uint a) external { bal[msg.sender]+=a; }}"),
      "non-liquidation function NOT surfaced")
_hg = recon.det_liquidation("contract C{function liquidate(address u) external { require(debt > maxDebt, NotLiquidatable()); x = a.mulDivUp(b); }}", "src/C.sol")
check(bool(_hg) and _hg[0][4] == 1, "fix#22: health-gated liquidation with up-rounding -> [.] not [!] (Morpho Midnight)")
_su = recon.det_liquidation("contract C{function liquidate(address u) external { uint seized = repay.mulDivUp(price); coll[u]-=seized; }}", "src/C.sol")
check(bool(_su) and "collateral-OUT" in _su[0][3], "fix#23: seize/collateral-OUT rounds up -> flagged (favors liquidator)")
_ru = recon.det_liquidation("contract C{function liquidate(address u) external { require(isHealthy(u)==false); uint repaid = seized.mulDivUp(price); }}", "src/C.sol")
check(bool(_ru) and "collateral-OUT" not in _ru[0][3], "fix#23: repaid/debt-side rounds up -> NOT flagged for rounding (protocol-favorable)")

print("== det_oracle (spot-reserve pricing sub-check) ==")
check(flagged(recon.det_oracle, "contract C{function getPrice() public view returns(uint){ (uint112 r0,uint112 r1,)=pair.getReserves(); return uint(r1)*1e18/uint(r0); }}", "function getPrice"),
      "value/price fn dividing SPOT reserves -> spot-manip lead")
check(not flagged(recon.det_oracle, "contract C{function getValue() public view returns(uint){ (uint r0,uint r1,)=pair.getReserves(); return cumulativePrice(r0) * 1e18 / r1; }}"),
      "getReserves but 'cumulative' (TWAP) in body NOT flagged (mitigation recognized)")

print("== det_arbcall (fix#24: inline admin-gate on arbitrary call) ==")
check(flagged(recon.det_arbcall, "contract C{function exec(address t, bytes d) external { t.call(d); }}", "exec"),
      "permissionless (address+bytes)+call flagged as arbitrary-call drain")
check(not flagged(recon.det_arbcall, "contract C{function replayCall(address t, bytes d) external { require(msg.sender==admin); t.call(d); }}"),
      "fix#24: inline require(msg.sender==admin) admin-gate NOT flagged (EtherOrcs MainlandPortal.replayCall)")
check(not flagged(recon.det_arbcall, "contract C{function exec(address t, bytes d) external onlyOwner { t.call(d); }}"),
      "onlyOwner arbitrary call NOT flagged")
check(not flagged(recon.det_arbcall, "contract C{function withBatch(bytes data, uint v, address refund) public payable { (bool s,) = msg.sender.call{value:v}(data); require(s); }}"),
      "fix#28: low-level call to msg.sender (callback-to-caller batching) NOT flagged (Centrifuge Gateway.withBatch)")
check(flagged(recon.det_arbcall, "contract C{function exec(address t, bytes d) external { (bool s,)=msg.sender.call(''); t.call(d); }}", "exec"),
      "fix#28 guard: a non-self t.call(d) STILL flagged even alongside a msg.sender.call")

print("== det_weak_random (predictable on-chain RNG in an outcome path) ==")
_wr = recon.det_weak_random("contract G{function _getReward(uint id) internal view returns(uint){"
                            " uint rdn = uint256(keccak256(abi.encodePacked(block.timestamp, blockhash(block.number-1), id))) % 10000; return rdn; }}", "src/Game.sol")
check(bool(_wr) and _wr[0][4] == 0, "keccak over block.timestamp/blockhash + modulo in a reward fn -> [!]")
check(flagged(recon.det_weak_random, "contract C{function _rand() internal view returns(uint){"
      " return uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, block.basefee, entropySauce))); }}"),
      "EtherOrcs-style _rand() (keccak over block entropy, 'rand' context) flagged")
_we = recon.det_weak_random("contract W{function mint() external { require(tx.origin == _msgSender());"
                            " uint seed = uint256(keccak256(abi.encodePacked(tx.origin, blockhash(block.number-1), block.timestamp))); }}", "src/Woolf.sol")
check(bool(_we) and "EOA-gate" in _we[0][3],
      "fix: tx.origin==msg.sender EOA-gate noted as a speed bump, still flagged (Wolf Game class)")
_wv = recon.det_weak_random("contract V is VRFConsumerBase{ function fulfillRandomWords(uint reqId, uint[] memory words) internal {"
                            " uint r = uint256(keccak256(abi.encodePacked(words[0], block.timestamp))) % 10; } }", "src/V.sol")
check(bool(_wv) and _wv[0][4] == 1, "VRF in file -> keccak-of-entropy downgraded to [.] (verify which path drives the outcome)")
check(not flagged(recon.det_weak_random, "contract C{ bytes32 d = keccak256(abi.encode(TYPEHASH, block.chainid, address(this))); }"),
      "EIP-712 domain separator (block.chainid) NOT flagged as RNG")
check(not flagged(recon.det_weak_random, "contract C{function id(uint x) internal view returns(bytes32){ return keccak256(abi.encodePacked(x, address(this))); }}"),
      "keccak with NO block entropy NOT flagged as RNG")
# NEW: direct modulo of block entropy (no keccak) in an outcome ctx -> flagged
check(flagged(recon.det_weak_random, "contract C{function spin() external { uint winner = block.prevrandao % players; payout(winner); }}"),
      "det_weak_random: DIRECT modulo of block entropy (block.prevrandao % players, no keccak) flagged in an outcome ctx")
check(not flagged(recon.det_weak_random, "contract C{function epoch() public view returns(uint){ return block.number % epochLength; }}"),
      "det_weak_random guard: block.number % epochLength (no RNG-outcome word) NOT flagged (no time-bucket FP)")

print("== det_nft_callback (ERC721/1155 receiver-hook reentrancy -- #1 NFT bug) ==")
check(flagged(recon.det_nft_callback, "contract G is ERC721{function claim() external { _safeMint(msg.sender, nextId); totalMinted++; }}", "claim"),
      "det_nft_callback: _safeMint THEN state write (totalMinted++), no nonReentrant -> receiver-hook reentrancy")
check(not flagged(recon.det_nft_callback, "contract G is ERC721{function claim() external nonReentrant { _safeMint(msg.sender, nextId); totalMinted++; }}"),
      "det_nft_callback guard: nonReentrant -> NOT flagged")
check(not flagged(recon.det_nft_callback, "contract G is ERC721{function claim() external { totalMinted++; _safeMint(msg.sender, nextId); }}"),
      "det_nft_callback guard: state write BEFORE _safeMint (CEI-correct) -> NOT flagged")
check(not flagged(recon.det_nft_callback, "contract V{using SafeERC20 for IERC20; function pull(address t,uint a) external { IERC20(t).safeTransferFrom(msg.sender, address(this), a); deposited[msg.sender]+=a; }}"),
      "det_nft_callback guard: SafeERC20 safeTransferFrom in a NON-NFT file (no hook) -> NOT flagged (no FP)")

print("== det_swap_guard (slippage / deadline; sandwich/MEV) ==")
check(flagged(recon.det_swap_guard, "contract C{function zap(uint a) external { router.swapExactTokensForTokens(a, 0, path, to, block.timestamp); }}"),
      "V2 swapExactTokensForTokens with positional amountOutMin==0 flagged")
_sv3 = recon.det_swap_guard("contract C{function s(uint a) external { router.exactInputSingle(ISwapRouter.ExactInputSingleParams({tokenIn:t0,tokenOut:t1,fee:500,recipient:msg.sender,deadline:block.timestamp,amountIn:a,amountOutMinimum:0,sqrtPriceLimitX96:0})); }}", "src/C.sol")
check(bool(_sv3) and any(l[4] == 0 and "amountOutMin == 0" in l[3] for l in _sv3),
      "V3 exactInputSingle with amountOutMinimum: 0 flagged [!]")
check(not flagged(recon.det_swap_guard, "contract C{function s(uint a,uint minOut) external { router.swapExactTokensForTokens(a, minOut, path, to, deadline); }}"),
      "swap with a real (non-zero) min-out NOT flagged")
_sd = recon.det_swap_guard("contract C{function s(uint a,uint m) external { router.swapExactTokensForTokens(a, m, path, to, deadline); uint x; deadline = block.timestamp; }}", "src/C.sol")
# deadline=block.timestamp near a swap -> [.] no-expiry note (only the deadline lead, not the safe swap)
check(any(l[4] == 1 and "no expiry" in l[3] for l in _sd),
      "deadline = block.timestamp near a swap -> [.] no-expiry lead")
check(not flagged(recon.det_swap_guard, "contract C{function transfer(address to,uint a) external { bal[to]+=a; }}"),
      "non-swap function NOT flagged")

print("== det_mapping_default (Nomad class: unset key passes a gate) ==")
_nd = recon.det_mapping_default('contract R{function process(bytes32 h) external { require(acceptableRoot(messages[h]), "!proven"); }}', "src/Replica.sol")
check(bool(_nd), "Nomad-style gate over a security mapping (acceptableRoot/messages) flagged")
check(not flagged(recon.det_mapping_default, 'contract R{function f(bytes32 r) external { require(confirmAt[r] != 0, "not confirmed"); }}'),
      "explicit default-rejection (confirmAt[r] != 0) NOT flagged (safe gate)")
_na = recon.det_mapping_default("contract R{function ok(bytes32 h) external view returns(bool){ return acceptableRoot[messages[h]]; }}", "src/R.sol")
check(bool(_na) and any(l[4] == 0 for l in _na), "Shape A: security mapping indexed by another mapping's result -> [!] value-as-key")
check(not flagged(recon.det_mapping_default, "contract C{function claim(uint id) external { require(!used[id]); used[id]=true; }}"),
      "ordinary nonce/used guard (not a security-root mapping) NOT flagged")
check(not flagged(recon.det_mapping_default, "contract C{function f(address u) external { require(balances[u] > 0); }}"),
      "ordinary balances gate NOT flagged (not a security mapping)")

print("== det_strict_balance (force-feed DoS) ==")
check(flagged(recon.det_strict_balance, "contract C{function f() external { require(address(this).balance == target, 'bad'); }}"),
      "strict == on address(this).balance flagged")
check(flagged(recon.det_strict_balance, "contract C{function f() external { if (token.balanceOf(address(this)) == expected) run(); }}"),
      "strict == on balanceOf flagged")
check(not flagged(recon.det_strict_balance, "contract C{function f() external { require(token.balanceOf(address(this)) >= expected); }}"),
      "balanceOf with >= (delta-safe) NOT flagged")
check(not flagged(recon.det_strict_balance, "contract C{function f() external { uint b = address(this).balance; pay(b); }}"),
      "reading balance without an equality comparison NOT flagged")
check(not flagged(recon.det_strict_balance, "contract C{function f(bytes4 sig) external { if (sig == I.balanceOf.selector || sig == I.balanceOfBatch.selector) revert(); }}"),
      "FP guard: == ...balanceOf.selector (a selector ref, not a balance value) NOT flagged")

print("== scout (Stage-0 target sourcing: pure logic, no network) ==")
import scout  # noqa: E402
check(scout.target_key("2025-07-mellow-flexible-vaults") == "mellow-flexible-vaults",
      "scout.target_key strips the sherlock YYYY-MM- date prefix")
check(scout.target_key("dTRINITY-0xee5c6f15e8d0b55a5eff84bb66beeee0e6140ffe") == "dtrinity",
      "scout.target_key strips the trailing hats -0x.. hash + lowercases")
check(bool(scout.SKIP_NAME.search("2025-07-cap-judging")) and not scout.SKIP_NAME.search("2026-01-fluid-dex-v2"),
      "scout.SKIP_NAME drops -judging mirrors, keeps real contest repos")
check(scout.age_days("2025-06-09", "2026-06-09") > 360 and scout.age_days("2026-06-01", "2026-06-09") == 8,
      "scout.age_days: ~1yr apart > 360; 8 days apart == 8")
check(any(k in "lending vault for cross-chain stablecoin".lower() for k in scout.WHEELHOUSE),
      "scout.WHEELHOUSE matches our-zone keywords (vault/lend/stablecoin/cross-chain)")
check({"Bridge", "Cross Chain Bridge", "Bridge Aggregator"} <= scout.DL_CATEGORIES
      and "Canonical Bridge" not in scout.DL_CATEGORIES,
      "scout.DL_CATEGORIES surfaces bridges (Bridge/Cross Chain Bridge/Aggregator) but NOT Canonical Bridge (audited L2 forks)")
# expanded game/gamble/predict sector (egor's edge)
check(all(any(k in s for k in scout.WHEELHOUSE) for s in
          ["a luck games coin flip", "sports betting protocol", "prediction market", "weekly raffle lottery", "casino jackpot"]),
      "scout.WHEELHOUSE: gambling/luck/betting/prediction/lottery sector now matches (det_weak_randomness lens)")
check(not any(k in "alphabet soup recipe" for k in scout.WHEELHOUSE),
      "scout.WHEELHOUSE: no bare 'bet' substring -> 'alphabet' is NOT a false zone hit")
check({"Gambling", "Luck Games", "Yield Lottery", "Betting"} <= scout.DL_CATEGORIES,
      "scout.DL_CATEGORIES: the game/gamble/lottery DefiLlama categories now pass the hard filter")
check(scout.audits_int("0") == 0 and scout.audits_int("2") == 2 and scout.audits_int(None) == 9,
      "scout v2: audits_int parses DefiLlama stringy audit count (None -> high so it's filtered)")
check(scout.is_all_non_evm(["Solana", "Sui"]) and not scout.is_all_non_evm(["Ethereum", "Solana"]),
      "scout v2: is_all_non_evm skips pure non-EVM, keeps protocols with an EVM chain (engines are Solidity)")
check(scout.is_suppressed("mellow-flexible-vaults", {"mellow"}) and not scout.is_suppressed("aave-v3", {"cap"}),
      "scout v2: is_suppressed matches a hunted target by first segment, not by tiny coincidences")
# reachability fix: resolve the CORE-contracts GitHub repo (not the gov token DefiLlama lists)
check(scout.dl_github_orgs({"github": ["RoycoProtocol", "https://github.com/foo/bar"]}) == ["RoycoProtocol", "foo"]
      and scout.dl_github_orgs({"github": "hopperlabsxyz"}) == ["hopperlabsxyz"]
      and scout.dl_github_orgs({}) == [],
      "scout.dl_github_orgs: parses DefiLlama github field (list/url/str/missing) into clean handles")
check(scout.lang_is_evm("Solidity") and scout.lang_is_evm("TypeScript") and not scout.lang_is_evm("Rust")
      and not scout.lang_is_evm("Move"),
      "scout.lang_is_evm: Solidity/TS huntable; Rust/Move flagged non-EVM (the Templar=NEAR/Rust case)")
_repos = [{"name": "contracts", "language": "Solidity", "description": "core smart contracts"},
          {"name": "interface", "language": "TypeScript"}, {"name": "docs", "language": "MDX"},
          {"name": "sdk", "language": "TypeScript"}]
check((scout.pick_core_repo(_repos, "Foo") or {}).get("name") == "contracts",
      "scout.pick_core_repo: picks the Solidity `contracts` repo over interface/docs/sdk noise")
check(scout.pick_core_repo([{"name": "contracts", "language": "Solidity", "archived": True}], "Foo") is None,
      "scout.pick_core_repo: an archived repo is rejected (-> None, nothing to clone)")
check((scout.pick_core_repo([{"name": "contracts", "language": "Rust"}, {"name": "cli", "language": "Rust"}], "Templar") or {}).get("name") == "contracts"
      and not scout.lang_is_evm("Rust"),
      "scout: Templar-shape repo still picks `contracts`, but lang_is_evm flags it NON-EVM (skip early)")
# scout v3 (Immunefi): parse the escaped-JSON program objects from the bounty-list RSC stream
_imm_html = (r'x,\"launchDate\":\"2026-05-01T00:00:00.000Z\",\"updatedDate\":\"2026-05-28T11:35:58.847Z\",\"kyc\":true,\"maxBounty\":15000000,'
             r'\"project\":\"LayerZero\",\"slug\":\"layerzero\",\"tags\":{\"language\":[\"Solidity\"],'
             r'\"ecosystem\":[],\"productType\":[\"Crosschain Liquidity\"],\"programType\":[\"Smart Contract\"],'
             r'\"projectType\":[\"Defi\"]},y'
             r'z,\"launchDate\":\"2021-01-10T00:00:00.000Z\",\"updatedDate\":\"2026-04-10T07:00:00.000Z\",\"kyc\":false,\"maxBounty\":500000,'
             r'\"project\":\"SomeChain\",\"slug\":\"somechain\",\"tags\":{\"language\":[\"Rust\"],'
             r'\"ecosystem\":[],\"productType\":[\"L1\"],\"programType\":[\"Blockchain/DLT\"],'
             r'\"projectType\":[\"Infrastructure\"]},w')
_imm = scout.parse_immunefi_programs(_imm_html)
check(len(_imm) == 2 and _imm[0]["name"] == "LayerZero" and _imm[0]["slug"] == "layerzero"
      and _imm[0]["maxBounty"] == 15000000 and _imm[0]["language"] == ["solidity"] and _imm[0]["launched"] == "2026-05-01",
      "scout.parse_immunefi_programs: extracts name/slug/maxBounty/language/launchDate from the escaped-JSON RSC blob")
check(scout.imm_is_evm_sc(_imm[0]) and not scout.imm_is_evm_sc(_imm[1]),
      "scout.imm_is_evm_sc: keeps Solidity Smart-Contract (LayerZero), drops Rust Blockchain/DLT (SomeChain)")

print("== contest_monitor (timing edge: parse Cantina/Sherlock/C4 + fresh/zone classify) ==")
import contest_monitor as cm  # noqa: E402
_can = cm.parse_cantina([{"name": "Morpho Midnight", "url": "https://cantina.xyz/x", "id": "abc",
    "totalRewardPot": "400000", "status": "live", "instructions": "fixed-rate lending markets, credit/debt units",
    "timeframe": {"start": "2026-05-29T12:00:00Z", "end": "2026-06-12T20:00:00Z"}, "company": {"github": "morpho-org"}}])
check(len(_can) == 1 and _can[0]["pot"] == 400000 and _can[0]["repo"] == "morpho-org"
      and _can[0]["start_unix"] == cm._iso_to_unix("2026-05-29T12:00:00Z") and _can[0]["start_unix"] > 0,
      "contest_monitor.parse_cantina: name/pot/repo/timeframe extracted from the competitions JSON")
check(cm.parse_sherlock({"items": [{"title": "DRE dreUSD", "id": 1259, "rewards": 60000, "status": "RUNNING",
      "starts_at": 1780930800, "ends_at": 1781708400, "short_description": "stablecoin vault"}]})[0]["pot"] == 60000,
      "contest_monitor.parse_sherlock: items[] -> pot/start/end (unix passthrough)")
check(cm.parse_code4rena({"data": {"audits": [{"title": "Monetrix", "slug": "monetrix", "status": "Live",
      "formattedAmount": "$100,000", "startTime": "2026-04-24T20:00:00Z", "endTime": "2026-05-04T20:00:00Z",
      "repo": "code-423n4/2026-04-monetrix", "details": "an AMM"}]}})[0]["pot"] == 100000,
      "contest_monitor.parse_code4rena: data.audits[] -> '$100,000' formattedAmount parsed to 100000")
_now = cm._iso_to_unix("2026-06-10T00:00:00Z")
_liveC = {"start_unix": cm._iso_to_unix("2026-06-09T00:00:00Z"), "end_unix": cm._iso_to_unix("2026-06-20T00:00:00Z"), "status": "live"}
_pastC = {"start_unix": cm._iso_to_unix("2026-04-01T00:00:00Z"), "end_unix": cm._iso_to_unix("2026-04-10T00:00:00Z"), "status": "completed"}
check(cm.is_live(_liveC, _now) and not cm.is_live(_pastC, _now),
      "contest_monitor.is_live: within-window live; past/completed excluded")
check(cm.hours_since_start(_liveC, _now) < 48 and cm.hours_since_start(_pastC, _now) > 48,
      "contest_monitor.hours_since_start: the FRESH (<48h) signal -- the first-hours timing edge")
check(bool(cm.zone_hits({"title": "Fixed-Rate Lending", "desc": "credit/debt units, collateral vault"})),
      "contest_monitor.zone_hits: our-wheelhouse keywords matched")
check(cm.is_gamefi({"title": "Pirate NFT Game", "desc": "on-chain game p2e"})
      and not cm.is_gamefi({"title": "Lending Pool", "desc": "borrow"}),
      "contest_monitor.is_gamefi: GameFi flagged (egor's edge bonus), plain DeFi not")
check(cm.is_gamefi({"title": "DiceRoll Casino", "desc": "on-chain dice betting wager payout"})
      and cm.is_gamefi({"title": "Prediction Market", "desc": "sports betting odds"})
      and cm.is_gamefi({"title": "EtherFlip", "desc": "coinflip luck games jackpot"}),
      "contest_monitor.is_gamefi: expanded -> gambling/betting/prediction/luck/casino now flagged GameFi")
check(cm.looks_non_evm({"title": "Solana Program", "desc": "anchor sealevel"})
      and not cm.looks_non_evm({"title": "EVM Vault", "desc": "solidity erc4626"}),
      "contest_monitor.looks_non_evm: Solana/Move/consensus down-ranked; EVM not")
check(cm._pot_int("$2,500,000") == 2500000 and cm._pot_int(60000) == 60000 and cm._pot_int("100000 USDC") == 100000,
      "contest_monitor._pot_int: parses $-formatted / numeric / suffixed reward pots")
# fresher contest outranks a stale one of equal pot/zone (the whole point of the monitor)
_fresh = {"title": "A Vault", "desc": "lending", "pot": 100000, "start_unix": _now - 3600, "end_unix": _now + 9e5, "status": "live"}
_stale = {"title": "B Vault", "desc": "lending", "pot": 100000, "start_unix": _now - 40*3600, "end_unix": _now + 9e5, "status": "live"}
check(cm.score(_fresh, _now, 48) > cm.score(_stale, _now, 48),
      "contest_monitor.score: a fresher contest outranks a stale one (equal pot/zone) -- timing edge baked in")
# --alert trigger: alertable() = NEW + FRESH + EVM-likely + our-zone (the always-on Task signal)
def _cm_c(plat, cid, title, desc, age_h):
    return {"platform": plat, "id": cid, "title": title, "desc": desc, "pot": 50000,
            "start_unix": _now - int(age_h * 3600), "end_unix": _now + 7 * 86400, "status": "live"}
_cm_live = [_cm_c("sherlock", "1", "Fresh Lending Vault", "a lending vault protocol", 2),    # NEW+FRESH+EVM+zone -> ALERT
            _cm_c("cantina", "2", "Old Perp DEX", "perp dex", 100),                          # NEW but stale -> no
            _cm_c("code4rena", "3", "Solana Staking", "solana anchor staking program", 1),   # NEW+FRESH but non-EVM -> no
            _cm_c("sherlock", "4", "Generic Thing", "just some app", 1),                     # NEW+FRESH+EVM, no zone -> no
            _cm_c("cantina", "5", "Seen Stablecoin", "stablecoin cdp", 1)]                   # fresh+zone but SEEN -> no
_cm_newkeys = {cm.contest_key(c) for c in _cm_live} - {cm.contest_key(_cm_live[4])}
check([h["id"] for h in cm.alertable(_cm_live, _cm_newkeys, _now, 48)] == ["1"],
      "contest_monitor.alertable: only the NEW+FRESH+EVM+our-zone contest fires (drops stale/non-EVM/no-zone/seen)")

print("== vault-gap detectors (downcast / precision / encodePacked / fee-on-transfer / delete-mapping) ==")
check(flagged(recon.det_downcast, "contract C{function f(uint256 a,uint256 b) external { y = uint128(a + b); }}"),
      "det_downcast: uint128(a + b) (a COMPUTED value) flagged (silent truncation)")
check(not flagged(recon.det_downcast, "contract C{function f(uint256 x) external { y = uint128(x); }}"),
      "det_downcast guard: uint128(x) bare var (intentional packing) NOT flagged (precision > recall)")
check(not flagged(recon.det_downcast, "contract C{function f() external { y = uint128(0); z = uint64(1e18); }}"),
      "det_downcast guard: casts of literals (uint128(0)/uint64(1e18)) NOT flagged (compiler-checked)")
check(not flagged(recon.det_downcast, "contract C{function f(address a) external { uint160 u = uint160(a); }}"),
      "det_downcast guard: uint160(addr) (address<->uint idiom) NOT flagged")
check(not flagged(recon.det_downcast, "contract C{function f(uint256 x) external { y = uint256(x); }}"),
      "det_downcast guard: uint256(x) (no truncation) NOT flagged")
check(not flagged(recon.det_downcast, "contract C{function f() external { t = uint64(block.timestamp); }}"),
      "det_downcast guard: uint64(block.timestamp) NOT flagged (can't overflow)")
check(flagged(recon.det_precision, "contract C{function f(uint a,uint b,uint c) external { y = a / b * c; }}"),
      "det_precision: a / b * c (divide-before-multiply) flagged")
check(flagged(recon.det_precision, "contract C{function f(uint a,uint b,uint c) external { y = (a / b) * c; }}"),
      "det_precision: (a/b)*c flagged")
check(not flagged(recon.det_precision, "contract C{function f(uint a,uint b,uint c) external { y = a * c / b; }}"),
      "det_precision guard: a * c / b (multiply-first, safe) NOT flagged")
# det_decimal_scale (ZKFair gas-token / bridge playbook E) -- lone decimals-factor mul/div, det_precision misses it
check(flagged(recon.det_decimal_scale, "contract C{function f() external { leafAmount /= gasTokenDecimalDiffFactor; }}"),
      "det_decimal_scale: `leafAmount /= gasTokenDecimalDiffFactor` flagged (the ZKFair shape)")
check(flagged(recon.det_decimal_scale, "contract C{function f() external { amount = amount * decimalsFactor; }}"),
      "det_decimal_scale: amount * decimalsFactor flagged")
check(not flagged(recon.det_decimal_scale, "contract C{function f(uint a,uint b,uint c) external { y = a / b * c; }}"),
      "det_decimal_scale scope: a/b*c (no decimals-factor name) is det_precision's job, NOT flagged here")
check(not flagged(recon.det_decimal_scale, "contract C{function f(uint a) external { y = a * 1e18; }}"),
      "det_decimal_scale: a generic `a * 1e18` (no decimals-factor var) -> NOT flagged (FP gate)")
check(not flagged(recon.det_decimal_scale, "contract C{ // amount /= decimalsFactor in the old code\n function f() external { x=1; }}"),
      "det_decimal_scale: the factor mentioned only in a COMMENT -> NOT flagged (line-based comment-skip)")
check(not flagged(recon.det_precision, "contract C{function f(uint a,uint b,uint c,uint d) external { y = a / b + c * d; }}"),
      "det_precision guard: a/b + c*d (independent terms) NOT flagged")
check(flagged(recon.det_encodepacked, "contract C{function f(string a,string b) external { h = keccak256(abi.encodePacked(a, b)); }}"),
      "det_encodepacked: keccak256(abi.encodePacked(a,b)) (2+ args) flagged")
check(not flagged(recon.det_encodepacked, "contract C{function f(string a) external { h = keccak256(abi.encodePacked(a)); }}"),
      "det_encodepacked guard: single-arg encodePacked NOT flagged (no collision)")
check(not flagged(recon.det_encodepacked, "contract C{function f(string a,string b) external { x = abi.encodePacked(a, b); }}"),
      "det_encodepacked guard: encodePacked NOT in a hash context NOT flagged")
# precision harvest (Gigaverse): 2+ ADJACENT DYNAMIC array params -> HIGH [!]; all-fixed args stay low [.]
_ep_hi = recon.det_encodepacked("contract C{function exp(address p,uint256[] calldata ids,uint256[] calldata amts,uint256 n) external { bytes32 h=keccak256(abi.encodePacked(p,ids,amts,n)); }}", "x.sol")
check(bool(_ep_hi) and _ep_hi[0][4] == 0,
      "det_encodepacked: 2+ ADJACENT dynamic array params in a hash -> HIGH [!] (Gigaverse ImportExport collision)")
_ep_lo = recon.det_encodepacked("contract C{function permit(address owner,address spender,uint256 value,uint256 nonce) external { bytes32 h=keccak256(abi.encodePacked(owner,spender,value,nonce)); }}", "x.sol")
check(bool(_ep_lo) and _ep_lo[0][4] == 1,
      "det_encodepacked: all-fixed args (permit-shape) stay low [.] (no adjacent dynamic -> no collision)")
check(flagged(recon.det_feeontransfer, "contract C{function deposit(uint a) external { token.transferFrom(msg.sender, address(this), a); bal[msg.sender]+=a; }}"),
      "det_feeontransfer: transferFrom to address(this) + no balance-delta flagged")
check(not flagged(recon.det_feeontransfer, "contract C{function deposit(uint a) external { uint b0=token.balanceOf(address(this)); token.transferFrom(msg.sender,address(this),a); uint d=token.balanceOf(address(this))-b0; bal[msg.sender]+=d; }}"),
      "det_feeontransfer guard: file measures balanceOf(this) delta -> NOT flagged (handled)")
check(not flagged(recon.det_feeontransfer, "contract C{function f(address t,address u,uint a) external { IERC20(t).transferFrom(u, msg.sender, a); }}"),
      "det_feeontransfer guard: transferFrom NOT to address(this) NOT flagged")
check(flagged(recon.det_delete_mapping, "contract C{struct S{ uint x; mapping(address=>uint) bal; } mapping(uint=>S) m; function f(uint id) external { delete m[id]; }}"),
      "det_delete_mapping: delete of a struct-with-mapping flagged (mapping not cleared)")
check(not flagged(recon.det_delete_mapping, "contract C{struct S{ uint x; uint y; } mapping(uint=>S) m; function f(uint id) external { delete m[id]; }}"),
      "det_delete_mapping guard: struct with NO mapping -> delete NOT flagged")
check(not flagged(recon.det_delete_mapping, "contract C{struct S{ uint x; mapping(address=>uint) bal; } function f() external { x = 1; }}"),
      "det_delete_mapping guard: struct-with-mapping but NO delete -> NOT flagged")
check(recon.det_overflow("pragma solidity ^0.7.6;\ncontract C{}", "src/C.sol")[0][4] == 0,
      "det_overflow: pre-0.8 pragma flagged [!] (no built-in overflow protection)")
check(flagged(recon.det_overflow, "contract C{function f(uint x,uint y) external { unchecked { z = x + y; } }}"),
      "det_overflow: unchecked{} block flagged (opts out of 0.8 checks)")
check(not flagged(recon.det_overflow, "pragma solidity ^0.8.20;\ncontract C{function f(uint x,uint y) external { z = x + y; }}"),
      "det_overflow guard: 0.8.x with no unchecked block NOT flagged (protected)")
check(flagged(recon.det_flashloan, "contract C{function executeOperation(address a,uint x,uint f,address initiator,bytes d) external returns(bool){ token.approve(spender, x); return true; }}"),
      "det_flashloan: executeOperation with NO initiator/sender check flagged [!]")
check(not flagged(recon.det_flashloan, "contract C{function executeOperation(address a,uint x) external returns(bool){ require(msg.sender == pool); return true; }}"),
      "det_flashloan guard: msg.sender==pool check -> NOT flagged")
check(not flagged(recon.det_flashloan, "contract C{function onFlashLoan(address initiator,address t,uint a,uint fee,bytes d) external returns(bytes32){ require(initiator == address(this)); return keccak256('ok'); }}"),
      "det_flashloan guard: initiator==address(this) check -> NOT flagged")

print("== operator-power / RUG class (owner-drain / fee-backdoor / honeypot levers) ==")
check(flagged(recon.det_owner_drain, "contract C{function emergencyWithdraw() external onlyOwner { payable(owner()).transfer(address(this).balance); }}"),
      "det_owner_drain: owner-gated emergencyWithdraw of contract balance flagged")
check(flagged(recon.det_owner_drain, "contract C{function sweep(address t) external onlyOwner { IERC20(t).transfer(owner(), 1); }}"),
      "det_owner_drain: owner-gated sweep(token) flagged")
check(not flagged(recon.det_owner_drain, "contract C{function rescue(address t) external { IERC20(t).transfer(msg.sender, 1); }}"),
      "det_owner_drain guard: an UNGATED drain (no owner gate) NOT flagged here (det_access's job)")
check(not flagged(recon.det_owner_drain, "contract C{function setConfig(uint x) external onlyOwner { cfg = x; }}"),
      "det_owner_drain guard: a non-drain owner fn NOT flagged")
check(flagged(recon.det_owner_drain, "contract C{function withdrawEth() external { if (msg.sender == owner) { payable(owner).transfer(address(this).balance); } }}"),
      "det_owner_drain: an INLINE if(msg.sender==owner)-gated drain flagged (hidden-owner backdoor, not onlyOwner)")
check(flagged(recon.det_fee_backdoor, "contract C{function setFee(uint256 f) external onlyOwner { fee = f; }}"),
      "det_fee_backdoor: setFee with NO upper bound flagged")
check(not flagged(recon.det_fee_backdoor, "contract C{function setFee(uint256 f) external onlyOwner { require(f <= MAX_FEE); fee = f; }}"),
      "det_fee_backdoor guard: setFee with require(f <= MAX) bound NOT flagged")
check(not flagged(recon.det_fee_backdoor, "contract C{function setOwner(address o) external onlyOwner { owner = o; }}"),
      "det_fee_backdoor guard: a non-fee setter NOT flagged")
check(flagged(recon.det_honeypot_lever, "contract C{function blacklist(address a) external onlyOwner { _bl[a] = true; }}"),
      "det_honeypot_lever: owner-gated blacklist flagged")
check(flagged(recon.det_honeypot_lever, "contract C{function enableTrading() external onlyOwner { tradingEnabled = true; }}"),
      "det_honeypot_lever: owner-gated enableTrading flagged (can disable sells)")

print("== det_reward_formula (Synthetix mis-bracket: reward accumulator inside .mul(balance)) ==")
_rf = recon.det_reward_formula("contract C{function earned(address account) public view returns(uint){"
      " return balanceOf(account).mul(rewardPerToken().sub(p).div(1e18).add(userInfo[account].rewards)); }}", "src/Vault.sol")
check(bool(_rf) and _rf[0][4] == 0,
      "det_reward_formula: .add(rewards) INSIDE .mul(balanceOf) -> [!] (posi-vaults quadratic inflation)")
check(not flagged(recon.det_reward_formula, "contract C{function earned(address account) public view returns(uint){"
      " return balanceOf(account).mul(rewardPerToken().sub(p)).div(1e18).add(rewards[account]); }}"),
      "det_reward_formula guard: correct Synthetix (.add(rewards) OUTSIDE the .mul) NOT flagged")
check(flagged(recon.det_reward_formula, "contract C{function earned(address a) public view returns(uint){"
      " return balanceOf(a) * ((rpt - paid) / 1e18 + rewards[a]); }}"),
      "det_reward_formula: operator form balance*(delta + rewards) flagged (no-SafeMath 0.8 style)")
check(not flagged(recon.det_reward_formula, "contract C{function f(uint a) external { y = amount.mul(price).div(1e18); }}"),
      "det_reward_formula guard: amount.mul(price) with no reward accumulator inside NOT flagged")
check(not flagged(recon.det_reward_formula, "contract C{function f() external { y = shares.mul(rate.add(bonus)); }}"),
      "det_reward_formula guard: .add(bonus) (not a reward accumulator) inside .mul NOT flagged (precision)")
check(not flagged(recon.det_reward_formula, "contract C{function pending(uint pid,address u) external view returns(uint){"
      " return user.amount.mul(pool.accPerShare).div(1e12).sub(user.rewardDebt); }}"),
      "det_reward_formula guard: correct MasterChef pending (rewardDebt OUTSIDE in .sub, not inside .mul) NOT flagged")
check(not flagged(recon.det_reward_formula, "contract C{function f() external { y = balance * (1 + feeRate); }}"),
      "det_reward_formula guard: balance*(1+feeRate) (no reward term) NOT flagged (operator-form precision)")

print("== det_spot_oracle (spot-AMM-as-oracle, #1 DeFiHackLabs class) ==")
_so = recon.det_spot_oracle("contract C{function valuePosition(uint amt) public view returns(uint){"
      " (uint112 r0,uint112 r1,)=pair.getReserves(); uint price=uint(r1)*1e18/uint(r0); uint collateral=amt*price/1e18; return collateral; }}", "src/Lend.sol")
check(bool(_so) and _so[0][4] == 0,
      "det_spot_oracle: getReserves() feeding a collateral computation, no TWAP -> [!] (PancakeBunny/UwuLend class)")
check(flagged(recon.det_spot_oracle, "contract V{function mint(uint a) external { uint pps=vault.getPricePerFullShare(); _mint(msg.sender, a*pps/1e18); }}"),
      "det_spot_oracle: getPricePerFullShare() feeding a _mint -> flagged")
check(not flagged(recon.det_spot_oracle, "contract C{function valuePosition(uint amt) public view returns(uint){"
      " (,int256 p,,uint256 updatedAt,)=oracle.latestRoundData(); require(block.timestamp-updatedAt<3600); return amt*uint(p)/1e8; }}"),
      "det_spot_oracle guard: latestRoundData() + updatedAt staleness check (Chainlink/TWAP-safe) NOT flagged")
check(not flagged(recon.det_spot_oracle, "contract Pair{function sync() external { (uint112 r0,uint112 r1,)=getReserves(); reserve0=r0; reserve1=r1; }}"),
      "det_spot_oracle guard: getReserves() with NO value sink (sync just caches reserves) NOT flagged")

print("== det_self_transfer (LPC/SSS/GPU self-transfer balance inflation) ==")
check(flagged(recon.det_self_transfer, "contract T{function _transfer(address from,address to,uint256 amount) internal {"
      " uint256 fromBal=_balances[from]; uint256 toBal=_balances[to]; _balances[from]=fromBal-amount; _balances[to]=toBal+amount; }}"),
      "det_self_transfer: caches BOTH balances[from] and balances[to], no from==to guard -> flagged (LPC/SSS class)")
check(not flagged(recon.det_self_transfer, "contract T{function _update(address from,address to,uint256 value) internal {"
      " uint256 fromBalance=_balances[from]; _balances[from]=fromBalance-value; _balances[to]+=value; }}"),
      "det_self_transfer guard: OZ-style (caches only `from`, uses += for `to`) NOT flagged")
check(not flagged(recon.det_self_transfer, "contract T{function _transfer(address from,address to,uint256 amt) internal {"
      " require(from!=to,'self'); uint256 a=_balances[from]; uint256 b=_balances[to]; _balances[from]=a-amt; _balances[to]=b+amt; }}"),
      "det_self_transfer guard: explicit from!=to guard NOT flagged")
check(flagged(recon.det_self_transfer, "contract T{function _transfer(address sender,address recipient,uint amount) internal {"
      " (bool vs,uint senderBalance)=_updateBalance(sender); (bool vr,uint recipientBalance)=_updateBalance(recipient);"
      " _balances[sender]=senderBalance.sub(amount); _balances[recipient]=recipientBalance.add(amount); }}"),
      "det_self_transfer: tuple/helper-cached write-back (real LPC on-chain shape) -> flagged")
check(not flagged(recon.det_self_transfer, "contract T{function _transfer(address from,address to,uint v) internal {"
      " balanceOf[from]=balanceOf[from].sub(v); balanceOf[to]=balanceOf[to].add(v); }}"),
      "det_self_transfer guard: in-place SafeMath (UniswapV2ERC20 shape, RHS is the mapping) NOT flagged")

print("== det_pair_reserve_mutation (reflection/deflationary BSC reserve crash) ==")
check(flagged(recon.det_pair_reserve_mutation, "contract Tok{function triggerAutoBurn() external { _burn(uniswapV2Pair, 1e18); IUniswapV2Pair(uniswapV2Pair).sync(); }}"),
      "det_pair_reserve_mutation: unprivileged burn-of-pair + sync() -> flagged (BIGFI/BYToken class)")
check(not flagged(recon.det_pair_reserve_mutation, "contract Tok{function adminRebalance() external onlyOwner { IUniswapV2Pair(pair).sync(); }}"),
      "det_pair_reserve_mutation guard: onlyOwner sync (admin op) NOT flagged")
check(not flagged(recon.det_pair_reserve_mutation, "contract Tok{function transfer(address to,uint a) external { _balances[msg.sender]-=a; _balances[to]+=a; }}"),
      "det_pair_reserve_mutation guard: a normal transfer (no pair sync/skim/burn) NOT flagged")

print("== det_unprotected_init (front-runnable ownership/role grab, class E) ==")
check(flagged(recon.det_unprotected_init, "contract C{function initialize(address _owner) external { owner = _owner; }}"),
      "det_unprotected_init: external initialize sets owner, no guard -> flagged (DaoMaker class)")
check(flagged(recon.det_unprotected_init, "contract C{function initialize() public { __Ownable_init(); }}"),
      "det_unprotected_init: public initialize calls __Ownable_init, no initializer modifier -> flagged")
check(not flagged(recon.det_unprotected_init, "contract C{function initialize(address o) external initializer { owner = o; }}"),
      "det_unprotected_init guard: OZ `initializer` modifier NOT flagged")
check(not flagged(recon.det_unprotected_init, "contract C{function initialize() external onlyOwner { admin = msg.sender; }}"),
      "det_unprotected_init guard: onlyOwner-gated init NOT flagged")
check(not flagged(recon.det_unprotected_init, "contract C{function initialize(address o) external { require(!initialized,'done'); initialized=true; owner=o; }}"),
      "det_unprotected_init guard: manual `initialized` one-shot flag NOT flagged")
check(not flagged(recon.det_unprotected_init, "contract C{function initialize(uint x) external { cap = x; }}"),
      "det_unprotected_init guard: init that grants no ownership/role NOT flagged")

print("== det_caller_supplied_authority (transferFrom source from calldata struct, class E #1 2026) ==")
check(flagged(recon.det_caller_supplied_authority, "contract C{function fill(Order calldata o,uint amt) external { token.transferFrom(o.maker, msg.sender, amt); }}"),
      "det_caller_supplied_authority: transferFrom(o.maker,...) unbound -> flagged (TrustedVolumes class)")
check(not flagged(recon.det_caller_supplied_authority, "contract C{function fill(Order calldata o,bytes sig) external { require(isValidSignature(o,sig)); token.transferFrom(o.maker, msg.sender, amt); }}"),
      "det_caller_supplied_authority guard: signature-verified order source NOT flagged")
check(not flagged(recon.det_caller_supplied_authority, "contract C{function fill(Order calldata o) external { require(o.maker==msg.sender); token.transferFrom(o.maker, address(this), amt); }}"),
      "det_caller_supplied_authority guard: source bound to msg.sender NOT flagged")
check(not flagged(recon.det_caller_supplied_authority, "contract C{function pull(address from,uint amt) external { token.transferFrom(from, address(this), amt); }}"),
      "det_caller_supplied_authority guard: bare-param `from` (allowance-gated router) NOT flagged")
check(not flagged(recon.det_caller_supplied_authority, "library L{function executeSupply(ExecuteSupplyParams memory params) external { IERC20(params.asset).safeTransferFrom(params.user, aToken, params.amount); }}"),
      "det_caller_supplied_authority guard: Aave-fork `memory` struct (.user bound upstream) NOT flagged")


print("== calibrate (feedback loop: finding-outcome precision + verdict recall) ==")
import calibrate  # noqa: E402
_F = [{"status": "accepted"}, {"status": "fixed-silent"}, {"status": "duplicate"},
      {"status": "disputed"}, {"status": "drafted"}, {"status": "disclosed"}]
_acc, _dec, _pend = calibrate.precision_stats(_F)
check(len(_acc) == 3 and len(_dec) == 4 and len(_pend) == 2,
      "calibrate.precision_stats: accepted/fixed-silent/duplicate count as accepted; disputed is decided; drafted/disclosed pending")
_C = [{"result": "TP"}, {"result": "TP"}, {"result": "FN"}, {"result": "TN"}]
_tp, _fn = calibrate.recall_stats(_C)
check(len(_tp) == 2 and len(_fn) == 1,
      "calibrate.recall_stats: TP/FN partition for recall (TN excluded)")
check("duplicate" in calibrate.ACCEPTED_LIKE and "disputed" in calibrate.REJECTED_LIKE,
      "calibrate: a duplicate is a real finding (accepted-like); a disputed one is rejected-like")
check(calibrate.SEV_RANK["high"] > calibrate.SEV_RANK["medium"] > calibrate.SEV_RANK["low"],
      "calibrate.SEV_RANK: severity ordering (for awarded-vs-claimed drift)")

print("== fanout_log (persist fan-out triage: typed table + ledger-suppress) ==")
import fanout_log  # noqa: E402
check(fanout_log.REC_TO_VERDICT["DIG"] == "todo" and fanout_log.REC_TO_VERDICT["DIG-CAREFUL"] == "todo"
      and fanout_log.REC_TO_VERDICT["SKIP"] == "known" and fanout_log.REC_TO_VERDICT["PARK"] == "wontfix"
      and fanout_log.REC_TO_VERDICT["UNREACHABLE"] == "known",
      "fanout_log.REC_TO_VERDICT: DIG/DIG-CAREFUL->todo (deep-dive queue); SKIP/UNREACHABLE->known + PARK->wontfix (suppress)")
_fv = fanout_log.parse_verdicts({"result": [{"name": "a", "recommendation": "DIG"}, {"bad": 1}, {"name": "b", "recommendation": "SKIP"}]})
check(len(_fv) == 2 and _fv[0]["name"] == "a",
      "fanout_log.parse_verdicts: unwraps {result:[...]}, drops entries with no name")
check(fanout_log.parse_verdicts([{"name": "x", "recommendation": "PARK"}])[0]["name"] == "x",
      "fanout_log.parse_verdicts: accepts a bare list too")
check(fanout_log.leads_str({"top_leads": [{"title": "reentrancy in claim"}, {"title": "oracle stale"}]}).count(";") == 1
      and fanout_log.leads_str({"top_leads": []}) == "-",
      "fanout_log.leads_str: joins lead titles (pipe-safe), '-' when none")
check(not flagged(recon.det_honeypot_lever, "contract C{function setBlacklist(address a) external { _bl[a] = true; }}"),
      "det_honeypot_lever guard: ungated lever (no owner gate) NOT flagged")
check(not flagged(recon.det_honeypot_lever, "contract C{function setFee(uint x) external onlyOwner { fee = x; }}"),
      "det_honeypot_lever guard: a non-lever owner fn NOT flagged")

print("== det_key (new detectors get distinct ledger groups, never 'other') ==")
_keys = [recon.det_key(t) for t, _, _ in recon.DETECTORS]
check("other" not in _keys, "every detector title maps to a real det_key (none fall through to 'other')")
check(len(set(_keys)) == len(_keys), "each detector has a UNIQUE det_key (no silent ledger-group collisions)")

print("== recon.detect_all (one crashing detector can't abort the whole scan) ==")
_orig_dets = recon.DETECTORS
try:
    import io as _io
    import contextlib as _cl

    def _boom(_t, _r):
        raise ValueError("boom")
    recon.DETECTORS = [("CRASHER", _boom, "x")] + list(_orig_dets)
    _errbuf = _io.StringIO()
    with _cl.redirect_stderr(_errbuf):
        _da = recon.detect_all("contract C{function setFee(uint x) external { fee=x; }}", "src/C.sol")
    check(_da.get("CRASHER") == [] and "CRASHER" in _errbuf.getvalue()
          and any("setFee" in (l[2] or "") for v in _da.values() for l in v),
          "recon.detect_all: a crashing detector is isolated ([] + stderr WARN); real detectors still fire")
finally:
    recon.DETECTORS = _orig_dets

print("== forkdrift (fork-of-audited-base detection + substantive drift diff) ==")
import forkdrift  # noqa: E402
# detect_base: the Lagoon/Hopper storage-namespace fingerprint (RockSolid was a verbatim Lagoon fork)
_lag = forkdrift.detect_base("bytes32 c = 0x..; /// @custom:storage-location erc7201:hopper.storage.vault")
check(bool(_lag) and "Lagoon" in _lag[0][1], "forkdrift.detect_base flags the hopper.storage namespace as Lagoon")
check(forkdrift.detect_base("contract MyToken is ERC20 { uint x; }") == [],
      "forkdrift.detect_base: original code (no base sig) -> no false fork match")
check(forkdrift.detect_base("/// @custom:storage-location erc7201:M0.storage.MYieldToOne\ncontract X{}")[0][1].startswith("M^0"),
      "forkdrift.detect_base: M^0 MExtension framework (erc7201:M0.storage namespace) matches (Nerona/USDnr)")
check(forkdrift.detect_base("library SupplyLogic{function executeSupply()internal{} } contract P{function borrowLogic()external{}}")[0][1].startswith("Aave"),
      "forkdrift.detect_base: Aave v3 IMPL-INTERNAL fingerprint (SupplyLogic+executeSupply+borrowLogic) matches")
# anti-FP (the Ledgity case): a protocol that INTEGRATES Aave (calls IPool.getReserveData / reads
# liquidityIndex via the interface) but has NONE of Aave's impl internals -> NOT flagged as a fork.
check(forkdrift.detect_base(
        "import {IPool} from '@aave/core-v3/contracts/interfaces/IPool.sol';"
        "contract Strat{ function f()external{ pool.getReserveData(a); uint i=r.liquidityIndex; r.reserveConfiguration; } }"
      ) == [],
      "forkdrift.detect_base: an Aave INTEGRATOR (interface calls only, no impl internals) is NOT a false fork (Ledgity FP fix)")
# detect_version: version() return is the strongest signal; src/vX path is the fallback
check(forkdrift.detect_version('function version() public pure returns(string memory){return "v0.5.0";}') == ("0.5.0", "version() returns"),
      "forkdrift.detect_version reads the version() return string (RockSolid -> v0.5.0)")
check(forkdrift.detect_version("// New variables introduce with v0.5.1")[0] == "0.5.1",
      "forkdrift.detect_version falls back to an 'introduced with vX' comment")
check(forkdrift.detect_version("contract C{}")[0] is None,
      "forkdrift.detect_version: no version evidence -> None (no fabrication)")
check(forkdrift._ver_tuple("0.5.1") > forkdrift._ver_tuple("0.5.0") and forkdrift._ver_tuple("0.6.0") > forkdrift._ver_tuple("0.5.1"),
      "forkdrift._ver_tuple orders semver so 'next version' selection is correct")
# norm_line / substantive_diff: CRLF + whitespace + the spurious quoted-pragma reflow are NOT drift...
check(forkdrift.norm_line('pragma   solidity\t"0.8.26";\r') == 'pragma solidity "0.8.26";',
      "forkdrift.norm_line collapses CRLF + internal whitespace (Etherscan/Sourcify noise)")
check(forkdrift.substantive_diff("function f(uint a, uint b) external {\r\n  x=1;\r\n}",
                                  "function f(\n    uint a,\n    uint b\n) external {\n    x = 1;\n}") == [],
      "forkdrift.substantive_diff: pure reflow/CRLF (no logic change) -> EMPTY (cosmetic, not flagged)")
_real = forkdrift.substantive_diff("if (!isWhitelisted(owner)) revert NotWhitelisted();",
                                   "_doubleWhitelistedCheck(owner, controller);")
check(bool(_real) and any("doubleWhitelistedCheck" in l for l in _real),
      "forkdrift.substantive_diff: a real logic change (the v0.5.1 whitelist patch) IS surfaced")
# pick_canonical: choose the smallest version >= the fork's version (the patch it SHOULD have taken)
_canon = ["src/v0.5.1/Vault.sol", "src/v0.6.0/Vault.sol", "src/protocol-v1/FeeRegistry.sol"]
check(forkdrift.pick_canonical("Vault.sol", "0.5.0", _canon) == "src/v0.5.1/Vault.sol",
      "forkdrift.pick_canonical: fork v0.5.0 -> pairs with the NEXT canonical (v0.5.1), not v0.6.0")
check(forkdrift.pick_canonical("FeeRegistry.sol", "0.5.0", _canon) == "src/protocol-v1/FeeRegistry.sol",
      "forkdrift.pick_canonical: unversioned-dir file still pairs by basename")
check(forkdrift.pick_canonical("Nonexistent.sol", "0.5.0", _canon) is None,
      "forkdrift.pick_canonical: a fork-only file has no canonical counterpart (-> NEW)")
# audit-awareness: a repo audit/ dir is GROUND TRUTH (Royco Dawn showed DefiLlama audits=0 yet ships 5 reports)
_aud = forkdrift.detect_audit_evidence(
    ["audit/Certora-Royco-Dawn-1.pdf", "audit/Hexens-Royco-Dawn-2.pdf", "src/RoycoKernel.sol"], "")
check(_aud["audited"] and _aud["formal"] and "Certora" in _aud["firms"] and "Hexens" in _aud["firms"] and len(_aud["reports"]) == 2,
      "forkdrift.detect_audit_evidence: audit/ PDFs -> audited=True, firms=[Certora,Hexens], formal=True (Royco Dawn)")
check(forkdrift.detect_audit_evidence(["src/Vault.sol", "README.md"], "This vault was audited by Trail of Bits.")["audited"]
      and not forkdrift.detect_audit_evidence(["src/Vault.sol"], "Audited by Trail of Bits.")["formal"],
      "forkdrift.detect_audit_evidence: a README 'audited by <firm>' claim counts; a non-Certora firm is not 'formal'")
check(not forkdrift.detect_audit_evidence(["src/Vault.sol", "README.md"], "We plan to get an audit soon. Audit pending.")["audited"],
      "forkdrift.detect_audit_evidence: 'plan to get an audit' (no firm, no report file) is NOT audited (no false-audited)")
# Ledgity FALSE-AUDITED guards (its only 'report' was a slither dump; 'consensys' was a Linea logo badge;
# 'Security audit reports' was a folder label) -> must resolve to NOT audited (it's our real Medium target).
check(not forkdrift.detect_audit_evidence(["audit/slither-report.md", "src/WrappedLToken.sol"], "")["audited"],
      "forkdrift: a slither-report.md (automated TOOL output) is NOT a professional audit (Ledgity guard)")
check(not forkdrift.detect_audit_evidence([".claude/rules/hh-audit-context.md", "src/game/modes/TournamentGame.sol"], "")["audited"]
      and not forkdrift.detect_audit_evidence([".cursor/audit-notes.md", "src/X.sol"], "")["audited"],
      "forkdrift: a `.claude/` AI-assistant audit-context note is NOT a professional audit (heavy-helms guard)")
check(forkdrift.detect_audit_evidence(["audits/2026-Spearbit-audit.pdf", ".claude/rules/audit-context.md"], "")["audited"],
      "forkdrift guard: a REAL firm report still counts even when a .claude/ context file sits beside it")
check(not forkdrift.detect_audit_evidence(["src/X.sol"], '<img src="https://img.shields.io/badge/Linea?logo=consensys" />')["audited"],
      "forkdrift: a `logo=consensys` shield BADGE is not an audit-firm claim (README-noise stripped; Ledgity guard)")
check(not forkdrift.detect_audit_evidence(["src/X.sol"], "Repo layout:\n  audit/   Security audit reports")["audited"],
      "forkdrift: 'Security audit reports' as a FOLDER LABEL is not an audit claim (strong-claim regex; Ledgity guard)")
check(forkdrift.detect_audit_evidence(["audit/Certora-Dawn.pdf"], "")["audited"]
      and forkdrift.detect_audit_evidence(["src/X.sol"], "The protocol has been audited by Hexens.")["audited"],
      "forkdrift: a REAL report file (Certora-Dawn.pdf) or a strong README claim ('has been audited by Hexens') still counts")
check(forkdrift.likely_out_of_scope(
        ["src/integrations/Maple.sol", "src/core/Vault.sol", "src/periphery/Zap.sol",
         "src/interfaces/external/IMaple.sol", "test/Foo.t.sol", "script/Deploy.s.sol"])
      == ["src/integrations/Maple.sol", "src/periphery/Zap.sol"],
      "forkdrift.likely_out_of_scope: integrations/periphery IMPLs flagged; interfaces/tests/scripts/core excluded")
# _repo_root_of MUST NOT ascend into a parent monorepo (the over-scan bug: fingerprinting a fetched target in
# hunts/_volume/ walked up to security-lab's .git and scanned 88 audit PDFs from OTHER clones).
check(os.path.basename(forkdrift._repo_root_of("hunts/_volume/royco-v2/src")) == "royco-v2",
      "forkdrift._repo_root_of: a `.../<target>/src` resolves to <target> (parent, to find its audit/ dir)")
check(os.path.basename(forkdrift._repo_root_of("hunts/_volume/venus-flux")) == "venus-flux",
      "forkdrift._repo_root_of: a target dir resolves to ITSELF -- never ascends to _volume (88-PDF over-scan regression)")
check(os.path.basename(forkdrift._repo_root_of("x/hunts/_volume/foo/contracts")) == "foo",
      "forkdrift._repo_root_of: a `.../<target>/contracts` source subdir resolves to <target>")

print("== forkdrift.parse_github_org (sibling-audits routing; Mezo MUSD lesson) ==")
check(forkdrift.parse_github_org('[remote "origin"]\n\turl = https://github.com/mezo-org/musd.git\n') == "mezo-org",
      "parse_github_org: https remote -> org 'mezo-org' (points the audit hunt at github.com/mezo-org/audits)")
check(forkdrift.parse_github_org("\turl = git@github.com:mezo-org/musd.git\n") == "mezo-org",
      "parse_github_org: ssh remote (git@github.com:org/repo) -> 'mezo-org'")
check(forkdrift.parse_github_org("no remote here") is None and forkdrift.parse_github_org("") is None,
      "parse_github_org: no github remote -> None (graceful, generic <org>/audits hint)")

print("== scaffold (multi-engine harness: foundry / chimera / halmos) ==")
import scaffold  # noqa: E402
_SC = ("contract Vault {"
       " function deposit(uint256 amt, address to) external { bal[to]+=amt; }"
       " function flag(bool b, uint8 n) external { f=b; m=n; }"
       " function pay() external payable { got+=msg.value; }"
       " function peek() external view returns (uint256) { return bal[msg.sender]; } }")
_cn, _body = scaffold.find_contract_body(_SC, "Vault")
_fns = list(scaffold.parse_functions(_body))
check(_cn == "Vault" and [n for n, _, _ in _fns] == ["deposit", "flag", "pay"],
      "scaffold.parse_functions: external/public state-changing fns only (view peek() skipped)")

# foundry engine: single-file, backward-compatible shape
_fd = scaffold.emit_foundry("Vault", "Vault.sol", _fns)
check(list(_fd) == ["VaultInvariants.t.sol"], "scaffold foundry: one .t.sol named <Contract>Invariants")
_ftxt = _fd["VaultInvariants.t.sol"]
check("VaultHandler" in _ftxt and "targetSelector" in _ftxt and "h_deposit" in _ftxt and "invariant_solvency" in _ftxt,
      "scaffold foundry: Handler + targetSelector wiring + h_* handlers + universal invariant stubs")

# chimera engine: ONE harness, three engines (Recon-Fuzz pattern)
_c = scaffold.emit_chimera("Vault", "Vault.sol", _fns)
check(set(_c) == {"Setup.sol", "Properties.sol", "TargetFunctions.sol", "CryticTester.sol",
                  "CryticToFoundry.sol", "echidna.yaml", "medusa.json"},
      "scaffold chimera: emits the 5 .sol parts + echidna.yaml + medusa.json")
_tf = _c["TargetFunctions.sol"]
check("vm." not in _tf and "bound(" not in _tf,
      "scaffold chimera PORTABILITY: handlers use NO forge-std vm/bound (compile under Echidna/Medusa too)")
check("a1 = a1 % 1e30;" in _tf,
      "scaffold chimera: a full-width uint256 arg is clamped with % 1e30")
check("n = n % 1e30" not in _tf,
      "scaffold chimera COMPILE-SAFETY: a uint8 arg is NOT clamped by % 1e30 (the literal would not fit the type)")
check("function h_pay() public payable {" in _tf and "target.pay{value: msg.value}()" in _tf,
      "scaffold chimera: a payable fn -> payable handler forwarding msg.value")
check("_actors[_actorSeed % _actors.length]" in _tf,
      "scaffold chimera: an address param resolves to a configured fuzzer actor")
check("function property_solvency() public view returns (bool)" in _c["Properties.sol"],
      "scaffold chimera: universal invariants emitted as bool-returning property_* (Echidna/Medusa mode)")
check("setup();" in _c["CryticTester.sol"],
      "scaffold chimera: CryticTester ctor calls setup() (Echidna/Medusa entrypoint)")
check("assertTrue(property_solvency())" in _c["CryticToFoundry.sol"] and "invariant_solvency()" in _c["CryticToFoundry.sol"],
      "scaffold chimera: CryticToFoundry wraps each property_* in a Foundry invariant_*")
check(all(a in _c["echidna.yaml"] for a in scaffold.ACTORS),
      "scaffold chimera: echidna.yaml sender list = the shared ACTORS (msg.sender is always an actor)")
check('prefix: "property_"' in _c["echidna.yaml"],
      "scaffold chimera: echidna.yaml sets prefix=property_ (else echidna ignores our property_* and tests nothing -- dogfood fix)")
check('"propertyTesting"' in _c["medusa.json"] and scaffold.ACTORS[0] in _c["medusa.json"],
      "scaffold chimera: medusa.json enables propertyTesting + lists the sender addresses")

# halmos engine: symbolic check_* suite
_h = scaffold.emit_halmos("Vault", "Vault.sol", _fns)
check(list(_h) == ["VaultSymbolic.t.sol"], "scaffold halmos: one <Contract>Symbolic.t.sol")
_htxt = _h["VaultSymbolic.t.sol"]
check("function check_deposit(uint256 a1, address a2) public" in _htxt,
      "scaffold halmos: a check_<fn> per fn with symbolic typed args (uint256 + address)")
check("--function check_" in _htxt and "function check_pay() public" in _htxt,
      "scaffold halmos: run hint emitted + a no-arg check_ for the payable fn")

# build('all') merges chimera + halmos; _clampable guards literal-type errors
_all = scaffold.build("all", "Vault", "Vault.sol", _fns)
check(len(_all) == 8 and "VaultSymbolic.t.sol" in _all and "CryticTester.sol" in _all,
      "scaffold build('all'): chimera (7) + halmos (1) = 8 files")
check(scaffold._clampable("uint256") and scaffold._clampable("int") and not scaffold._clampable("uint8")
      and not scaffold._clampable("bytes32"),
      "scaffold._clampable: only full-width int clamps with % 1e30 (uint8/bytes32 left raw -> no compile error)")

print("== deepdive (per-target bespoke-tooling workspace) ==")
import deepdive  # noqa: E402
check(deepdive.lead_form("LIQUIDATION math (self-liq, rounding, bad-debt)") == "differential"
      and deepdive.lead_form("ORACLE usage vs 3-guard checklist") == "differential"
      and deepdive.lead_form("INTEREST-INDEX inflation (Aave-fork)") == "differential",
      "deepdive.lead_form: numeric-formula detectors route to the DIFFERENTIAL model")
check(deepdive.lead_form("ACCESS CONTROL leads (privileged fn)") == "invariant"
      and deepdive.lead_form("SIGNATURE / ecrecover (replay)") == "invariant"
      and deepdive.lead_form("SUPPLY INTEGRITY (mint/burn entry points)") == "invariant",
      "deepdive.lead_form: auth/replay/state detectors route to the BESPOKE INVARIANT")
_dl = [("A.sol", 10, "LIQUIDATION math", "n", 0, "differential"),
       ("A.sol", 20, "ACCESS CONTROL leads", "n", 0, "invariant"),
       ("B.sol", 5, "ORACLE usage", "n", 0, "differential"),
       ("C.sol", 7, "SUPPLY INTEGRITY", "n", 1, "invariant")]  # prio 1 -> excluded from top_files
_tf = deepdive.top_files(_dl)
check(_tf[0] == ("A.sol", 2) and all(f != "C.sol" for f, _ in _tf) and any(f == "B.sol" for f, _ in _tf),
      "deepdive.top_files: ranks files by [!] (prio-0) lead count; [.] leads don't count")
_notes = deepdive.gen_notes("foo", "src/foo", _dl)
check("## Tier-1 files" in _notes and "DIFFERENTIAL MODEL" in _notes and "BESPOKE INVARIANT" in _notes
      and "conservation:" in _notes and "## Worklog" in _notes,
      "deepdive.gen_notes: Tier-1 + both routes + bespoke-invariant menu + worklog")
check("LIQUIDATION math" in _notes.split("DIFFERENTIAL MODEL")[1].split("BESPOKE INVARIANT")[0]
      and "ACCESS CONTROL leads" in _notes.split("BESPOKE INVARIANT")[1],
      "deepdive.gen_notes: a math lead lands under Route A, an auth lead under Route B")
check("def reference" in deepdive.gen_model_py("Foo") and "Ledgity" in deepdive.gen_model_py("Foo"),
      "deepdive.gen_model_py: Python differential skeleton (reference() + the Ledgity method)")
_sol = deepdive.gen_differential_sol("Foo")
check("library FooReference" in _sol and "contract FooDifferential" in _sol and "testFuzz_diff" in _sol and "assertEq" in _sol,
      "deepdive.gen_differential_sol: Foundry differential skeleton (reference lib + fuzz-diff)")
# end-to-end on a temp dir: recon integration + test-skip + routing
_dd = os.path.join(tempfile.gettempdir(), "dd-fixture")
import shutil as _sh
_sh.rmtree(_dd, ignore_errors=True)
os.makedirs(os.path.join(_dd, "test"), exist_ok=True)
open(os.path.join(_dd, "Vault.sol"), "w").write(
    "contract V{function setFee(uint x) external { fee=x; } function liquidate(address u) external { seizeCollateral(u); }}")
open(os.path.join(_dd, "test", "VaultTest.sol"), "w").write("contract T{function setFee(uint x) external { fee=x; }}")
_leads = deepdive.collect_leads(_dd)
_rels = {l[0] for l in _leads}
check("Vault.sol" in _rels and all("test" not in r for r in _rels),
      "deepdive.collect_leads: runs recon on the target, SKIPS the test/ dir")
check(any(l[2].startswith("LIQUIDATION") and l[5] == "differential" for l in _leads)
      and any("ACCESS" in l[2] and l[5] == "invariant" for l in _leads),
      "deepdive.collect_leads: routes a real liquidate() to differential + an ungated setter to invariant")
_sh.rmtree(_dd, ignore_errors=True)

print("== activity (LIVE-FIRST Phase-0/1 gate: classify verdicts) ==")
import activity  # noqa: E402
check(activity.classify(0, 5, 100)[0] == "NO-CODE" and activity.classify(0, 5, 100)[1] == "SKIP",
      "activity.classify: a real '0x' (0-len bytecode = EOA) -> NO-CODE / SKIP")
check(activity.classify(-1, 5, 100)[0] == "UNKNOWN",
      "activity.classify: eth_getCode null (code_len<0) -> UNKNOWN, NOT a false NO-CODE (the QA-pass fix)")
check(activity.classify(2000, -1, 0)[0] == "UNKNOWN",
      "activity.classify: events query failed (-1) -> UNKNOWN (do NOT call a query-fail 'dormant')")
check(activity.classify(2000, 7, 0)[0] == "ACTIVE" and activity.classify(2000, 7, 0)[1] == "DIG",
      "activity.classify: recent events -> ACTIVE / DIG")
check(activity.classify(2000, 0, 10**18)[0] == "QUIET-VALUE"
      and activity.classify(2000, 0, 0, token_bal=5)[0] == "QUIET-VALUE",
      "activity.classify: no events but holds ETH or token value -> QUIET-VALUE / DIG-CAREFUL")
check(activity.classify(2000, 0, 0)[0] == "DORMANT" and activity.classify(2000, 0, 0)[1] == "PARK/SKIP",
      "activity.classify: deployed, no events, 0 value -> DORMANT / PARK-SKIP (the heavy-helms case)")
check(activity.classify(2000, 0, 0, supply=0)[0] == "EMPTY" and "not live" in activity.classify(2000, 0, 0, supply=0)[1],
      "activity.classify: deployed but totalSupply==0 -> EMPTY / not live (the ledgity WrappedLTokenSonic deployment-gate)")
check(activity.classify(2000, 5, 10**18, supply=0)[0] == "EMPTY",
      "activity.classify: totalSupply==0 -> EMPTY even with events + value (no shares/positions exist to act on)")
check(activity.classify(2000, 7, 0, supply=1000)[0] == "ACTIVE" and activity.classify(2000, 0, 0, supply=None)[0] == "DORMANT",
      "activity.classify: supply>0 doesn't block ACTIVE; supply=None keeps prior behavior (back-compat)")
check(activity.classify(2000, 0, 0, supply=988027)[0] == "QUIET-VALUE",
      "activity.classify: totalSupply>0 + no events/0 held value -> QUIET-VALUE, NOT DORMANT (the lazy funds-forwarded-vault FN fix)")
check(activity.resolve_chain("mantle") == "5000" and activity.resolve_chain("sonic") == "146"
      and activity.resolve_chain("mezo") == "31612" and activity.resolve_chain("hyperevm") == "999",
      "activity.resolve_chain: exotic chains (mantle/sonic/mezo/hyperevm) now alias to ids (the fan-out RPC FN fix)")
check(activity.resolve_chain("abstract") == "2741" and activity.resolve_chain("abs") == "2741",
      "activity.resolve_chain: Abstract (zkSync) aliases to 2741")
check(activity.classify(2000, 0, 0, txcount=20)[0] == "ACTIVE" and "txlist" in activity.classify(2000, 0, 0, txcount=20)[2],
      "activity.classify: recent txns (txlist) -> ACTIVE even with 0 getLogs events (the death.fun false-DORMANT fix)")
check(activity.classify(2000, 0, 0, txcount=0)[0] == "DORMANT" and activity.classify(2000, 0, 0, txcount=None)[0] == "DORMANT",
      "activity.classify: txcount 0/None does NOT override -> DORMANT preserved (no key / genuinely idle)")
check(activity.classify(2000, 0, 0, supply=0, txcount=20)[0] == "EMPTY",
      "activity.classify: EMPTY (totalSupply==0) still beats txns -> an empty share contract is not live even if admin transacts")
check(activity.resolve_chain("base") == "8453" and activity.resolve_chain("8453") == "8453"
      and activity.resolve_chain("eth") == "1",
      "activity.resolve_chain: chain names + ids both resolve to the id string")
check(activity._selector("0xdeadbeef") == "0xdeadbeef"
      and activity._selector("nextGauntletId()").startswith("0x") and len(activity._selector("nextGauntletId()")) == 10,
      "activity._selector: passes a 0x selector through; hashes a 'sig()' to a 4-byte selector")
check(bool(activity.token_hint(100, 90)) and not activity.token_hint(100, 50) and not activity.token_hint(0, 0),
      "activity.token_hint: >=80% Transfer events -> flags a gov TOKEN (the DefiLlama/XVS trap); mixed activity -> not")
check(activity.parse_logs(None) == (-1, 0),
      "activity.parse_logs: a null getLogs result (RPC range-refused) -> (-1,0) UNKNOWN, NOT 0 (false-DORMANT bug)")
check(activity.parse_logs([]) == (0, 0)
      and activity.parse_logs([{"topics": [activity.ERC20_TRANSFER]}, {"topics": ["0xabc"]}, {}]) == (3, 1),
      "activity.parse_logs: real [] -> 0 genuine events; counts Transfer-topic logs for the token heuristic")

print("== shadow (recon recall benchmark: name->class mapping + HIT/MISS/UNCOVERED/UNMAPPED) ==")
import shadow  # noqa: E402
check(shadow.normalize_name("src/test/Unsafe-downcast.sol") == "unsafe-downcast"
      and shadow.normalize_name("Divmultiply.sol") == "divmultiply",
      "shadow.normalize_name: a test path -> lowercase slug (drop dir/ext, separators -> '-')")
check(shadow.expected_keys("unsafe-downcast")[1] == {"downcast"}
      and shadow.expected_keys("readonlyreentrancy") == ("readonlyreentrancy", None)
      and shadow.expected_keys("totally-novel-thing") == (None, None),
      "shadow.expected_keys: covered class -> det_keys; uncovered -> (kw,None); no match -> (None,None)")
check(shadow.classify(("downcast", {"downcast"}), {"downcast", "access"}) == "HIT"
      and shadow.classify(("downcast", {"downcast"}), {"access"}) == "MISS"
      and shadow.classify(("readonly", None), set()) == "UNCOVERED"
      and shadow.classify((None, None), set()) == "UNMAPPED",
      "shadow.classify: HIT (expected fired) / MISS (expected exists, didn't fire) / UNCOVERED / UNMAPPED")
# DeFiHackLabs real-victim corpus (#6): classify_dhl + manifest sanity
check(shadow.classify_dhl({"selftransfer"}, {"selftransfer", "access"}, True) == "HIT"
      and shadow.classify_dhl({"uinit"}, {"access"}, True) == "MISS"
      and shadow.classify_dhl(None, set(), True) == "UNCOVERED"
      and shadow.classify_dhl({"uinit"}, set(), False) == "UNREACHABLE",
      "shadow.classify_dhl: HIT / MISS (regex-gap) / UNCOVERED (reasoning-tier) / UNREACHABLE (unverified)")
_dhlkeys = {k for e in shadow.DEFIHACKLABS_SAMPLE if e["keys"] for k in e["keys"]}
_allkeys = {recon.det_key(t) for t, _f, _d in recon.DETECTORS}
check(_dhlkeys <= _allkeys and all(e.get("addr", "").startswith("0x") for e in shadow.DEFIHACKLABS_SAMPLE),
      "shadow.DEFIHACKLABS_SAMPLE: every expected key is a real recon det_key + every entry has an address")

print("== analyze L2 bridge (Windows->WSL Slither path translation) ==")
import analyze  # noqa: E402
check(analyze._drive_to_mnt("C:\\Users\\pesto\\repo\\src") == "/mnt/c/Users/pesto/repo/src"
      and analyze._drive_to_mnt("D:\\x\\y") == "/mnt/d/x/y",
      "analyze._drive_to_mnt: absolute Windows path -> /mnt/<lowerdrive>/.. (forward slashes) for the WSL bridge")
check(analyze._drive_to_mnt("/home/x/y") == "/home/x/y",
      "analyze._drive_to_mnt: a posix path passes through (Linux/CI local-slither case)")

print(f"\n{_p} passed, {_f} failed")
sys.exit(1 if _f else 0)
