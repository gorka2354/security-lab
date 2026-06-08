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
check(not flagged(recon.det_access,
      "contract C{function updateRewards(P p) external { uint a; uint b; uint c; _verifySignatures(m,h,p.s); root=p.r; }}"),
      "fix#11: deep _verifySignatures gate NOT flagged")
check(not flagged(recon.det_access, "contract C{function setX(uint x) external { require(msg.sender==owner); x_=x; }}"),
      "msg.sender comparison guard NOT flagged")
check(flagged(recon.det_access, "contract C{function setFee(uint x) external { emit Set(msg.sender,x); fee=x; }}", "setFee"),
      "fix: trailing emit(msg.sender) does NOT mask a real ungated setter")
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

print("== det_unchecked (silent transfer, super. fix) ==")
check(flagged(recon.det_unchecked, "x.transferFrom(a, b, c);"), "bare transferFrom flagged")
check(not flagged(recon.det_unchecked, "x.safeTransfer(to, amt);"), "safeTransfer NOT flagged")
check(not flagged(recon.det_unchecked, "super.transfer(to, amt);"), "fix#9: super.transfer NOT flagged")
check(not flagged(recon.det_unchecked, "payable(to).transfer(amt);"), "ETH payable.transfer NOT flagged")
check(not flagged(recon.det_unchecked, "bool ok = token.transfer(to, amt);"), "captured-return transfer NOT flagged")

print("== det_signature / det_upgrade / det_oracle ==")
check(flagged(recon.det_signature, "contract C{ function f() external { a = ecrecover(h,v,r,s); } }"),
      "raw ecrecover (no guards) flagged")
check(flagged(recon.det_upgrade, "contract C{function _authorizeUpgrade(address) internal override {}}"),
      "empty _authorizeUpgrade flagged")
check(not flagged(recon.det_upgrade, "contract C{function _authorizeUpgrade(address) internal override onlyOwner {}}"),
      "onlyOwner _authorizeUpgrade NOT flagged")
check(not flagged(recon.det_upgrade, "contract C{function _authorizeUpgrade(address) internal view override checkAccess(bytes4(0)) {}}"),
      "fix#17: checkAccess(bytes4(0)) _authorizeUpgrade NOT flagged (Cap selector-gating)")
check(flagged(recon.det_oracle, "contract C{ function p() external { (,int a,,,)=feed.latestRoundData(); } }"),
      "latestRoundData with missing guards flagged")

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

print(f"\n{_p} passed, {_f} failed")
sys.exit(1 if _f else 0)
