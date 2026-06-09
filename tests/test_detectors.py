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
_mw = recon.det_mint("contract C{function mintRogues(uint n) external { for(uint i;i<n;i++){ mintRogue(); } }"
                     " function mintRogue() public { require(openForMint||auth[msg.sender]); _mint(msg.sender,1); }}", "src/Fix.sol")
_mr = [l for l in _mw if "mintRogues" in l[2]][0]
check(_mr[4] == 1 and "WRAPPER" in _mr[3],
      "fix#25: mint wrapper delegating to a gated sibling -> [.] not [!] (EtherOrcs mintRogues)")
check(recon.det_mint("contract C{function mint(address t,uint a) external { _mint(t,a); }}", "src/Fix.sol")[0][4] == 0,
      "fix#25: a real ungated mint calling the _mint primitive stays [!] (not a wrapper)")

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

print("== det_key (new detectors get distinct ledger groups, never 'other') ==")
_keys = [recon.det_key(t) for t, _, _ in recon.DETECTORS]
check("other" not in _keys, "every detector title maps to a real det_key (none fall through to 'other')")
check(len(set(_keys)) == len(_keys), "each detector has a UNIQUE det_key (no silent ledger-group collisions)")

print(f"\n{_p} passed, {_f} failed")
sys.exit(1 if _f else 0)
