#!/usr/bin/env python3
"""Golden tests for the MEMORY+RADAR lane (registry.py + radar.py).

Same style as test_detectors.py: pure asserts, no pytest, exits 1 if any fail (CI-friendly).

    python tests/test_registry_radar.py

Pins: norm_key merge/dedup, category extraction (chains/zones/fork/OWASP), fanout-table parse,
registry merge precedence, radar storage_impl slot-decode, and radar detect_events (baseline-seed,
bounty-open, impl-upgrade, dedup, non-registry ignore).
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "toolkit"))
import registry as R   # noqa: E402
import radar           # noqa: E402

_p, _f = 0, 0


def check(cond, msg):
    global _p, _f
    if cond:
        _p += 1
    else:
        _f += 1
        print("  FAIL:", msg)


def eq(a, b, msg):
    check(a == b, f"{msg}  (got {a!r}, want {b!r})")


print("== registry.norm_key (stable merge key; merges parenthetical dupes) ==")
eq(R.norm_key("Twyne (twyne-contracts-v1)"), "twyne", "parenthetical annotation dropped")
eq(R.norm_key("twyne"), "twyne", "bare key stable")
eq(R.norm_key("Vena Finance (native money market of Fluent L2)"), "vena-finance", "multi-word + paren")
eq(R.norm_key("venus-flux (XVS governance token)"), "venus-flux", "slug + paren merge")
check(R.norm_key("mezo-borrow") != R.norm_key("mezo-musd"), "distinct sibling products stay distinct")
eq(R.norm_key("Ample (Ample Earn — layer3xyz)"), "ample", "em-dash + paren")
eq(R.norm_key(""), "unknown", "empty -> unknown")
eq(R.norm_key("Twyne (x)"), R.norm_key("Twyne"), "annotated == bare (the dedup that 93->79 relies on)")

print("== registry.extract_chains (ambiguous English words gated to structured columns) ==")
eq(R.extract_chains("audited base currency, deployed on arbitrum"), ["arb"], "free-text drops spurious 'base'")
eq(R.extract_chains("Base,Arbitrum", structured=True), ["arb", "base"], "structured column keeps 'base'")
eq(R.extract_chains("native money market of Fluent L2"), ["fluent"], "fluent picked up")
eq(R.extract_chains("on ethereum mainnet"), ["eth"], "ethereum -> eth")
eq(R.extract_chains("a codebase note"), [], "'codebase' does not match 'base'")

print("== registry.extract_zones (DeFiLlama-style, canonicalised) ==")
check("lending" in R.extract_zones("isolated lending market"), "lending")
z = R.extract_zones("perp dex on arbitrum")
check("perp" in z and "dex" in z, "perp + dex")
check("lending" in R.extract_zones("a money market"), "money market -> lending (canon)")
check("lending" in R.extract_zones("borrow against collateral"), "borrow -> lending (canon)")

print("== registry.extract_fork ==")
eq(R.extract_fork("verbatim re-deployment of Velodrome V2"), "velodrome", "velodrome fork")
eq(R.extract_fork("a fork of Aave V3 lending"), "aave", "aave fork")
eq(R.extract_fork("greenfield custom code, no base"), None, "greenfield -> None")
eq(R.extract_fork("Compound-style comptroller"), "compound", "compound")

print("== registry.owasp_for (detector -> OWASP SC class) ==")
check("SC02-OracleManipulation" in R.owasp_for("spot_oracle"), "oracle -> SC02")
check("SC01-AccessControl" in R.owasp_for("unprotected_init"), "init -> SC01")
check("SC05-Reentrancy" in R.owasp_for("operator-reentrancy-cei"), "reentrancy -> SC05")
check("SC03-LogicError" in R.owasp_for("decimal_scale"), "decimal -> SC03")
eq(R.owasp_for("totally-unknown-detector"), [], "unknown detector -> no class")

print("== registry.parse_fanout (typed table) ==")
with tempfile.TemporaryDirectory() as d:
    md = os.path.join(d, "2026-06-27-demo.md")
    open(md, "w").write(
        "# demo\n"
        "| target | type | chain | gate | fork/audit | rec | leads |\n"
        "|---|---|---|---|---|---|---|\n"
        "| Foo Lending (foo-v1) | lending | arbitrum | live | aave-fork | DIG | x |\n"
        "| Bar Bridge | bridge | eth | dormant | greenfield | SKIP | - |\n"
    )
    fan = R.parse_fanout(os.path.join(d, "*.md"))
    check("foo-lending" in fan, "fanout row -> norm_key 'foo-lending'")
    eq(fan["foo-lending"]["status"], ("DIG", 5), "rec DIG -> status DIG/prio5")
    check("lending" in fan["foo-lending"]["zones"], "type 'lending' -> zone")
    check("arb" in fan["foo-lending"]["chains"], "structured chain 'arbitrum' -> arb")
    eq(fan["foo-lending"]["fork"], "aave", "fork/audit col -> aave")
    eq(fan["bar-bridge"]["status"], ("SKIP", 1), "rec SKIP -> status SKIP/prio1")

print("== registry.merge (status takes max priority across sources) ==")
a1 = {"x": {"name": "X", "sources": {"ledger"}, "zones": {"dex"}, "chains": set(), "fork": None,
            "owasp": set(), "status": ("CLEAN", 2), "n": 1, "reason": "short", "dates": ["2026-06-01"]}}
a2 = {"x": {"name": "X (long)", "sources": {"fanout"}, "zones": {"amm"}, "chains": {"eth"}, "fork": "uniswap",
            "owasp": set(), "status": ("DIG", 5), "n": 1, "reason": "a much longer reason", "dates": ["2026-06-10"]}}
m = R.merge(a1, a2)["x"]
eq(m["status"], ("DIG", 5), "DIG(5) beats CLEAN(2)")
eq(m["fork"], "uniswap", "fork carried")
check(m["sources"] == {"ledger", "fanout"}, "sources unioned")
eq(m["reason"], "a much longer reason", "longest reason kept")

print("== radar.storage_impl (EIP-1967 slot decode; monkeypatched RPC) ==")
_orig = radar.fs._rpc
try:
    radar.fs._rpc = lambda rpc, method, params: "0x000000000000000000000000" + "ab" * 20      # padded impl
    eq(radar.storage_impl("0xproxy", 1), "0x" + "ab" * 20, "padded slot -> last-20-bytes addr (lowercased)")
    radar.fs._rpc = lambda rpc, method, params: "0x" + "0" * 64                                  # empty slot
    eq(radar.storage_impl("0xproxy", 1), None, "zero slot -> None (non-proxy)")
    def _boom(*a):
        raise RuntimeError("rpc down")
    radar.fs._rpc = _boom
    eq(radar.storage_impl("0xproxy", 1), None, "rpc error -> None (graceful)")
    eq(radar.storage_impl("0xproxy", 999999), None, "no DEFAULT_RPC for chain -> None")
finally:
    radar.fs._rpc = _orig

print("== radar.detect_events (baseline / bounty-open / impl-upgrade / dedup / ignore) ==")
REG = {"twyne": {"name": "Twyne", "status": "DIG", "fork_base": "euler", "zones": ["lending"],
                 "last_reason": "prior read of the liq math"}}
prog = {"name": "Twyne", "slug": "twyne", "ecosystem": ["eth"], "assets": ["0xAAA"], "maxBounty": 50000}

# first run: seed baseline, NO events
seen = {"bounties": {}, "impls": {}}
ev = radar.detect_events([prog], REG, seen, True, "2026-06-27", impl_fn=lambda a, c: "0ximpl1")
eq(len(ev), 0, "first run emits no events")
check("twyne" in seen["bounties"], "first run seeds the bounty baseline")
check("1_0xaaa" in seen["impls"] and seen["impls"]["1_0xaaa"] == "0ximpl1", "first run seeds the impl baseline")

# steady state: same bounty, same impl -> NO events
ev = radar.detect_events([prog], REG, seen, False, "2026-06-27", impl_fn=lambda a, c: "0ximpl1")
eq(len(ev), 0, "no change -> no events")

# impl upgrade -> IMPL-UPGRADE event with prior notes attached
ev = radar.detect_events([prog], REG, seen, False, "2026-06-27", impl_fn=lambda a, c: "0ximpl2")
eq(len(ev), 1, "impl change -> one event")
eq(ev[0]["type"], "IMPL-UPGRADE", "event type")
check(ev[0]["tgt"]["last_reason"].startswith("prior read"), "prior notes carried into the event")
# dedup: same new impl next run -> NO event
ev = radar.detect_events([prog], REG, seen, False, "2026-06-27", impl_fn=lambda a, c: "0ximpl2")
eq(len(ev), 0, "dedup: recorded change does not re-fire")

# bounty newly opens (slug not yet seen) -> BOUNTY-OPEN
seen2 = {"bounties": {}, "impls": {"1_0xaaa": "0ximpl1"}}   # impl already baselined, bounty not
ev = radar.detect_events([prog], REG, seen2, False, "2026-06-27", impl_fn=lambda a, c: "0ximpl1")
eq([e["type"] for e in ev], ["BOUNTY-OPEN"], "new bounty -> BOUNTY-OPEN only")

# a program NOT in the registry is ignored
other = {"name": "RandomUntriaged", "slug": "rnd", "ecosystem": ["eth"], "assets": ["0xBBB"], "maxBounty": 1}
ev = radar.detect_events([other], REG, {"bounties": {}, "impls": {}}, False, "2026-06-27", impl_fn=lambda a, c: "0xz")
eq(len(ev), 0, "untriaged program ignored (we only signal on our targets)")

print("== radar.write_queue (rendered work-list) ==")
with tempfile.TemporaryDirectory() as d:
    q = os.path.join(d, "QUEUE.md")
    radar.write_queue([], "2026-06-27", True, q)
    check("baseline seeded" in open(q).read(), "first run -> baseline message")
    radar.write_queue([], "2026-06-27", False, q)
    check("All quiet" in open(q).read(), "no events -> All quiet")
    radar.write_queue([{"type": "IMPL-UPGRADE", "target": "Twyne", "key": "twyne", "slug": "twyne",
                        "detail": "0xAAA on chain 1: reviewed X -> NEW Y",
                        "tgt": REG["twyne"]}], "2026-06-27", False, q)
    body = open(q).read()
    check("IMPL-UPGRADE" in body and "Twyne" in body, "event rendered with type + target")
    check("prior read" in body, "prior notes rendered into the queue")

print("== radar.detect_impl_for_addrs (extra non-Immunefi address sources) ==")
TGT = {"name": "Venus Flux", "status": "CLEAN", "last_reason": "gov token, dead"}
pairs = [("56", "0xCFB", TGT)]
seen = {"bounties": {}, "impls": {}}
# baseline-seed on first run: no event, slot recorded
ev = radar.detect_impl_for_addrs(pairs, seen, True, impl_fn=lambda a, c: "0ximplA")
eq(len(ev), 0, "first run seeds, no event")
check(seen["impls"].get("56_0xcfb") == "0ximplA", "slot baselined under lowercased key")
# steady -> no event
eq(len(radar.detect_impl_for_addrs(pairs, seen, False, impl_fn=lambda a, c: "0ximplA")), 0, "no change -> none")
# upgrade -> event with prior notes
ev = radar.detect_impl_for_addrs(pairs, seen, False, impl_fn=lambda a, c: "0ximplB")
eq([e["type"] for e in ev], ["IMPL-UPGRADE"], "impl change -> IMPL-UPGRADE")
check(ev[0]["tgt"]["last_reason"] == "gov token, dead", "prior notes carried")
# dedup
eq(len(radar.detect_impl_for_addrs(pairs, seen, False, impl_fn=lambda a, c: "0ximplB")), 0, "dedup: no re-fire")
# non-proxy (impl_fn -> None) is skipped, not watched
seen2 = {"bounties": {}, "impls": {}}
eq(len(radar.detect_impl_for_addrs([("1", "0xEOA", TGT)], seen2, False, impl_fn=lambda a, c: None)), 0, "non-proxy skipped")
check("1_0xeoa" not in seen2["impls"], "non-proxy NOT baselined (correctly unwatchable)")

print("== radar.add_address (manual coverage-growth store) ==")
with tempfile.TemporaryDirectory() as d:
    os.makedirs(os.path.join(d, "monitor"))
    radar.add_address(d, "footgt", "8453", "0xDEAD")
    store = R and __import__("json").load(open(os.path.join(d, "monitor", "addresses.json")))
    check(store.get("footgt") == [{"chain": "8453", "addr": "0xDEAD"}], "address appended to store")
    radar.add_address(d, "footgt", "8453", "0xdead")     # same addr, different case
    store = __import__("json").load(open(os.path.join(d, "monitor", "addresses.json")))
    eq(len(store["footgt"]), 1, "idempotent: case-insensitive dedup, no dupe row")

print("== freshdeploy (deployer/factory new-contract radar) ==")
import freshdeploy as FD   # noqa: E402
eq(FD.cid("apechain"), 33139, "chain-name -> id (apechain)")
eq(FD.cid("eth"), 1, "chain-name -> id (eth)")
eq(FD.cid("42161"), "42161", "numeric chain passes through")
with tempfile.TemporaryDirectory() as d:
    os.makedirs(os.path.join(d, "hunts", "_radar"))
    _origroot = FD.ROOT
    FD.ROOT = d
    try:
        q = os.path.join(d, "hunts", "_radar", "FRESH-DEPLOY.md")
        FD.write_queue([], "2026-06-27", True, [{"addr": "0x1", "chain": "1"}])
        check("baseline seeded" in open(q).read(), "first run -> baseline message")
        FD.write_queue([], "2026-06-27", False, [{"addr": "0x1", "chain": "1"}])
        check("All quiet" in open(q).read(), "no new deploys -> All quiet")
        FD.write_queue([{"deployer": "0xDEP", "label": "Twyne factory", "kind": "factory",
                         "chain": "1", "child": "0xNEW", "verified": "CollateralVault"}],
                       "2026-06-27", False, [{"addr": "0x1", "chain": "1"}])
        body = open(q).read()
        check("0xNEW" in body and "Twyne factory" in body and "CollateralVault" in body,
              "new verified deploy rendered (child + label + ContractName)")
        check("dig FIRST" in body or "dig first" in body.lower(), "verified deploy prioritised as dig-first")
    finally:
        FD.ROOT = _origroot

print("== freshfeed (DefiLlama listedAt freshness filter) ==")
import time as _time
import freshfeed as FF   # noqa: E402
_now = _time.time()
_fresh = {"name": "FreshLend", "category": "Lending", "tvl": 1e6, "chains": ["eth"], "listedAt": _now - 2 * 86400, "audits": "0", "url": "x"}
_old = {"name": "OldLend", "category": "Lending", "tvl": 1e6, "chains": ["eth"], "listedAt": _now - 90 * 86400, "audits": "0", "url": "x"}
_offzone = {"name": "SomeNFTThing", "category": "NFT Marketplace", "tvl": 1e6, "chains": ["eth"], "listedAt": _now - 1 * 86400, "audits": "0", "url": "x"}
res_ff = FF.defillama_fresh(7, 0, "2026-06-27", data=[_fresh, _old, _offzone])
eq([c["name"] for c in res_ff], ["FreshLend"], "freshfeed: keeps recent our-zone, drops old + off-zone")
check("lend" in res_ff[0]["zones"], "freshfeed: zone tag derived")
eq(FF.norm("Jupiter Offerbook"), "jupiter-offerbook", "freshfeed.norm slugifies")

print("== registry.query (instant memory recall) ==")
import io
import contextlib
with tempfile.TemporaryDirectory() as d:
    os.makedirs(os.path.join(d, "monitor"))
    reg = {"targets": {
        "twyne": {"name": "Twyne", "key": "twyne", "status": "DIG", "zones": ["lending"], "chains": ["eth"],
                  "fork_base": "euler", "owasp_classes": ["SC02-Oracle"], "last_reason": "euler credit layer"},
        "flex": {"name": "Flex", "key": "flex", "status": "DIG", "zones": ["lending"], "chains": [],
                 "fork_base": "liquity", "owasp_classes": [], "last_reason": "liquity fork avg-rate"},
        "aborean": {"name": "Aborean", "key": "aborean", "status": "CLEAN", "zones": ["dex"], "chains": ["abstract"],
                    "fork_base": "velodrome", "owasp_classes": [], "last_reason": "verbatim velodrome"},
    }}
    __import__("json").dump(reg, open(os.path.join(d, "monitor", "registry.json"), "w"))

    def _q(**kw):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            R.query(d, kw.get("text"), kw.get("status"), kw.get("zone"), kw.get("fork"), kw.get("chain"), kw.get("owasp"))
        return buf.getvalue()
    check("Twyne" in _q(text="euler") and "Flex" not in _q(text="euler"), "free-text query matches reason/name")
    check("Flex" in _q(fork="liquity") and "Twyne" not in _q(fork="liquity"), "--fork filters to the fork-family (batch-CVE)")
    out_dig = _q(status="DIG")
    check("Twyne" in out_dig and "Flex" in out_dig and "Aborean" not in out_dig, "--status DIG excludes CLEAN")
    check("Twyne" in _q(owasp="SC02") and "Flex" not in _q(owasp="SC02"), "--owasp filters by vuln class")
    check("Aborean" in _q(chain="abstract") and "Twyne" not in _q(chain="abstract"), "--chain filters by chain")

print("== parkwatch.check_url_appears active-status gate (no FP on completed Cantina comps) ==")
import re as _re
import parkwatch as W   # noqa: E402

_rx = _re.compile(r'(?i)"panoptic')
# Cantina-shape: completed comp must NOT fire (the bug we just fixed)
_complete = '[{"name":"panoptic-core","status":"complete","createdAt":"2024-10-10"}]'
fired, reason, decided = W._active_match(_complete, _rx)
check(not fired and decided, "completed Cantina comp -> decided non-active, no fire")
check("status=complete" in reason, "reason names the non-active status")
# active comp MUST fire
_active = '[{"name":"panoptic-v2","status":"active","createdAt":"2026-06-28"}]'
fired, reason, decided = W._active_match(_active, _rx)
check(fired and "ACTIVE" in reason, "active Cantina comp -> fires")
# mixed feed: one complete + one active for the SAME needle -> active wins
_mixed = '[{"name":"panoptic-core","status":"complete"},{"name":"panoptic-v2","status":"live"}]'
fired, _, _ = W._active_match(_mixed, _rx)
check(fired, "mixed complete+live -> the live item fires")
# presence-based feed with NO status field (Immunefi bounties.json shape) -> raw fallback (decided False)
_nostatus = '[{"project":"panoptic","maxBounty":100000}]'
fired, reason, decided = W._active_match(_nostatus, _rx)
check(not fired and not decided, "no status-bearing match -> defer to raw substring fallback")
# wrapper dict whose own scalars don't contain the needle must not swallow the active child
_wrapped = '{"ok":true,"competitions":[{"name":"panoptic-v2","status":"active"}]}'
fired, _, _ = W._active_match(_wrapped, _rx)
check(fired, "active child under a status-less wrapper still fires")
# non-JSON (HTML) feed -> not decided, raw fallback handles it
fired, reason, decided = W._active_match("<html>panoptic</html>", _rx)
check(not decided, "non-JSON body -> defer to raw substring (HTML feeds)")
# full check_url_appears against a non-active stub: returns the honest non-active reason
def _stub_get(url):
    return _complete
W._get = _stub_get
ok, why = W.check_url_appears({"needle": r'(?i)"panoptic', "urls": ["http://x"]})
check(not ok and "non-active" in why, "check_url_appears: completed comp -> quiet + honest reason")

print("== parkwatch: unread feeds are named, never reported as quiet ==")
def _stub_get_partial(url):
    if "down" in url:
        raise OSError("certificate has expired")
    return _complete
W._get = _stub_get_partial
ok, why = W.check_url_appears({"needle": r'(?i)"panoptic', "urls": ["http://down.example/a", "http://x"]})
check(not ok and "UNREACHABLE" in why and "down.example" in why, "one feed down -> quiet reason names the unreachable host")
ok, why = W.check_url_appears({"needle": r'(?i)"panoptic', "urls": ["http://down.example/a", "http://down.example/b"]})
check(not ok and why.startswith("BLIND"), "every feed down -> BLIND, not 'needle absent'")

print("== parkwatch.main exit contract (FIRED -> 10; argparse's 2 can never read as a fire) ==")
W._get = lambda url: _active
with tempfile.TemporaryDirectory() as d:
    _wl = os.path.join(d, "watchlist.json")
    __import__("json").dump({"findings": [{"id": "p1", "title": "t", "fire_means": "m",
                                           "check": {"type": "url_appears", "needle": r'(?i)"panoptic',
                                                     "urls": ["http://x"]}}]}, open(_wl, "w"))
    _argv, sys.argv = sys.argv, ["parkwatch.py", _wl]
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            W.main()
        _rc = 0
    except SystemExit as e:
        _rc = e.code
    finally:
        sys.argv = _argv
eq(_rc, W.FIRED_EXIT, "an ACTIVE program match exits FIRED_EXIT")
eq(W.FIRED_EXIT, 10, "FIRED_EXIT = 10 (the monitors' shared convention)")

print("== monitor/watchlist.json: every parked lead uses a check type parkwatch knows ==")
_wl_real = __import__("json").load(open(os.path.join(os.path.dirname(__file__), "..", "monitor", "watchlist.json"),
                                        encoding="utf-8"))
for _lead in _wl_real.get("findings", []):
    check((_lead.get("check") or {}).get("type") in W.CHECKS, "watchlist %s: check type is dispatchable" % _lead.get("id"))
    _n = (_lead.get("check") or {}).get("needle")
    if _n is not None:
        # a JSON "\b" decodes to a BACKSPACE, not a regex word boundary -> the needle silently never matches
        check(not _re.search(r"[\x00-\x1f]", _n), "watchlist %s: needle has no control chars (write \\\\b in JSON)" % _lead.get("id"))

print("== FP regression: the Vena needle vs an Immunefi leaderboard handle 'Venator' ==")
_vena = next((x["check"] for x in _wl_real.get("findings", []) if x.get("id") == "vena-finance-pyth-oracle"), None)
if _vena:
    W._get = lambda url: '[{"project":"Audit Comp | Base Azul","boostedLeaderboard":[{"name":"Venator","points":1}]}]'
    ok, why = W.check_url_appears({"needle": _vena["needle"], "urls": ["http://x"]})
    check(not ok, "a researcher handle 'Venator' does NOT fire the Vena lead (fired daily until 2026-09-25)")
    W._get = lambda url: '[{"project":"Vena Finance","maxBounty":50000}]'
    ok, why = W.check_url_appears({"needle": _vena["needle"], "urls": ["http://x"]})
    check(ok and "Vena Finance" in why, "a real 'Vena Finance' program fires and the signal shows what matched")

print(f"\n{_p} passed, {_f} failed")
sys.exit(1 if _f else 0)
