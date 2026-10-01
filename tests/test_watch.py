#!/usr/bin/env python3
"""Golden tests for the change-event monitor (toolkit/watch.py) -- the pure classify() core.

    python tests/test_watch.py

classify() is pure (snapshot-in -> events-out), so this runs with no network. Stdlib only.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "toolkit"))
import watch as W  # noqa: E402

W._notify_telegram = lambda title, msg: False  # a HIGH event in run() must never reach a real bot from the tests

_p, _f = 0, 0


def check(cond, msg):
    global _p, _f
    if cond:
        _p += 1
    else:
        _f += 1
        print("  FAIL:", msg)


def snap(value=0, code="aaaa", has_code=True, last_days=None):
    return {"code_hash": code, "value": value, "has_code": has_code, "last_days": last_days, "native": value}


print("== classify: baseline + no-change ==")
check(W.classify(None, snap(100)) == [], "first snapshot (prev None) -> no events (baseline)")
check(W.classify(snap(100), snap(100)) == [], "identical snapshot -> no events")
check(W.classify(snap(100), snap(150)) == [], "value +50% (below 2x, above 50%) -> no event")

print("== classify: value events ==")
funded = W.classify(snap(0), snap(500))
check(len(funded) == 1 and funded[0]["type"] == "FUNDED" and funded[0]["sev"] == "HIGH",
      "0 -> value -> FUNDED (HIGH): a dormant finding went live")
drained = W.classify(snap(1000), snap(400))
check(len(drained) == 1 and drained[0]["type"] == "DRAINED" and drained[0]["sev"] == "HIGH",
      "value dropped >=50% -> DRAINED (HIGH): possible exploit")
check(W.classify(snap(1000), snap(600)) == [], "value dropped 40% (<50%) -> no DRAINED (threshold)")
grew = W.classify(snap(100), snap(250))
check(len(grew) == 1 and grew[0]["type"] == "GREW" and grew[0]["sev"] == "HIGH", "value >=2x -> GREW (HIGH, pushes)")
check(W.classify(snap(100), snap(0))[0]["type"] == "DRAINED", "value -> 0 -> DRAINED (full drain)")

print("== classify: code + activity ==")
cc = W.classify(snap(100, code="aaaa"), snap(100, code="bbbb"))
check(len(cc) == 1 and cc[0]["type"] == "CODE-CHANGE" and cc[0]["sev"] == "HIGH", "code hash change -> CODE-CHANGE (HIGH)")
check(W.classify(snap(100, code="aaaa"), snap(100, code="bbbb", has_code=False)) == [],
      "code hash 'change' to no-code -> ignored (RPC hiccup guard)")
react = W.classify(snap(100, last_days=90), snap(100, last_days=2))
check(len(react) == 1 and react[0]["type"] == "REACTIVATED", "dormant(90d) -> active(2d) -> REACTIVATED")
check(W.classify(snap(100, last_days=90), snap(100, last_days=40)) == [], "still dormant (40d) -> no REACTIVATED")

print("== classify: combined (code change + drain in one diff) ==")
combo = W.classify(snap(1000, code="aaaa"), snap(100, code="cccc"))
types = {e["type"] for e in combo}
check(types == {"CODE-CHANGE", "DRAINED"}, "simultaneous code-swap + drain -> both events emitted")

print("== unread value: an RPC that gives no answer is unknown, never a 0 (no false DRAINED / FUNDED) ==")
check(W.classify(snap(1000), snap(None)) == [], "value unread this cycle -> no DRAINED (a null RPC answer is not a drain)")
check(W.classify(snap(None), snap(500)) == [], "no baseline value -> no FUNDED (nothing to diff against)")


def _rpc_null_balance(rpc, method, params):
    return {"eth_getCode": "0x6080", "eth_getBalance": None}.get(method)


_s = W.snapshot({"key": "k", "chain": "x", "addr": "0x" + "11" * 20}, "t0", _rpc=_rpc_null_balance)
check(_s["value"] is None and _s["native"] is None and _s["has_code"], "snapshot: eth_getBalance null -> value None, not 0")

import json  # noqa: E402
import tempfile  # noqa: E402

_tmp = tempfile.mkdtemp()
_paths = (W.WATCHLIST, W.STATE, W.EVENTS, W.QUEUE)
W.WATCHLIST, W.STATE, W.EVENTS, W.QUEUE = (os.path.join(_tmp, n) for n in ("wl.json", "st.json", "ev.json", "q.md"))
try:
    with open(W.WATCHLIST, "w") as f:
        json.dump([{"key": "k", "chain": "1", "addr": "0x" + "22" * 20}], f)
    with open(W.STATE, "w") as f:
        json.dump({"k": snap(1000, last_days=90)}, f)
    ev = W.run(_snap=lambda e, now: snap(None, last_days=None))
    with open(W.STATE) as f:
        st = json.load(f)["k"]
    check(ev == [] and st["value"] == 1000 and st.get("value_unread") and st["last_days"] == 90,
          "run: an unread cycle keeps the last good baseline (value + last_days), flagged *_unread")
finally:
    W.WATCHLIST, W.STATE, W.EVENTS, W.QUEUE = _paths

import fetch_source  # noqa: E402

check(W.WATCH_RPC is fetch_source.DEFAULT_RPC,
      "one RPC map: the watcher and threat/activity see the same chains (X Layer/Robinhood/ApeChain/opBNB)")

print("== native symbol: a chain's own coin, never a blanket ETH (111 APE arrived as a '111 ETH DRAINED' alarm) ==")
E18 = 10 ** 18


def nsnap(value, sym):
    return dict(snap(value), native_sym=sym)


_d = W.classify(nsnap(111 * E18, "APE"), nsnap(0, "APE"))
check(_d and "111 APE -> 0 APE" in _d[0]["detail"] and "ETH" not in _d[0]["detail"],
      "ApeChain DRAINED prints APE, not ETH")
_d = W.classify(snap(111 * E18), nsnap(0, "APE"))
check(_d and "111 APE -> 0 APE" in _d[0]["detail"], "a baseline from before native_sym borrows the current symbol")
check(fetch_source.native_symbol("33139") == "APE" and fetch_source.native_symbol(56) == "BNB",
      "native_symbol: ApeChain APE, BSC BNB (str or int chain id)")
check(fetch_source.native_symbol("999999") == "native", "unknown chain -> 'native', not a guessed ETH")
check(W._fmtv(5 * E18, {}) == "5 native", "a snapshot without a symbol prints 'native'")
_lad, W.T.last_activity_days = W.T.last_activity_days, lambda a, c: None  # no network: a numeric chain asks the explorer
try:
    _s = W.snapshot({"key": "k", "chain": "33139", "addr": "0x" + "11" * 20}, "t0",
                    _rpc=lambda rpc, m, p: {"eth_getCode": "0x6080", "eth_getBalance": hex(E18)}.get(m))
finally:
    W.T.last_activity_days = _lad
check(_s["native_sym"] == "APE", "snapshot records the chain's native symbol")

print("== DRAINED flows: where the value went vs what each recipient had put in ==")
H2H = "0x88c1f4ecde714fba062853da1f686171f560ebaa"
A, B, FEE = "0x181001add634b3bce130984e0984be39c56caeb6", "0xbe18b5180d" + "0" * 30, "0x36825bf3fb" + "0" * 30


def row(frm, to, apes, ts, err="0"):
    return {"from": frm, "to": to, "value": str(int(apes * 10000) * 10 ** 14), "timeStamp": str(ts), "isError": err}


T0, T1 = 1_790_000_000, 1_790_900_000  # baseline / drain window
# the 2026-10-01 head2head shape: B matched A's three open bets (1/10/100 APE); each match paid the Entropy fee
TXLIST = [row(A, H2H, 1, T0 - 50), row(A, H2H, 10, T0 - 50), row(A, H2H, 100, T0 - 50),
          row(B, H2H, 1, T1), row(B, H2H, 10, T1), row(B, H2H, 100, T1),
          row(B, H2H, 500, T1, err="1")]  # a reverted bet never paid in
INTERNAL = [row(H2H, A, 199.7768, T1), row(H2H, B, 19.7768, T1), row(H2H, B, 1.7768, T1),
            row(H2H, FEE, 0.2232, T1), row(H2H, FEE, 0.2232, T1), row(H2H, FEE, 0.2232, T1),
            row(H2H, B, 50, T0 - 999)]  # an old payout, before the window


def fake_query(chain, params):
    rows = {"txlist": TXLIST, "txlistinternal": INTERNAL}[params["action"]]
    return rows[(params["page"] - 1) * params["offset"]:params["page"] * params["offset"]], "etherscan", None


_e = {"key": "h2h", "chain": "33139", "addr": H2H}
_out, _in, _why, _cap = W.fetch_flows(_e, T0, _query=fake_query)
check(_why is None and len(_out) == 6 and not _cap, "fetch_flows: only outflows at/after `since` (the old payout is out)")
check(all(r["isError"] != "1" for r in _in) and len(_in) == 6, "fetch_flows: a reverted deposit is not a stake")
_note = W.summarize_flows(_out, _in, lambda v: W._fmtv(v, {"native_sym": "APE"}))
check(_note.startswith("flows: 222 APE out to 3 addr"), "summary: total out + distinct recipients")
check(_note.index("199.7768 APE -> 0x181001ad.. (put in 111 APE)") < _note.index("21.5536 APE -> 0xbe18b518"),
      "recipients ranked by take, each with what it had put in")
check("0x36825bf3.. (put in 0 native)" not in _note and "(put in 0 APE)" in _note,
      "a never-depositor (the Entropy fee) shows put in 0")
check(_note.endswith("100% to addresses that had paid in"), "share of the outflow that went back to depositors")
_thief = W.summarize_flows([row(H2H, "0xa77ac4e7" + "0" * 32, 111, T1)], _in, lambda v: W._fmtv(v, {"native_sym": "APE"}))
check("(put in 0 APE)" in _thief and _thief.endswith("0% to addresses that had paid in"),
      "an outsider drain reads as value to a never-depositor")
check(W.summarize_flows([], _in, str).startswith("flows: no outflow on record"),
      "value dropped but no outflow on record -> said, not silently empty")
_many = W.summarize_flows([row(H2H, "0x%040x" % i, i, T1) for i in range(1, 8)], [], str)
check("+3 more" in _many and "to 7 addr" in _many, "beyond the top recipients -> summed as '+N more'")

_refused = lambda c, p: (None, None, "etherscan: Free API access is not supported for this chain")  # noqa: E731
check(W.flow_note(_e, {"ts": "2026-09-26T10:00:00"}, nsnap(0, "APE"),
                  _fetch=lambda e, s: W.fetch_flows(e, s, _query=_refused))
      == "flows: UNKNOWN (etherscan: Free API access is not supported for this chain)",
      "explorer refusal -> flows UNKNOWN with the reason, never 'no outflow'")


def _boom(e, s):
    raise RuntimeError("socket closed")


check(W.flow_note(_e, {}, nsnap(0, "APE"), _fetch=_boom).startswith("flows: UNKNOWN ("),
      "a crashing lookup degrades to UNKNOWN, the DRAINED alert still goes out")
_seen = []
W.flow_note(_e, {"ts": "2026-09-26T10:00:00"}, nsnap(0, "APE"),
            _fetch=lambda e, s: _seen.append(s) or ([], [], None, False))
check(_seen and abs(_seen[0] - (W._iso_ts("2026-09-26T10:00:00") - W._FLOW_SLACK_S)) < 1,
      "the window starts at the previous snapshot (minus clock slack)")
_seen = []
W.flow_note(_e, {"ts": "2026-09-26T14:00:00", "value_ts": "2026-09-26T10:00:00"}, nsnap(0, "APE"),
            _fetch=lambda e, s: _seen.append(s) or ([], [], None, False))
check(_seen and abs(_seen[0] - (W._iso_ts("2026-09-26T10:00:00") - W._FLOW_SLACK_S)) < 1,
      "a carried (unread-cycle) value -> the window starts when it was READ, not at the unread check")
check(W.flow_note(_e, {"ts": "1969-12-31T23:59:59"}, nsnap(0, "APE"),
                  _fetch=lambda e, s: ([], [], None, False)).startswith("flows: "),
      "an unconvertible baseline stamp (Windows pre-1970 OSError) never crashes flow_note")
check("apikey=***" in W.flow_note(_e, {}, nsnap(0, "APE"),
                                  _fetch=lambda e, s: (None, None, "etherscan: bad url ?apikey=SECRET123&x", False))
      and "SECRET123" not in W.flow_note(_e, {}, nsnap(0, "APE"),
                                         _fetch=lambda e, s: (None, None, "x apikey=SECRET123", False)),
      "an explorer reason that echoes the key is masked before it reaches the alert")

print("== flows: paging, CREATE recipients ==")
_BIG = [row(A, H2H, 1, T0 - 10)] + [row(B, H2H, 1, T1)] * 2500  # A's stake sits behind 2500 newer rows
_pages = []


def big_query(chain, params):
    _pages.append((params["action"], params["page"]))
    rows = _BIG[::-1] if params["action"] == "txlist" else INTERNAL
    return rows[(params["page"] - 1) * params["offset"]:params["page"] * params["offset"]], "etherscan", None


_out, _in, _why, _cap = W.fetch_flows(_e, T0, _query=big_query)
check(("txlist", 3) in _pages and not _cap and any((r["from"] == A) for r in _in),
      "a stake older than the first 1000 rows is still found (paged until a short page)")
_old = W._FLOW_PAGES
W._FLOW_PAGES = 2
try:
    _out, _in, _why, _cap = W.fetch_flows(_e, T0, _query=big_query)
finally:
    W._FLOW_PAGES = _old
check(_cap and "capped at" in W.summarize_flows(_out, _in, str, _cap),
      "history beyond the page cap -> the note says the sums are lower bounds")


def flaky_query(chain, params):
    if params["page"] > 1:
        return None, None, "etherscan: Max rate limit reached"
    return big_query(chain, params)


_out, _in, _why, _cap = W.fetch_flows(_e, T0, _query=flaky_query)
check(_why is None and _cap, "a later page failing keeps the first pages and marks the result capped")
_create = [dict(row(H2H, "", 3, T1), contractAddress="0x" + "c1" * 20, type="create"),
           dict(row(H2H, "", 4, T1), contractAddress="0x" + "c2" * 20, type="create")]
check("to 2 addr" in W.summarize_flows(_create, [], str) and "?.." not in W.summarize_flows(_create, [], str),
      "CREATE transfers: the recipient is the created contract (contractAddress), not one '?' bucket")

_tmp2 = tempfile.mkdtemp()
_paths = (W.WATCHLIST, W.STATE, W.EVENTS, W.QUEUE)
W.WATCHLIST, W.STATE, W.EVENTS, W.QUEUE = (os.path.join(_tmp2, n) for n in ("wl.json", "st.json", "ev.json", "q.md"))
try:
    with open(W.WATCHLIST, "w") as f:
        json.dump([_e], f)
    with open(W.STATE, "w") as f:
        json.dump({"h2h": dict(nsnap(111 * E18, "APE"), ts="2026-09-26T10:00:00")}, f)
    _ev = W.run(now_iso="2026-10-01T09:00:00", _snap=lambda e, now: dict(nsnap(0, "APE"), ts=now),
                _flows=lambda e, s: W.fetch_flows(e, s, _query=fake_query))
    check(len(_ev) == 1 and _ev[0]["type"] == "DRAINED" and "| flows: " in _ev[0]["detail"]
          and "(put in 111 APE)" in _ev[0]["detail"], "run: a DRAINED event carries the flows line")
    # unread cycle between the read baseline and the drain: value_ts keeps the window anchored at the last real read
    with open(W.STATE, "w") as f:
        json.dump({"h2h": dict(nsnap(111 * E18, "APE"), ts="2026-09-26T10:00:00")}, f)
    W.run(now_iso="2026-09-26T14:00:00", _snap=lambda e, now: dict(nsnap(None, "APE"), ts=now))
    with open(W.STATE) as f:
        _st = json.load(f)["h2h"]
    check(_st["value"] == 111 * E18 and _st["value_ts"] == "2026-09-26T10:00:00",
          "run: an unread cycle records when the carried value was read (value_ts)")
finally:
    W.WATCHLIST, W.STATE, W.EVENTS, W.QUEUE = _paths

print(f"\n{_p} passed, {_f} failed")
sys.exit(1 if _f else 0)
