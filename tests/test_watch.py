#!/usr/bin/env python3
"""Golden tests for the change-event monitor (toolkit/watch.py) -- the pure classify() core.

    python tests/test_watch.py

classify() is pure (snapshot-in -> events-out), so this runs with no network. Stdlib only.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "toolkit"))
import watch as W  # noqa: E402

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

print(f"\n{_p} passed, {_f} failed")
sys.exit(1 if _f else 0)
