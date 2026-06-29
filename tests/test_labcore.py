#!/usr/bin/env python3
"""Golden tests for Layer 1+2a of the platform: labcore operations + the lab_mcp JSON-RPC protocol.

    python tests/test_labcore.py

Pins: pipeline staging, target filters (AND), name/id lookup, next_dig ranking, record_verdict
validation + ledger write; and the MCP handle() dispatch (initialize echoes proto, notifications -> None,
tools/list shape with NO leaked _req, tools/call wraps result / errors on unknown tool+method).
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "toolkit"))
import labcore as C       # noqa: E402
import lab_mcp as M       # noqa: E402

_p, _f = 0, 0


def check(cond, msg):
    global _p, _f
    if cond:
        _p += 1
    else:
        _f += 1
        print("  FAIL:", msg)


# --- a minimal injected state (read ops take s=, so no file IO) ---
S = {"targets": [
    {"id": "a", "name": "Alpha", "status": "REAL", "zones": ["dex"], "fork_base": None, "chains": ["eth"],
     "sensitivity": "high", "lastupdated": "2026-06-01", "verdicts": []},
    {"id": "b", "name": "Bravo", "status": "DIG", "zones": ["lending"], "fork_base": "euler", "chains": ["eth"],
     "sensitivity": "high", "lastupdated": "2026-06-03", "verdicts": [{"verdict": "todo"}]},
    {"id": "c", "name": "Charlie", "status": "DIG", "zones": ["lending"], "fork_base": "euler", "chains": ["base"],
     "sensitivity": "high", "lastupdated": "2026-06-02", "verdicts": []},
    {"id": "d", "name": "Delta", "status": "CLEAN", "disposition": "skip", "zones": [], "chains": [],
     "sensitivity": "normal", "lastupdated": "2026-06-01", "verdicts": []},
    {"id": "e", "name": "Echo", "status": "CLEAN", "disposition": "park", "zones": [], "chains": [],
     "sensitivity": "normal", "lastupdated": "2026-06-01", "verdicts": []},
    {"id": "g", "name": "Golf", "status": "CLEAN", "disposition": None, "zones": [], "chains": [],
     "sensitivity": "normal", "lastupdated": "2026-06-01", "verdicts": []},
], "findings": [{"id": "f1"}], "parked": [{"id": "p1"}], "repos": [{"slug": "x/y"}],
   "metrics": {"precision": {"value": 0.5}, "recall": {"value": 1.0}}}

print("== labcore reads (pipeline / filters / lookup / next_dig) ==")
pl = C.pipeline(s=S)
check(pl["by_stage"] == {"REAL": 1, "DIG": 2, "SKIP": 1, "PARK": 1, "CLEAN": 1},
      "pipeline by_stage splits CLEAN into SKIP/PARK/CLEAN via disposition")
check(pl["targets"] == 6 and pl["findings"] == 1 and pl["parked"] == 1, "pipeline rollup counts")
check([t["id"] for t in C.targets(status="DIG", s=S)] == ["b", "c"], "--status filter")
check([t["id"] for t in C.targets(fork="euler", s=S)] == ["b", "c"], "--fork filter")
check([t["id"] for t in C.targets(zone="dex", s=S)] == ["a"], "--zone filter")
check([t["id"] for t in C.targets(chain="base", s=S)] == ["c"], "--chain filter")
check({t["id"] for t in C.targets(sensitivity="normal", s=S)} == {"d", "e", "g"}, "--sensitivity filter")
check([t["id"] for t in C.targets(status="DIG", fork="euler", chain="eth", s=S)] == ["b"], "filters AND together")
check(C.target("c", s=S)["id"] == "c" and C.target("Alpha", s=S)["id"] == "a", "lookup by id OR name")
nd = C.next_dig(s=S)
check(nd["next"]["id"] == "a" and nd["total"] == 3, "next_dig: REAL first, 3 actionable")
check([t["id"] for t in nd["queue"]] == ["a", "c", "b"], "next_dig queue: REAL, then oldest-lastupdated DIG first")

print("== labcore.record_verdict (mutation -> ledger) ==")
with tempfile.TemporaryDirectory() as d:
    lp = os.path.join(d, "ledger.json")
    r = C.record_verdict("Foo Protocol", "fp", "false positive: gated by isAdmin", detector="sibling", path=lp)
    check(r["ok"] and r["verdict"] == "fp", "valid verdict written")
    saved = json.load(open(lp))
    check(saved["entries"][0]["verdict"] == "fp" and "foo" in saved["entries"][0]["target"].lower(), "entry persisted to ledger")
    try:
        C.record_verdict("X", "bogus", "r", path=lp)
        check(False, "bad verdict should raise")
    except ValueError:
        check(True, "bad verdict rejected")
    try:
        C.record_verdict("X", "fp", "", path=lp)
        check(False, "empty reason should raise")
    except ValueError:
        check(True, "empty reason rejected")

print("== lab_mcp.handle (JSON-RPC protocol) ==")
tools = M.build_tools()
ini = M.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2099-01-01"}}, tools)
check(ini["result"]["serverInfo"]["name"] == "security-lab", "initialize -> serverInfo")
check(ini["result"]["protocolVersion"] == "2099-01-01", "initialize echoes client protocol version")
check(M.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}, tools) is None, "notification -> no reply")
tl = M.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, tools)
names = [t["name"] for t in tl["result"]["tools"]]
check(len(names) == 9 and "lab_record_verdict" in names and "lab_next_dig" in names, "tools/list: 9 tools")
schemas = [t["inputSchema"] for t in tl["result"]["tools"]]
check(all("_req" not in json.dumps(s) for s in schemas), "internal _req marker stripped from sent schemas")
rv = next(t for t in tl["result"]["tools"] if t["name"] == "lab_record_verdict")
check(set(rv["inputSchema"]["required"]) == {"target", "verdict", "reason"}, "required params surfaced in schema")

# pure dispatch with a MOCK tool (no real state coupling)
mock = [("echo", "e", {"type": "object", "properties": {}}, lambda a: {"got": a})]
call = M.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                 "params": {"name": "echo", "arguments": {"x": 1}}}, mock)
check(json.loads(call["result"]["content"][0]["text"]) == {"got": {"x": 1}}, "tools/call wraps result as text content")
bad = M.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "nope"}}, mock)
check(bad["error"]["code"] == -32602, "unknown tool -> JSON-RPC error -32602")
err = [("boom", "e", {}, lambda a: (_ for _ in ()).throw(RuntimeError("kaboom")))]
ce = M.handle({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "boom", "arguments": {}}}, err)
check(ce["result"]["isError"] and "kaboom" in ce["result"]["content"][0]["text"], "tool exception -> isError result, not protocol crash")
check(M.handle({"jsonrpc": "2.0", "id": 6, "method": "bogus/method"}, tools)["error"]["code"] == -32601,
      "unknown method -> -32601")

print("== lab_http bridge (pure api_get / api_post routing) ==")
import lab_http as H   # noqa: E402

code, obj = H.api_get("/api/pipeline")
check(code == 200 and "by_stage" in obj, "GET /api/pipeline -> 200 + rollup")
code, obj = H.api_get("/api/targets?status=DIG")
check(code == 200 and isinstance(obj, list) and all(t["status"] == "DIG" for t in obj), "GET /api/targets?status=DIG filters")
check(H.api_get("/api/nope")[0] == 404, "unknown read api -> 404")

check(H.api_post("/api/record_verdict", {"target": "X", "verdict": "bogus", "reason": "r"})[0] == 400,
      "POST record_verdict bad verdict -> 400 (validation)")
check(H.api_post("/api/record_verdict", {"target": "X", "verdict": "fp", "reason": ""})[0] == 400,
      "POST record_verdict empty reason -> 400")
check(H.api_post("/api/nope", {})[0] == 404, "unknown write api -> 404")
# a VALID write routes to labcore — monkeypatch so the test never touches the real ledger
_orig = H.C.record_verdict
H.C.record_verdict = lambda *a, **k: {"ok": True, "verdict": a[1] if len(a) > 1 else k.get("verdict")}
try:
    code, obj = H.api_post("/api/record_verdict", {"target": "Foo", "verdict": "fp", "reason": "gated"})
    check(code == 200 and obj["ok"] and obj["verdict"] == "fp", "POST record_verdict valid -> 200 (routes to labcore)")
finally:
    H.C.record_verdict = _orig

print(f"\n{_p} passed, {_f} failed")
sys.exit(1 if _f else 0)
