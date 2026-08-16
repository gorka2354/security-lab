#!/usr/bin/env python3
"""Golden tests for the dynamic-fuzz dispatch loop (toolkit/dispatch.py).

    python tests/test_dispatch.py

Pure core (select/build/parse/interpret/record) with an injected SSH runner + temp log/ledger, so this runs
with or without the stand reachable. Stdlib only.
"""
import os
import sys
import json
import types
import tempfile
import subprocess

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "toolkit"))
import dispatch as D  # noqa: E402

_p, _f = 0, 0


def check(cond, msg):
    global _p, _f
    if cond:
        _p += 1
    else:
        _f += 1
        print("  FAIL:", msg)


REG = {
    "clean1": {"name": "clean1", "status": "CLEAN", "addresses": ["0x" + "1" * 40], "chains": ["eth"]},
    "noaddr": {"name": "noaddr", "status": "DIG", "addresses": [], "chains": ["eth"]},
    "abstractonly": {"name": "abs", "status": "DIG", "addresses": ["0x" + "2" * 40], "chains": ["abstract"]},
    "zeroaddr": {"name": "zero", "status": "DIG", "addresses": ["0x" + "0" * 40], "chains": ["eth"]},
    "good_eth": {"name": "good_eth", "status": "DIG", "addresses": ["0x" + "a" * 40], "chains": ["eth"]},
    "good_arb": {"name": "good_arb", "status": "REAL", "addresses": ["0x" + "b" * 40], "chains": ["arbitrum", "eth"]},
    "impl_pref": {"name": "impl", "status": "DIG", "addresses": ["0x" + "c" * 40], "chains": ["eth"],
                  "reviewed_impl": {"eth": {"impl": "0x" + "d" * 40}}},
}

print("== select_targets (filtering) ==")
sel = D.select_targets(REG, log=[])
keys = {s["key"] for s in sel}
check(keys == {"good_eth", "good_arb", "impl_pref"}, "keeps DIG/REAL w/ EVM addr; drops CLEAN/noaddr/abstract/zero")
check(all(s["chain"] in D.EVM_FUZZ_CHAINS for s in sel), "picked chains are EVM-fuzzable")
byk = {s["key"]: s for s in sel}
check(byk["good_arb"]["chain"] in ("arbitrum",), "first EVM chain chosen (arbitrum before eth)")
check(byk["impl_pref"]["address"] == "0x" + "d" * 40 + ",0x" + "c" * 40,
      "reviewed_impl impl first, then addresses[0] (comma-list, capped)")
check(sel[0]["key"] == "good_arb", "REAL (good_arb) selected before DIG")
check(len(D.select_targets(REG, statuses=("REAL",), log=[])) == 1, "status filter (REAL only -> 1)")
check(len(D.select_targets(REG, chains={"arbitrum"}, log=[])) == 1, "chains restrict (arbitrum -> only good_arb)")
check(len(D.select_targets(REG, limit=1, log=[])) == 1, "limit honored")

print("== recently_fuzzed / skip + force ==")
LOG = [{"key": "good_eth", "ts": "2026-08-15"}]
check(D.recently_fuzzed(LOG, "good_eth", "2026-08-16") is True, "same key within 14d -> recent")
check(D.recently_fuzzed(LOG, "good_eth", "2026-09-30") is False, "same key >14d ago -> not recent")
skipped = {s["key"] for s in D.select_targets(REG, log=LOG, today="2026-08-16")}
check("good_eth" not in skipped, "recently-fuzzed target skipped in sweep")
forced = {s["key"] for s in D.select_targets(REG, log=LOG, today="2026-08-16", force=True)}
check("good_eth" in forced, "--force re-includes a recently-fuzzed target")

print("== reach-chaining (resolve address-less targets) ==")
check(D.resolve_from_key("krystal-community-vault-0xff630c5d2fb9920c29c264b85e968d435f07e293")
      == "0xff630c5d2fb9920c29c264b85e968d435f07e293", "address embedded in key -> extracted")
check(D.resolve_from_key("no-address-here") is None, "no address in key -> None")
check(D.resolve_from_key("zero-0x" + "0" * 40) is None, "zero address in key -> None")
_fake_dl = lambda k: {"ethereum": ["0x" + "e" * 40, "0x" + "f" * 40]} if k == "hit" else {}
check(D.resolve_from_defillama("hit", _addrs=_fake_dl) == (["0x" + "e" * 40, "0x" + "f" * 40], "ethereum"),
      "defillama -> addr LIST + primary chain")
check(D.resolve_from_defillama("miss", _addrs=_fake_dl) is None, "defillama no adapter -> None")
_multi = lambda k: {"base": ["0x" + "1" * 40], "arbitrum": ["0x" + "2" * 40, "0x" + "3" * 40, "0x" + "4" * 40]}
check(D.resolve_from_defillama("x", _addrs=_multi)[1] == "arbitrum",
      "primary chain = the EVM chain with the MOST contracts")
check(D.resolve_from_defillama("x", _addrs=lambda k: {"tron": ["0x" + "e" * 40]}) is None,
      "defillama non-EVM chain only -> None")


def _boom(k):
    raise RuntimeError("404")


check(D.resolve_from_defillama("x", _addrs=_boom) is None, "defillama fetch error -> None (no crash)")
# enrich fills addresses for address-less DIG, leaves addressed/CLEAN alone
_reg2 = {"kk-0x" + "a" * 40: {"name": "kk", "status": "DIG", "addresses": [], "chains": ["eth"]},
         "dlt": {"name": "dlt", "status": "REAL", "addresses": [], "chains": ["eth"]},
         "clean1": {"name": "c", "status": "CLEAN", "addresses": [], "chains": ["eth"]}}
_en = D.enrich(_reg2, reach=True, _addrs=lambda k: {"ethereum": ["0x" + "b" * 40]})
check(_en["kk-0x" + "a" * 40]["addresses"] == ["0x" + "a" * 40], "enrich: address-in-key fills addresses")
check(_en["dlt"]["addresses"] == ["0x" + "b" * 40], "enrich: defillama fills addresses")
check(_en["clean1"]["addresses"] == [], "enrich: CLEAN target left untouched")
check(D.enrich(_reg2, reach=False) is _reg2, "enrich reach=False -> no-op passthrough")
# and enriched targets become selectable
sel2 = D.select_targets(_en, log=[])
check({s["key"] for s in sel2} == {"kk-0x" + "a" * 40, "dlt"}, "reach-resolved targets are now selectable")
# multi-address: enrich stores ALL resolved contracts; pick_address fuzzes up to ADDR_CAP together (comma-list)
_reg3 = {"multi": {"name": "m", "status": "DIG", "addresses": [], "chains": ["eth"]}}
_en3 = D.enrich(_reg3, reach=True, _addrs=lambda k: {"ethereum": ["0x" + c * 40 for c in "12345"]})
check(len(_en3["multi"]["addresses"]) == 5, "enrich stores ALL resolved contracts")
check(D.pick_address(_en3["multi"]).count("0x") == D.ADDR_CAP, "pick_address caps the fuzz set at ADDR_CAP")
check(D.pick_address(_en3["multi"]) == ",".join("0x" + c * 40 for c in "123"), "comma-list of the first ADDR_CAP")

print("== build_remote_cmd ==")
rc = D.build_remote_cmd("0xABC", "eth", 240)
check("ityfuzz_lane.py 0xABC --chain eth --timeout 240" in rc, "lane invocation with addr/chain/timeout")
check("source ~/.seclab_env" in rc and ".ityfuzz/bin" in rc, "sources env + puts ityfuzz on PATH")
check(D.build_ssh(rc)[0] == "ssh" and "BatchMode=yes" in D.build_ssh(rc), "ssh wrapper is batch-mode")

print("== parse_remote + interpret ==")
lane_json = '[ityfuzz] fuzzing ...\n{\n "found": false,\n "ok": true,\n "n_signals": 0\n}\n'
r = D.parse_remote(lane_json)
check(r and r["ok"] is True and r["found"] is False, "extracts the lane JSON block from noisy stdout")
check(D.parse_remote("no json here") is None, "no JSON -> None")
check(D.interpret({"ok": True, "found": True, "n_signals": 2, "markers": ["[BUG] arbitrary call"]})["state"] == "lead",
      "found -> lead")
check(D.interpret({"ok": True, "found": False, "execs": 900000})["state"] == "clean", "ok+not found+real execs -> clean")
check(D.interpret({"ok": True, "found": False, "execs": 0})["state"] == "error",
      "ok but ~0 execs -> error (false-clean guard: campaign never ran)")
check(D.interpret({"ok": False, "error": "boom"})["state"] == "error", "not ok -> error")
check(D.interpret(None)["state"] == "error", "None -> error")

print("== run_one via injected runner ==")
tgt = {"key": "good_eth", "name": "good_eth", "status": "DIG", "address": "0x" + "a" * 40, "chain": "eth"}
clean_out = types.SimpleNamespace(stdout='{"ok": true, "found": false, "n_signals": 0, "execs": 900000}', stderr="")
row = D.run_one(tgt, 10, _runner=lambda *a, **k: clean_out)
check(row["state"] == "clean", "mocked clean campaign -> clean row")
lead_out = types.SimpleNamespace(stdout='{"ok": true, "found": true, "n_signals": 3, "markers": ["[BUG] reentrancy"]}',
                                 stderr="")
row2 = D.run_one(tgt, 10, _runner=lambda *a, **k: lead_out)
check(row2["state"] == "lead" and row2["n_signals"] == 3, "mocked lead campaign -> lead row w/ signals")


def _timeout_runner(*a, **k):
    raise subprocess.TimeoutExpired(cmd="ssh", timeout=1, output='{"ok": true, "found": false, "execs": 500000}',
                                    stderr="")


row3 = D.run_one(tgt, 1, _runner=_timeout_runner)
check(row3["state"] == "clean", "timeout still parses the partial JSON the lane printed")

print("== record: dispatch-log + ledger todo on lead ==")
tmp = tempfile.mkdtemp()
log_path = os.path.join(tmp, "dispatch-log.json")
led_path = os.path.join(tmp, "ledger.json")
D.record({**tgt, "state": "clean", "n_signals": 0, "summary": "0 objectives"}, today="2026-08-16",
         log_path=log_path, ledger_path=led_path)
D.record({**tgt, "key": "leadtgt", "state": "lead", "n_signals": 3, "summary": "[BUG] reentrancy"},
         today="2026-08-16", log_path=log_path, ledger_path=led_path)
saved = json.load(open(log_path))
check(len(saved) == 2 and saved[0]["state"] == "clean" and saved[1]["state"] == "lead", "both rows logged")
led = json.load(open(led_path)) if os.path.exists(led_path) else {}
blob = json.dumps(led)
check("leadtgt" in blob and "todo" in blob and "dynfuzz" in blob, "LEAD -> ledger `todo` (not real); clean -> no ledger")
check("good_eth" not in blob, "clean target did NOT get a ledger entry")

print(f"\n{_p} passed, {_f} failed")
sys.exit(1 if _f else 0)
