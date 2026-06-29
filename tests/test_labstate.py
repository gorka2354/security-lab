#!/usr/bin/env python3
"""Golden tests for the lab-state CONTRACT (toolkit/labstate.py) — Layer 0 of the platform.

Same style as the other suites: pure asserts, no pytest, exits 1 on any fail (CI-friendly).

    python tests/test_labstate.py

Pins the field->source JOIN map from research/platform/DESIGN-platform.md: targets (status preserved incl.
SKIP-as-disposition, verdicts JOINed by norm_key, sensitivity), findings=calibration lifecycle, parked=
watchlist, repos=repos x secrets-seen, radar counts vs fresh-delta, metrics=pure-fns (and NO hitrate).
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "toolkit"))
import labstate as L   # noqa: E402

_p, _f = 0, 0


def check(cond, msg):
    global _p, _f
    if cond:
        _p += 1
    else:
        _f += 1
        print("  FAIL:", msg)


def _write(root, rel, obj):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    if isinstance(obj, str):
        open(p, "w", encoding="utf-8").write(obj)
    else:
        json.dump(obj, open(p, "w", encoding="utf-8"))


def _fixture(root):
    _write(root, "monitor/registry.json", {"targets": {
        "twyne": {"key": "twyne", "name": "Twyne", "status": "DIG", "zones": ["lending"], "chains": ["eth"],
                  "fork_base": "euler", "owasp_classes": ["SC02"], "sources": ["fanout"],
                  "firstseen": "2026-06-01", "lastupdated": "2026-06-02", "last_reason": "[PARK/x] watch"},
        "foo":   {"key": "foo", "name": "Foo", "status": "CLEAN", "zones": [], "chains": [], "fork_base": None,
                  "owasp_classes": [], "sources": ["defillama"], "firstseen": "2026-06-01",
                  "lastupdated": "2026-06-01", "last_reason": "[SKIP/y] unreachable"}}})
    # ledger in the {single key: [entries]} wrapper shape (the real triage-ledger.json shape)
    _write(root, "toolkit/triage-ledger.json", {"entries": [
        {"target": "Twyne (twyne-contracts-v1)", "detector": "sibling", "verdict": "fp",
         "reason": "[PARK/x] euler sibling", "date": "2026-06-02"}]})
    _write(root, "toolkit/calibration.json", {
        "findings": [{"id": "f1", "target": "twyne", "status": "accepted", "sev_claimed": "high",
                      "sev_awarded": "high", "bounty_received": 5000},
                     {"id": "f2", "target": "foo", "status": "withdrawn", "sev_claimed": "med"}],
        "calibrations": [{"result": "TP"}, {"result": "FN"}]})
    _write(root, "monitor/watchlist.json", {"findings": [{"id": "w1", "title": "Vena oracle", "fire_means": "bounty"}]})
    _write(root, "monitor/repos.json", {"repos": [{"slug": "a/b", "protocol": "P", "chain": "eth",
                                                   "source": "immunefi", "bounty": 1000}]})
    _write(root, "monitor/secrets-seen.json", {"a/b": {"keys": ["k1", "k2"], "sha": "deadbeef"}})
    _write(root, "monitor/radar-seen.json", {"bounties": {"x": 1}, "impls": {"a": 1, "b": 2}})
    _write(root, "monitor/freshfeed-seen.json", {"defillama": ["p1", "p2", "p3"]})
    _write(root, "monitor/deployers.json", {"deployers": [{"addr": "0x1"}, {"addr": "0x2"}]})
    _write(root, "hunts/_radar/QUEUE.md", "# Q\n\n**All quiet** - nothing\n")
    _write(root, "hunts/_radar/FRESH-DEPLOY.md", "# F\n\n### newdeploy on chain 1\n- contract: 0xabc\n")


print("== labstate.build: contract shape + JOIN map ==")
with tempfile.TemporaryDirectory() as d:
    _fixture(d)
    s = L.build(root=d, today="2026-06-29")
    check(s["version"] == 1 and s["generated"] == "2026-06-29", "version + generated stamped")
    check(set(s) >= {"targets", "findings", "parked", "repos", "radars", "metrics"}, "all contract sections present")

    tw = next(t for t in s["targets"] if t["id"] == "twyne")
    foo = next(t for t in s["targets"] if t["id"] == "foo")
    check(tw["status"] == "DIG" and foo["status"] == "CLEAN", "registry status preserved verbatim")
    check(foo["disposition"] == "skip" and tw["disposition"] == "park", "disposition recovered from [TAG/..] last_reason")
    check(tw["sensitivity"] == "high" and foo["sensitivity"] == "normal", "DIG/REAL -> sensitivity high (sanitize seam)")
    check(len(tw["verdicts"]) == 1 and tw["verdicts"][0]["verdict"] == "fp",
          "verdicts JOINed by norm_key (ledger 'Twyne (..)' -> registry 'twyne')")

    check([f["id"] for f in s["findings"]] == ["f1", "f2"] and s["findings"][0]["sev_awarded"] == "high",
          "findings = calibration.json lifecycle (sev/bounty carried, not a lossy enum)")
    check(s["parked"][0]["id"] == "w1" and s["parked"][0]["fire_means"] == "bounty", "parked = watchlist findings")

    r = s["repos"][0]
    check(r["slug"] == "a/b" and r["head_sha"] == "deadbeef" and r["leaks"] == 2,
          "repos = repos.json x secrets-seen (head_sha + leaks=len(keys) from seen)")

    rd = s["radars"]
    check(rd["queue"]["impl_upgrades"] == 2 and rd["queue"]["bounty_launches"] == 1, "radar counts from *-seen.json")
    check(rd["freshfeed"]["seen"] == 3 and rd["secrets"]["repos"] == 1 and rd["secrets"]["leaks"] == 2,
          "freshfeed/secrets durable counts")
    check(rd["queue"]["fresh_items"] == [], "QUEUE 'All quiet' -> no fresh items")
    check(len(rd["freshdeploy"]["fresh_items"]) == 1, "FRESH-DEPLOY '### ' delta parsed from the .md")

    m = s["metrics"]
    check(m["precision"]["accepted"] == 1 and m["precision"]["decided"] == 2 and m["precision"]["value"] == 0.5,
          "precision from calibrate.precision_stats (1 accepted / 2 decided)")
    check(m["recall"]["caught"] == 1 and m["recall"]["total"] == 2 and m["recall"]["value"] == 0.5,
          "recall from calibrate.recall_stats (1 TP / 1 FN)")
    check("hitrate" not in m, "hitrate dropped (no implementation exists)")

print("== _ledger_rows handles every top-level shape ==")
check(L._ledger_rows([{"target": "x"}]) == [{"target": "x"}], "bare list")
check(L._ledger_rows({"entries": [{"target": "x"}]}) == [{"target": "x"}], "{entries:[...]}")
check(L._ledger_rows({"only": [{"target": "x"}]}) == [{"target": "x"}], "single list-valued wrapper")
check(L._ledger_rows({"sigA": {"target": "x"}}) == [{"target": "x"}], "{sig: entry} map")
check(L._ledger_rows({}) == [], "empty -> []")

print("== helpers ==")
check(L._disposition("[SKIP/wave] foo") == "skip" and L._disposition("no tag") is None, "_disposition")

print(f"\n{_p} passed, {_f} failed")
sys.exit(1 if _f else 0)
