#!/usr/bin/env python3
"""labcore.py - Layer 1 of the platform: operations over the lab-state CONTRACT
(research/platform/DESIGN-platform.md).

Read ops re-derive from labstate (the read-through projection). The one WRITE op (record_verdict) goes to
the UNDERLYING ledger; the next read re-derives it - lab-state.json is never written directly. Both frontends
(MCP server, web HTTP bridge) call this one module, so they can never drift. Pure where it can be: every read
takes an optional pre-built `s=` state for isolated testing.

Stdlib only. Reuses labstate.build (reads) + ledger.add (the single mutation).
"""
import datetime
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import labstate
import ledger

VERDICTS = {"fp", "known", "wontfix", "real", "todo"}   # ledger's verdict vocabulary


def state():
    """The full lab-state (generate-on-read; sub-100ms)."""
    return labstate.build()


def _col(t):
    """Pipeline column for a target: REAL/DIG straight; CLEAN splits to PARK/SKIP/CLEAN via disposition."""
    if t["status"] in ("REAL", "DIG"):
        return t["status"]
    return (t.get("disposition") or "clean").upper()


def pipeline(s=None):
    s = s or state()
    by = {}
    for t in s["targets"]:
        c = _col(t)
        by[c] = by.get(c, 0) + 1
    return {"targets": len(s["targets"]), "by_stage": by, "findings": len(s["findings"]),
            "parked": len(s["parked"]), "repos": len(s["repos"]), "metrics": s["metrics"]}


def targets(status=None, zone=None, fork=None, chain=None, sensitivity=None, s=None):
    """Filtered targets (filters AND together; all optional)."""
    s = s or state()
    out = []
    for t in s["targets"]:
        if status and t["status"] != status.upper():
            continue
        if sensitivity and t.get("sensitivity") != sensitivity:
            continue
        if fork and (t.get("fork_base") or "") != fork:
            continue
        if zone and zone.lower() not in [z.lower() for z in t.get("zones", [])]:
            continue
        if chain and chain.lower() not in [c.lower() for c in t.get("chains", [])]:
            continue
        out.append(t)
    return out


def target(tid, s=None):
    """One target by id or name (full detail incl. verdicts)."""
    s = s or state()
    tid_l = (tid or "").lower()
    return next((t for t in s["targets"] if t["id"] == tid or (t.get("name") or "").lower() == tid_l), None)


def next_dig(s=None):
    """The actionable backlog ranked for work: REAL before DIG, then oldest-lastupdated first (unattended
    floats up). Returns the next one + the top of the queue."""
    s = s or state()
    digs = [t for t in s["targets"] if t["status"] in ("REAL", "DIG")]
    digs.sort(key=lambda t: (0 if t["status"] == "REAL" else 1, t.get("lastupdated") or ""))
    slim = [{"id": t["id"], "name": t["name"], "status": t["status"], "zones": t.get("zones", []),
             "fork_base": t.get("fork_base"), "lastupdated": t.get("lastupdated")} for t in digs]
    return {"next": slim[0] if slim else None, "queue": slim[:10], "total": len(digs)}


def findings(s=None):
    return (s or state())["findings"]


def parked(s=None):
    return (s or state())["parked"]


def radars(s=None):
    return (s or state())["radars"]


def metrics(s=None):
    return (s or state())["metrics"]


def repos(s=None):
    return (s or state())["repos"]


def record_verdict(target, verdict, reason, detector="manual", file="(labcore)", line=0, snippet="",
                   date=None, path=None):
    """MUTATION: write a triage verdict to the UNDERLYING ledger (not lab-state.json); the next read
    re-derives it into targets[].verdicts. verdict in {fp,known,wontfix,real,todo}. `path` for tests."""
    if verdict not in VERDICTS:
        raise ValueError(f"verdict must be one of {sorted(VERDICTS)} (got {verdict!r})")
    if not target or not reason:
        raise ValueError("target and reason are required")
    date = date or datetime.date.today().isoformat()
    kw = {"path": path} if path else {}
    sig = ledger.add(target, file, line, detector, snippet, verdict, reason, date, **kw)
    return {"ok": True, "sig": sig, "target": target, "verdict": verdict, "date": date}
