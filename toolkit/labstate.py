#!/usr/bin/env python3
"""labstate.py - Layer 0 of the platform: the lab-state CONTRACT (research/platform/DESIGN-platform.md).

Re-derives monitor/lab-state.json as a READ-THROUGH projection: an explicit JOIN over the already-derived
caches (registry.json, triage-ledger, calibration, watchlist, repos x secrets-seen, radar/freshfeed/deployers
seen, calibrate pure-fns). It sits ABOVE the existing derivers - never re-runs them, never a new store.
lab-state.json is generated-on-read (sub-100ms) and must NEVER be hand-edited; mutations go to the underlying
store (ledger/watchlist) and then a re-derive picks them up.

    python toolkit/labstate.py            # write monitor/lab-state.json (+ one-line summary)
    python toolkit/labstate.py --print    # print the state to stdout, don't write

Stdlib only. Reuses registry.norm_key (target JOIN) + calibrate.precision_stats/recall_stats (metrics).
"""
import argparse
import datetime
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import registry as R          # norm_key: stable target JOIN key
try:
    import calibrate          # precision_stats / recall_stats (pure)
except Exception:
    calibrate = None

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCHEMA_VERSION = 1
_TAG = re.compile(r"\s*\[([A-Z]+)/")          # last_reason prefix [SKIP/..]/[PARK/..] -> disposition


def load(path, default):
    p = path if os.path.isabs(path) else os.path.join(ROOT, path)
    if os.path.exists(p):
        try:
            return json.load(open(p, encoding="utf-8"))
        except Exception:
            pass
    return default


def _disposition(reason):
    m = _TAG.match(reason or "")
    return m.group(1).lower() if m else None


def _md_items(path, prefix, root=ROOT):
    """Fresh-delta items from a radar .md (live only in the .md, transiently). [] when quiet/baseline."""
    p = os.path.join(root, path)
    if not os.path.exists(p):
        return []
    body = open(p, encoding="utf-8").read()
    if "All quiet" in body or "baseline seeded" in body or "All quiet" in body:
        return []
    return [l.strip()[len(prefix):].strip() for l in body.splitlines() if l.strip().startswith(prefix)][:12]


def _ledger_rows(ledger):
    """The verdict entries, whatever the ledger's top-level shape: a bare list, {entries:[...]} /
    {verdicts:[...]}, a single {k: [...]} wrapper, or a {sig: entry} map."""
    if isinstance(ledger, list):
        return ledger
    if not isinstance(ledger, dict):
        return []
    for key in ("entries", "verdicts", "ledger"):
        if isinstance(ledger.get(key), list):
            return ledger[key]
    vals = list(ledger.values())
    if len(vals) == 1 and isinstance(vals[0], list):   # single list-valued wrapper
        return vals[0]
    return vals                                        # {sig: entry} map


def _ledger_by_target(ledger):
    """Group triage-ledger verdicts by registry norm_key (handles every ledger top-level shape)."""
    by = {}
    for e in _ledger_rows(ledger):
        if not isinstance(e, dict):
            continue
        k = R.norm_key(e.get("target", ""))
        by.setdefault(k, []).append({"detector": e.get("detector"), "verdict": e.get("verdict"),
                                     "reason": (e.get("reason") or "")[:160], "date": e.get("date")})
    return by


def build(root=ROOT, today=None):
    """The contract. Returns the lab-state dict (pure given the files on disk)."""
    today = today or datetime.date.today().isoformat()
    reg = load(os.path.join(root, "monitor/registry.json"), {"targets": {}})
    ledger = load(os.path.join(root, "toolkit/triage-ledger.json"), {})
    cal = load(os.path.join(root, "toolkit/calibration.json"), {"findings": [], "calibrations": []})
    watch = load(os.path.join(root, "monitor/watchlist.json"), {"findings": []})
    repos = load(os.path.join(root, "monitor/repos.json"), {"repos": []})
    sseen = load(os.path.join(root, "monitor/secrets-seen.json"), {})
    rseen = load(os.path.join(root, "monitor/radar-seen.json"), {"bounties": {}, "impls": {}})
    ffseen = load(os.path.join(root, "monitor/freshfeed-seen.json"), {"defillama": []})
    deployers = load(os.path.join(root, "monitor/deployers.json"), {"deployers": []})

    led_by = _ledger_by_target(ledger)

    # detect-cache: fingerprint.py --save writes per-target known-bug rechecks; JOIN by registry key
    detect_by = {}
    dc = os.path.join(root, "monitor", "detect-cache")
    if os.path.isdir(dc):
        for fn in os.listdir(dc):
            if fn.endswith(".json"):
                try:
                    detect_by[fn[:-5]] = json.load(open(os.path.join(dc, fn), encoding="utf-8"))
                except Exception:
                    pass

    # --- targets (registry is already derived from ledger; we READ it, JOIN verdicts, derive disposition) ---
    targets = []
    for k, t in (reg.get("targets") or {}).items():
        st = t.get("status")
        targets.append({
            "id": t.get("key", k), "name": t.get("name"), "status": st,
            "disposition": _disposition(t.get("last_reason")),   # SKIP/PARK folded into CLEAN by registry; recover it
            "zones": t.get("zones", []), "chains": t.get("chains", []), "fork_base": t.get("fork_base"),
            "owasp": t.get("owasp_classes", []), "sources": t.get("sources", []),
            "firstseen": t.get("firstseen"), "lastupdated": t.get("lastupdated"),
            "verdicts": led_by.get(R.norm_key(t.get("name") or k), []),
            "detect": detect_by.get(t.get("key", k)) or detect_by.get(k),   # known-bug fingerprint rechecks (if run)
            "sensitivity": "high" if st in ("DIG", "REAL") else "normal",  # mechanical sanitize seam (Inc 5)
        })

    # --- findings (AUTHORITATIVE: calibration.json lifecycle) + parked (watchlist, different shape) ---
    findings = (cal.get("findings") if isinstance(cal, dict) else []) or []
    cals = (cal.get("calibrations") if isinstance(cal, dict) else []) or []
    parked = [{"id": f.get("id"), "title": f.get("title"), "fire_means": f.get("fire_means")}
              for f in (watch.get("findings") or [])]

    # --- repos = repos.json x secrets-seen (head_sha / leaks live in seen, keyed by slug) ---
    repo_rows = []
    for r in (repos.get("repos") or []):
        s = sseen.get(r.get("slug"), {}) if isinstance(sseen, dict) else {}
        repo_rows.append({"slug": r.get("slug"), "protocol": r.get("protocol"), "chain": r.get("chain"),
                          "source": r.get("source"), "bounty": r.get("bounty"),
                          "head_sha": s.get("sha"), "leaks": len(s.get("keys", []))})

    # --- radars: durable counts from *-seen.json, fresh DELTA from the .md ---
    radars = {
        "queue": {"impl_upgrades": len(rseen.get("impls", {}) or {}),
                  "bounty_launches": len(rseen.get("bounties", {}) or {}),
                  "fresh_items": _md_items("hunts/_radar/QUEUE.md", "### ", root)},
        "freshdeploy": {"watched": len(deployers.get("deployers", []) or []),
                        "fresh_items": _md_items("hunts/_radar/FRESH-DEPLOY.md", "### ", root)},
        "freshfeed": {"seen": len(ffseen.get("defillama", []) or []),
                      "fresh_items": _md_items("hunts/_radar/FRESH-FEED.md", "- **", root)},
        "secrets": {"repos": len(repos.get("repos", []) or []),
                    "leaks": sum(len((v or {}).get("keys", [])) for v in sseen.values()) if isinstance(sseen, dict) else 0,
                    "fresh_items": _md_items("hunts/_radar/SECRETS.md", "### ", root)},
    }

    # --- metrics: calibrate pure-fns, rendered as numbers (no chart; dataset is tiny) ---
    if calibrate:
        acc, decided, pending = calibrate.precision_stats(findings)
        tp, fn = calibrate.recall_stats(cals)
    else:
        acc = decided = pending = tp = fn = []
    metrics = {
        "precision": {"accepted": len(acc), "decided": len(decided), "pending": len(pending),
                      "value": round(len(acc) / len(decided), 3) if decided else None},
        "recall": {"caught": len(tp), "total": len(tp) + len(fn),
                   "value": round(len(tp) / (len(tp) + len(fn)), 3) if (tp or fn) else None},
    }

    return {"version": SCHEMA_VERSION, "generated": today, "targets": targets, "findings": findings,
            "parked": parked, "repos": repo_rows, "radars": radars, "metrics": metrics}


def sanitize(state):
    """PUBLIC projection (Inc 5): strip everything that would tip off an ACTIVE hunt, keep the aggregate
    shape. Mechanical, driven by per-target `sensitivity`. Safe for a phone glance / any non-local exposure:
      - verdict REASONS (the exploit hypotheses) dropped on every target -> count only;
      - parked leads (active exploitable hypotheses on live unfixed contracts) -> count only, no detail;
      - findings keep the KPI (target/sev/status/bounty), drop file/line/notes;
      - repos keep slug/protocol/bounty, drop head_sha;
      - radars + metrics (aggregate) pass through.
    NOTE: even sanitized, target NAMES remain (a phone glance wants the pipeline) -> only serve over a
    token-gated LAN bridge, do NOT publish publicly. The private-boundary precondition still holds."""
    pub_targets = [{"id": t.get("id"), "name": t.get("name"), "status": t.get("status"),
                    "disposition": t.get("disposition"), "zones": t.get("zones", []),
                    "fork_base": t.get("fork_base"), "sensitivity": t.get("sensitivity"),
                    "verdicts": len(t.get("verdicts", []))}                # count only — NO reasons
                   for t in state.get("targets", [])]
    pub_findings = [{k: f.get(k) for k in ("id", "target", "sev_claimed", "sev_awarded", "status",
                                           "kind", "bounty_received")} for f in state.get("findings", [])]
    pub_repos = [{k: r.get(k) for k in ("slug", "protocol", "source", "bounty", "leaks")}
                 for r in state.get("repos", [])]
    return {"version": state.get("version"), "generated": state.get("generated"), "_public": True,
            "targets": pub_targets, "findings": pub_findings, "parked": [],
            "parked_count": len(state.get("parked", [])), "repos": pub_repos,
            "radars": state.get("radars", {}), "metrics": state.get("metrics", {})}


def main():
    ap = argparse.ArgumentParser(description="lab-state contract (read-through projection over the caches)")
    ap.add_argument("--print", action="store_true", help="print the state, don't write the file")
    ap.add_argument("--public", action="store_true",
                    help="also write monitor/lab-state-public.json (sensitivity-sanitized projection)")
    a = ap.parse_args()
    state = build()
    if a.public:
        pubp = os.path.join(ROOT, "monitor", "lab-state-public.json")
        json.dump(sanitize(state), open(pubp, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
        print(f"[labstate] monitor/lab-state-public.json (sanitized: parked->count, verdict reasons dropped)")
    if a.print:
        print(json.dumps(state, indent=1, ensure_ascii=False))
        return
    p = os.path.join(ROOT, "monitor", "lab-state.json")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    json.dump(state, open(p, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    st = state["targets"]
    n = lambda s: sum(1 for t in st if t["status"] == s)  # noqa: E731
    print(f"[labstate] monitor/lab-state.json  ::  {len(st)} targets "
          f"(REAL {n('REAL')} / DIG {n('DIG')} / CLEAN {n('CLEAN')}), "
          f"{len(state['findings'])} findings, {len(state['parked'])} parked, "
          f"{len(state['repos'])} repos, precision={state['metrics']['precision']['value']}")


if __name__ == "__main__":
    main()
