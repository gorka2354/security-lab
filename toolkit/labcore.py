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
import glob
import os
import re
import shutil
import subprocess
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import labstate
import ledger

VERDICTS = {"fp", "known", "wontfix", "real", "todo"}   # ledger's verdict vocabulary
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _autosync():
    """Push hunt outputs to the always-on mini-PC dashboard right after a finding/verdict is logged, so the
    Tailscale dashboard reflects it with no manual step. OPT-IN via SECLAB_AUTOSYNC=1 (kept off in tests/CI and
    on the stand itself, so those never shell out to SSH).

    SYNCHRONOUS by design: a detached background child does not survive the short-lived shells we record from
    (the runner kills the process tree on command exit), so we run sync-stand.sh inline with a timeout. It is
    fast (~2-3s: tar ~12 small files + a remote lab-state rebuild) and best-effort -- an offline stand or any
    error is swallowed (the finding is already saved locally; a later `sync-stand.sh` is the catch-all). No
    debounce: each record re-tars the CURRENT file state, so a burst's LAST sync always carries the full set."""
    if not os.environ.get("SECLAB_AUTOSYNC"):
        return
    try:
        # resolve a real bash: a bare "bash" on Windows resolves to System32 WSL bash (can't run this script);
        # shutil.which finds Git Bash, and on the stand it finds /usr/bin/bash. Relative script path + cwd avoids
        # backslash-path issues in Git Bash.
        bash = shutil.which("bash")
        for c in (r"C:\Program Files\Git\usr\bin\bash.exe", r"C:\Program Files\Git\bin\bash.exe"):
            if not bash and os.path.exists(c):
                bash = c
        if not bash:
            return
        subprocess.run([bash, "toolkit/sync-stand.sh"], cwd=_ROOT, stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=45, check=False)
    except Exception:
        pass


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


def _fnorm(x):
    return re.sub(r"[^a-z0-9]", "", (x or "").lower())


def _keymatch(a, b):
    """Fuzzy target<->poc/watch key match: equal / substring / shared >=6-char prefix (krystal<->krystal-vault)."""
    na, nb = _fnorm(a), _fnorm(b)
    if not na or not nb:
        return False
    return na == nb or na in nb or nb in na or (len(na) >= 6 and len(nb) >= 6 and na[:6] == nb[:6])


def watch_events(n=30):
    """Recent change-events from the watch monitor (monitor/watch-events.json), newest first -> browser/TG alerts."""
    ev = labstate.load(os.path.join(labstate.ROOT, "monitor", "watch-events.json"), [])
    if not isinstance(ev, list):
        ev = []
    return sorted(ev, key=lambda e: e.get("ts", ""), reverse=True)[:int(n or 30)]


def finding_detail(key):
    """Rich per-finding detail for the dashboard detail card: the FINDING.md write-up (bugs+fixes+source) +
    the live watch snapshot + recent change-events for the target. Lazy (not baked into lab-state)."""
    root = labstate.ROOT
    out = {"key": key, "finding_md": None, "poc_path": None, "liveness": None, "watch_target": None, "events": []}
    for p in sorted(glob.glob(os.path.join(root, "*-poc", "FINDING.md"))):
        d = os.path.basename(os.path.dirname(p))[:-4] if os.path.basename(os.path.dirname(p)).endswith("-poc") \
            else os.path.basename(os.path.dirname(p))
        if _keymatch(d, key):
            out["poc_path"] = os.path.relpath(p, root).replace("\\", "/")
            try:
                with open(p, encoding="utf-8") as f:
                    out["finding_md"] = f.read()
            except Exception:
                pass
            break
    # a saved disclosure draft ("Письмо команде"), if the researcher composed one
    out["draft_md"], out["draft_path"] = None, None
    for dp in (sorted(glob.glob(os.path.join(root, "*-poc", "DISCLOSURE.md")))
               + sorted(glob.glob(os.path.join(root, "disclosures", "*.md")))):
        par = os.path.basename(os.path.dirname(dp))
        d = par[:-4] if par.endswith("-poc") else os.path.basename(dp)[:-3].replace("-DISCLOSURE", "")
        if _keymatch(d, key):
            out["draft_path"] = os.path.relpath(dp, root).replace("\\", "/")
            try:
                out["draft_md"] = open(dp, encoding="utf-8").read()
            except Exception:
                pass
            break
    ws = labstate.load(os.path.join(root, "monitor", "watch-state.json"), {})
    wt = labstate.load(os.path.join(root, "monitor", "watch-targets.json"), [])
    we = watch_events(9999)
    wk = next((w for w in ws if _keymatch(w, key)), None)
    if wk:
        out["liveness"] = ws.get(wk)
        out["watch_target"] = next((t for t in (wt or []) if t.get("key") == wk), None)
        out["events"] = [e for e in (we or []) if _keymatch(e.get("key", ""), wk)][-10:]
    return out


def _poc_dir_for(key):
    """The *-poc directory whose name fuzzy-matches a target key (where its DISCLOSURE.md draft lives)."""
    for p in sorted(glob.glob(os.path.join(labstate.ROOT, "*-poc"))):
        d = os.path.basename(p)
        if _keymatch(d[:-4] if d.endswith("-poc") else d, key):
            return p
    return None


def discover_contact(target):
    """On-demand disclosure-contact discovery (dashboard 'Найти контакт' button): run contacts.py for the
    target's links.json key, then return the freshly-cached contact record. Discovery only -- never sends."""
    if not target:
        raise ValueError("target required")
    root = labstate.ROOT
    links = labstate.load(os.path.join(root, "monitor", "links.json"), {})
    lk = next((k for k in links if not k.startswith("_") and isinstance(links[k], dict) and _keymatch(k, target)), None)
    if lk:
        try:
            subprocess.run([sys.executable, os.path.join(os.path.dirname(__file__), "contacts.py"), "--target", lk],
                           capture_output=True, text=True, timeout=30)
        except Exception:
            pass
    cache = labstate.load(os.path.join(root, "monitor", "contacts.json"), {})
    hit = next((cache[k] for k in cache
                if not k.startswith("_") and isinstance(cache[k], dict) and _keymatch(k, target)), {})
    return {"ok": True, "target": target, "contacts": hit,
            "note": None if lk else "no github/website for this target -> add one in monitor/links.json first"}


def save_draft(target, subject, body):
    """Persist a composed disclosure draft to <poc>/DISCLOSURE.md (or disclosures/<key>-DISCLOSURE.md if the
    target has no PoC dir). DRAFT ONLY -- writes a local file; the researcher sends it. Never emails/submits."""
    if not target:
        raise ValueError("target required")
    root = labstate.ROOT
    pd = _poc_dir_for(target)
    if pd:
        path = os.path.join(pd, "DISCLOSURE.md")
    else:
        os.makedirs(os.path.join(root, "disclosures"), exist_ok=True)
        safe = re.sub(r"[^a-z0-9._-]", "-", (target or "").lower())[:60] or "target"
        path = os.path.join(root, "disclosures", safe + "-DISCLOSURE.md")
    hdr = ("<!-- security-lab disclosure DRAFT -- target: %s -- %s -- the researcher reviews & SENDS; "
           "this tool never emails/submits -->\n\n" % (target, datetime.date.today().isoformat()))
    with open(path, "w", encoding="utf-8") as f:
        f.write(hdr + ("Subject: %s\n\n" % subject if subject else "") + (body or "") + "\n")
    return {"ok": True, "target": target, "path": os.path.relpath(path, root).replace("\\", "/")}


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
    _autosync()
    return {"ok": True, "sig": sig, "target": target, "verdict": verdict, "date": date}


def record_finding(target, title, sev="?", file="", line=0, status="drafted", channel="direct",
                   notes="", date=None, kind="live", also_verdict=True, rebuild=True):
    """ONE-STEP finding log: a calibration finding (-> dashboard Findings panel) + a ledger verdict=real
    (-> the target shows REAL in the pipeline) + a registry rebuild (-> the target appears). Closes the gap
    where logging a finding took three manual steps. status in calibrate.FINDING_STATUS (drafted/disclosed/
    accepted/disputed/...); kind in {live, non-live} (Gate-0 class). also_verdict/rebuild toggle side effects."""
    import calibrate
    if not target or not title:
        raise ValueError("target and title are required")
    if kind and kind not in calibrate.FINDING_KIND:
        raise ValueError(f"kind must be one of {calibrate.FINDING_KIND} (got {kind!r})")
    date = date or datetime.date.today().isoformat()
    a = types.SimpleNamespace(target=target, title=title, sev=sev, channel=channel, file=file, line=line,
                              status=status, kind=kind, bounty_expected=0, date=date, notes=notes)
    calibrate.finding_add(a)                                  # -> calibration.json (the Findings panel)
    if also_verdict:
        ledger.add(target, file or "(finding)", int(line or 0), "manual", "", "real", title, date)  # -> REAL
    if rebuild:
        try:
            subprocess.run([sys.executable, os.path.join(os.path.dirname(__file__), "registry.py")],
                           capture_output=True, text=True, timeout=120)
        except Exception:
            pass
    _autosync()
    return {"ok": True, "target": target, "title": title, "sev": sev, "kind": kind, "status": status,
            "date": date}
