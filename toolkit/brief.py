#!/usr/bin/env python3
"""brief.py — the session-start briefing. One command that answers "what's the state, what's fresh,
what do I do" so we skip the manual morning ritual (pull -> read QUEUE -> contests -> open DIGs -> git).

    python toolkit/brief.py            # fast, local only
    python toolkit/brief.py --fetch    # also git-fetch origin (network) for ahead/behind
    python toolkit/brief.py --contests # also check live audit-contests (network)

Reads what we already record: git, monitor/registry.json, hunts/_radar/QUEUE.md, monitor/watchlist.json,
monitor/ALERTS.md, hunts/_fanout/. Stdlib only. Designed to be the first thing run each session
(optionally wired to a Claude Code SessionStart hook)."""

import argparse
import glob
import json
import os
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def sh(*args):
    try:
        return subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=30).stdout.strip()
    except Exception:
        return ""


def load(path, default):
    p = os.path.join(ROOT, path)
    if os.path.exists(p):
        try:
            return json.load(open(p, encoding="utf-8"))
        except Exception:
            pass
    return default


def section(title):
    print(f"\n\033[1m{title}\033[0m" if sys.stdout.isatty() else f"\n{title}")


def git_block(do_fetch):
    branch = sh("git", "rev-parse", "--abbrev-ref", "HEAD") or "?"
    if do_fetch:
        sh("git", "fetch", "origin", "-q")
    upstream = sh("git", "rev-parse", "--abbrev-ref", "@{u}") or "origin/" + branch
    ahead = sh("git", "rev-list", "--count", f"{upstream}..HEAD") or "?"
    behind = sh("git", "rev-list", "--count", f"HEAD..{upstream}") or "?"
    dirty = sh("git", "status", "--porcelain")
    dirty_n = len([l for l in dirty.splitlines() if l.strip()])
    section("GIT")
    msg = f"  {branch} | {ahead} unpushed, {behind} behind {upstream}"
    if ahead not in ("0", "?"):
        msg += "  -> consider `git push`"
    if dirty_n:
        msg += f" | {dirty_n} uncommitted file(s)"
    print(msg + ("" if do_fetch else "   (run --fetch for true ahead/behind)"))


def radar_block():
    section("RADAR  (hunts/_radar/QUEUE.md — fresh, in-context work)")
    q = os.path.join(ROOT, "hunts", "_radar", "QUEUE.md")
    if not os.path.exists(q):
        print("  (no QUEUE.md yet — radar not seeded)")
        return
    body = open(q, encoding="utf-8").read()
    if "All quiet" in body or "baseline seeded" in body:
        print("  all quiet — no impl-upgrades or new bounties on our triaged targets")
    else:
        # print the NEW change headers
        hits = [l.strip() for l in body.splitlines() if l.strip().startswith("### [")]
        n = sum(1 for l in body.splitlines() if "NEW change" in l)
        print(f"  >>> FRESH: {len(hits) or n} change(s) queued — re-hunt these:")
        for h in hits[:8]:
            print(f"     {h[4:]}")
        print("     full: hunts/_radar/QUEUE.md")
    # any alerts
    a = os.path.join(ROOT, "monitor", "ALERTS.md")
    if os.path.exists(a) and os.path.getsize(a) > 0:
        last = [l for l in open(a, encoding="utf-8").read().splitlines() if l.startswith("## ")]
        if last:
            print(f"  ALERTS.md: {len(last)} alert block(s), latest: {last[-1][3:][:70]}")


def freshdeploy_block():
    p = os.path.join(ROOT, "hunts", "_radar", "FRESH-DEPLOY.md")
    if not os.path.exists(p):
        return
    body = open(p, encoding="utf-8").read()
    section("FRESH-DEPLOY  (new contracts from watched deployers/factories — the timing edge)")
    if "All quiet" in body or "baseline seeded" in body:
        wl = load("monitor/deployers.json", {}).get("deployers", [])
        print(f"  all quiet — no new deploys from {len(wl)} watched deployer(s)")
    else:
        hits = [l.strip() for l in body.splitlines() if l.strip().startswith("### ")]
        print(f"  >>> {len(hits)} NEW deploy(s) — dig the verified ones FIRST:")
        for h in hits[:6]:
            print(f"     {h[4:]}")
        print("     full: hunts/_radar/FRESH-DEPLOY.md")


def freshfeed_block():
    p = os.path.join(ROOT, "hunts", "_radar", "FRESH-FEED.md")
    if not os.path.exists(p):
        return
    body = open(p, encoding="utf-8").read()
    section("FRESH-FEED  (new DefiLlama-listed + Sourcify-verified code — wide freshness net)")
    if "baseline seeded" in body or "All quiet" in body:
        print("  all quiet — no new fresh-listed/verified code this run")
    else:
        prot = [l[2:].strip() for l in body.splitlines() if l.startswith("- **")][:6]
        print("  >>> fresh code surfaced (read hunts/_radar/FRESH-FEED.md):")
        for x in prot:
            print(f"     {x[:92]}")


def registry_block():
    reg = load("monitor/registry.json", {}).get("targets", {})
    if not reg:
        print("\nREGISTRY  (run `python toolkit/registry.py` to build)")
        return
    digs = [t for t in reg.values() if t.get("status") in ("DIG", "REAL")]
    section(f"OPEN BACKLOG  ({len(digs)} DIG/REAL of {len(reg)} triaged — actionable, already-sourced)")
    digs.sort(key=lambda t: (0 if t["status"] == "REAL" else 1, t["key"]))
    for t in digs[:10]:
        z = ",".join(t.get("zones", [])[:2]) or "-"
        fk = f" fork:{t['fork_base']}" if t.get("fork_base") else ""
        ch = ",".join(t.get("chains", [])[:2])
        print(f"  [{t['status']}] {t['name'][:34]:34} {z}{fk}" + (f"  ({ch})" if ch else ""))
    if len(digs) > 10:
        print(f"  ... +{len(digs) - 10} more (see monitor/REGISTRY.md)")
    # fork families for batch-CVE awareness
    forks = {}
    for t in reg.values():
        if t.get("fork_base"):
            forks.setdefault(t["fork_base"], 0)
            forks[t["fork_base"]] += 1
    fam = ", ".join(f"{b}x{n}" for b, n in sorted(forks.items(), key=lambda kv: -kv[1]) if n > 1)
    if fam:
        print(f"  fork-families (1 upstream CVE -> rescan all): {fam}")


def parked_block():
    wl = load("monitor/watchlist.json", {}).get("findings", [])
    if wl:
        section(f"PARKED  ({len(wl)} real leads watching for a bounty/contest launch)")
        for f in wl:
            print(f"  {f.get('id')}: {f.get('title','')[:80]}")


def fanout_block():
    tables = sorted(glob.glob(os.path.join(ROOT, "hunts", "_fanout", "*.md")))
    if tables:
        section("LAST FAN-OUT")
        print(f"  {os.path.basename(tables[-1])}  (+{len(tables)-1} older)")


def contests_block():
    section("LIVE CONTESTS (timing edge)")
    out = sh(sys.executable, "toolkit/contest_monitor.py", "--fresh-hours", "96")
    line = next((l for l in out.splitlines() if "live" in l.lower()), out.splitlines()[0] if out else "?")
    print("  " + line.strip().lstrip("# "))


def main():
    ap = argparse.ArgumentParser(description="Session-start briefing")
    ap.add_argument("--fetch", action="store_true", help="git-fetch origin for true ahead/behind (network)")
    ap.add_argument("--contests", action="store_true", help="also check live audit-contests (network)")
    a = ap.parse_args()
    today = sh("date", "+%Y-%m-%d") or ""
    title = f"=== security-lab brief  {today} ==="
    print("\033[1m" + title + "\033[0m" if sys.stdout.isatty() else title)
    git_block(a.fetch)
    radar_block()
    freshdeploy_block()
    freshfeed_block()
    registry_block()
    parked_block()
    fanout_block()
    if a.contests:
        contests_block()
    section("NEXT")
    print("  1) read hunts/_radar/QUEUE.md if FRESH  2) pick a DIG above  3) `scout.py` a fresh wave")
    print("  (network checks: --fetch for git ahead/behind, --contests for live contests)")


if __name__ == "__main__":
    main()
