#!/usr/bin/env python3
"""fingerprint.py - FAST "is a KNOWN bug live in this code?" check.

The slow part of a hunt is deciding whether a new target that LOOKS like a family we've seen actually carries
the bug (the death.fun-vs-ApeChurch lesson: same game, different architecture -> bug structurally absent).
This turns each CONFIRMED finding of ours (monitor/fingerprints.json) into a discriminator:

  relevant = ALL patterns that must be present for the bug CLASS to apply. Missing -> N/A (structurally
             impossible here, instant refute -- exactly how ApeChurch DeathFun was cleared: no increaseBet).
  guard    = ANY fix pattern that, if present, means the bug is MITIGATED -> SAFE.
  relevant AND no guard -> VULN?  (a fast lead; confirm by hand / PoC).

    python toolkit/fingerprint.py <src-dir>          # check a fetched/cloned target vs every fingerprint
    python toolkit/fingerprint.py <src-dir> --family gambling
    python toolkit/fingerprint.py --list

Add a fingerprint each time we confirm a real bug -> every future similar target is auto-checked (compounds,
like recon detectors + testmine). Pure verdict() -> golden-tested. Stdlib only.
"""
import argparse
import json
import os
import re

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LIB = "monitor/fingerprints.json"

# dependency / non-own-code paths -> skip (a guard in OZ shouldn't mark the target safe)
_SKIP = re.compile(r"(@openzeppelin|@layerzero|node_modules|/lib/|forge-std|solmate|solady|/test/|\.t\.sol"
                   r"|mock|/script/|/broadcast/|/interfaces?/|[A-Za-z0-9]Interface\.sol)", re.I)


def load(path=None):
    p = path or os.path.join(ROOT, LIB)
    return (json.load(open(p, encoding="utf-8")).get("fingerprints") or [])


def verdict(text, fp):
    """Pure: one file's text vs one fingerprint -> 'n/a' | 'safe' | 'vuln?'. Unit-tested."""
    if not all(re.search(p, text) for p in fp.get("relevant", [])):
        return "n/a"                       # preconditions absent -> the bug can't structurally apply here
    if any(re.search(g, text) for g in fp.get("guard", [])):
        return "safe"                      # a mitigation is present -> not the vulnerable shape
    return "vuln?"                          # relevant + unguarded -> fast lead, confirm by hand


def _own_sol(src):
    out = []
    for cur, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "lib", "out", "cache")]
        for f in files:
            if not f.endswith(".sol"):
                continue
            rel = os.path.relpath(os.path.join(cur, f), src).replace("\\", "/")
            if _SKIP.search("/" + rel):
                continue
            out.append((rel, os.path.join(cur, f)))
    return out


def scan(src, fps):
    """Per (own file, fingerprint) -> verdict. Returns {fp_id: {'verdict': best, 'files': {rel: v}}}
    where best = vuln? > safe > n/a (the strongest signal across files)."""
    order = {"vuln?": 2, "safe": 1, "n/a": 0}
    res = {fp["id"]: {"fp": fp, "verdict": "n/a", "files": {}} for fp in fps}
    for rel, path in _own_sol(src):
        try:
            text = open(path, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        for fp in fps:
            v = verdict(text, fp)
            if v != "n/a":
                res[fp["id"]]["files"][rel] = v
            if order[v] > order[res[fp["id"]]["verdict"]]:
                res[fp["id"]]["verdict"] = v
    return res


_MARK = {"vuln?": "[!] VULN?", "safe": "[.] safe ", "n/a": "[ ] n/a  "}


def main():
    ap = argparse.ArgumentParser(description="Fast known-bug liveness check (fingerprints vs a target)")
    ap.add_argument("src", nargs="?", help="target source dir (fetched/cloned)")
    ap.add_argument("--family", help="only run fingerprints of this family (oracle/gambling/pause/...)")
    ap.add_argument("--list", action="store_true", help="list the fingerprint library")
    a = ap.parse_args()
    fps = load()
    if a.family:
        fps = [f for f in fps if f.get("family") == a.family]
    if a.list or not a.src:
        print(f"# {len(fps)} fingerprint(s) (confirmed-finding liveness checks):")
        for f in fps:
            print(f"  {f['id']:32} [{f.get('family','?')}]  {f.get('desc','')[:70]}")
            print(f"      from: {f.get('finding','?')}")
        return
    res = scan(a.src, fps)
    hits = [r for r in res.values() if r["verdict"] == "vuln?"]
    safe = [r for r in res.values() if r["verdict"] == "safe"]
    print(f"# fingerprint scan: {os.path.basename(a.src.rstrip('/'))}  ({len(fps)} fingerprints)")
    for r in res.values():
        v = r["verdict"]
        loc = ("  ".join(f"{f}:{fv}" for f, fv in list(r["files"].items())[:3])) if r["files"] else ""
        print(f"  {_MARK[v]}  {r['fp']['id']:30}  {loc}")
    if hits:
        print(f"\n>>> {len(hits)} VULN? lead(s) -> confirm by hand:")
        for r in hits:
            print(f"    {r['fp']['id']}: {r['fp'].get('desc','')}")
    else:
        print(f"\n>>> no known-bug matches ({len(safe)} guarded/safe, rest N/A -> structurally absent). "
              f"This target does not carry our catalogued bugs.")


if __name__ == "__main__":
    main()
