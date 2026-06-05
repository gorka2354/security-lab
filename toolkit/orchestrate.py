#!/usr/bin/env python3
"""orchestrate.py - the VOLUME engine: L1-scan many targets, rank, surface the cream.

    python toolkit/orchestrate.py [targets.txt] [--workspace DIR] [--out queue.md]

targets.txt lines: "<name>  <git-url-or-local-path>" (# comments allowed).
Clones (shallow) git URLs into the workspace; scans local paths in place. Runs
recon's detectors on each, keeps only HIGH-SIGNAL PRODUCTION leads (prio 0, not
test/mock/script), scores each target, and writes a ranked triage queue so you
(L4) deep-dive the most promising first.

Honest scope: only L1 (regex) scales to N repos. Slither/fuzzing (L2/L3) are the
SELECTIVE deep pass you run on the top-ranked targets afterwards. ASCII output.
"""

import argparse
import os
import re
import subprocess

import ledger  # same folder
import recon  # same folder

# detector weight by proven hunting value (prio-0 production leads only)
WEIGHT = {
    "sibling": 3, "supply integrity": 3, "signature": 3, "upgrade": 3,
    "reentrancy": 2, "disabled": 2, "oracle": 2, "erc4626": 2, "unchecked": 2,
    "access control leads": 1, "dangerous": 1,
}


def weight_for(title):
    t = title.lower()
    for k, w in WEIGHT.items():
        if k in t:
            return w
    return 1


def resolve(name, src, workspace):
    if re.match(r"https?://|git@", src) or src.endswith(".git"):
        dest = os.path.join(workspace, name)
        if not os.path.isdir(dest):
            os.makedirs(workspace, exist_ok=True)
            try:
                r = subprocess.run(["git", "clone", "--depth", "1", src, dest],
                                   capture_output=True, text=True, timeout=300)
            except Exception:
                return None
            if r.returncode != 0:
                return None
        return dest
    return src if os.path.isdir(src) else None


def scan(repo):
    """Per-detector list of high-signal production leads (prio 0, excl. test/mock)."""
    res = {t: [] for t, _, _ in recon.DETECTORS}
    for path in recon.iter_sol(repo):
        rel = os.path.relpath(path, repo).replace("\\", "/")
        if recon._TESTRE.search(rel):
            continue
        try:
            text = open(path, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        for title, fn, _ in recon.DETECTORS:
            for f in fn(text, rel):
                if f[4] == 0:
                    res[title].append(f)
    return res


def suppress(res, target, led):
    """Drop leads already judged fp/known/wontfix in the ledger. Mutates res in
    place, returns how many were removed. This is why noise falls every run."""
    if not led:
        return 0
    removed = 0
    for title in list(res):
        key = recon.det_key(title)
        kept = []
        for f in res[title]:
            rel, ln, snip, note, prio = f
            if ledger.is_silenced(ledger.verdict_for(led, target, rel, key, snip)):
                removed += 1
            else:
                kept.append(f)
        res[title] = kept
    return removed


def main():
    ap = argparse.ArgumentParser(description="Volume engine: scan & rank many targets")
    ap.add_argument("targets", nargs="?", default="toolkit/targets.txt")
    ap.add_argument("--workspace", default="hunts/_volume")
    ap.add_argument("--out", default="hunts/_volume/triage-queue.md")
    a = ap.parse_args()

    targets = []
    for line in open(a.targets, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            targets.append((parts[0], parts[1]))

    led = ledger.load()
    total_suppressed = 0
    rows = []
    for name, src in targets:
        repo = resolve(name, src, a.workspace)
        if not repo:
            print(f"[skip]    {name}: clone/path failed")
            continue
        res = scan(repo)
        sup = suppress(res, name, led)
        total_suppressed += sup
        score = sum(weight_for(t) * len(v) for t, v in res.items())
        rows.append((score, name, repo, res))
        tag = f"  (-{sup} suppressed by ledger)" if sup else ""
        print(f"[scanned] {name}: score {score}{tag}")

    rows.sort(key=lambda r: -r[0])

    led_note = (f" {total_suppressed} already-judged leads auto-suppressed "
                f"(ledger: {len(led)} verdicts)." if led else
                " (no ledger yet - record verdicts with toolkit/ledger.py)")
    L = ["# Volume triage queue",
         f"\n{len(rows)} targets scanned (L1, production code only)."
         + led_note +
         "\nDeep-dive (L2 Slither / L3 fuzz / L4 me) the top-ranked first.\n",
         "## Ranked targets"]
    for score, name, repo, res in rows:
        hot = sum(len(v) for v in res.values())
        L.append(f"- **{name}** - score {score}  ({hot} high-signal prod leads)")
    for score, name, repo, res in rows:
        L.append(f"\n## {name}  (score {score})")
        leads = False
        for title, _, _ in recon.DETECTORS:
            v = res[title]
            if not v:
                continue
            leads = True
            L.append(f"### {title}  ({len(v)})")
            for rel, ln, snip, note, prio in v[:8]:
                L.append(f"- `{rel}:{ln}`  `{snip}` - {note}")
            if len(v) > 8:
                L.append(f"  ... and {len(v) - 8} more")
        if not leads:
            L.append("  (no high-signal production leads)")

    report = "\n".join(L)
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    open(a.out, "w", encoding="utf-8").write(report)
    print(f"\n[queue written to {a.out}]  ({len(rows)} targets ranked)")


if __name__ == "__main__":
    main()
