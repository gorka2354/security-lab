#!/usr/bin/env python3
"""analyze.py - L2: our heuristics (recon.py) + Slither (AST/dataflow).

    python analyze.py <repo> [--out report.md]

Always runs our custom detectors. Additionally runs Slither IF it is installed
and the target compiles. Slither needs a working solc toolchain, which is fiddly
on Windows -> the canonical home for the Slither pass is Linux/CI
(see .github/workflows/analyze.yml). Without Slither it degrades gracefully to
recon-only. ASCII output.
"""

import argparse
import json
import os
import shutil
import subprocess

import recon  # reuse our detectors (same folder)

MARK = {0: "[!]", 1: "[.]", 2: "[ ]"}


def run_recon(repo):
    files = list(recon.iter_sol(repo))
    res = {t: [] for t, _, _ in recon.DETECTORS}
    for path in files:
        rel = os.path.relpath(path, repo).replace("\\", "/")
        try:
            text = open(path, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        for title, fn, _ in recon.DETECTORS:
            res[title].extend(fn(text, rel))
    return files, res


def run_slither(repo):
    """Returns (findings, error). findings is a list of (impact, check, loc, desc)."""
    if not shutil.which("slither"):
        return None, "slither not on PATH (pip install slither-analyzer; needs solc)"
    try:
        p = subprocess.run(["slither", repo, "--json", "-"],
                           capture_output=True, text=True, timeout=900)
    except Exception as e:
        return None, f"slither failed to run: {e}"
    try:
        data = json.loads(p.stdout)
    except Exception:
        return None, "could not parse slither JSON (did the target compile?)"
    if not data.get("results"):
        return None, "slither produced no results (compile/deps issue?)"
    out = []
    for d in data["results"].get("detectors", []):
        impact = d.get("impact", "?")
        if impact in ("Informational", "Optimization"):
            continue
        loc = "?"
        els = d.get("elements", [])
        if els:
            sm = els[0].get("source_mapping", {})
            loc = f"{sm.get('filename_relative', '?')}:{(sm.get('lines') or ['?'])[0]}"
        desc = (d.get("description", "") or "").strip().splitlines()
        out.append((impact, d.get("check", ""), loc, desc[0][:120] if desc else ""))
    return out, None


def main():
    ap = argparse.ArgumentParser(description="L2 analyzer: recon heuristics + Slither")
    ap.add_argument("repo")
    ap.add_argument("--out")
    ap.add_argument("--top", type=int, default=20)
    args = ap.parse_args()

    files, recon_res = run_recon(args.repo)
    slither_res, slither_err = run_slither(args.repo)

    L = [f"# Analyze report: {os.path.basename(os.path.abspath(args.repo))}",
         f"\nScanned {len(files)} .sol files (recon) + Slither (AST/dataflow). Triage only.\n"]

    L.append("## Slither (AST/dataflow) - High/Medium impact")
    if slither_res is None:
        L.append(f"  [skipped] {slither_err}")
    elif not slither_res:
        L.append("  (no High/Medium findings)")
    else:
        order = {"High": 0, "Medium": 1, "Low": 2}
        for impact, check, loc, desc in sorted(slither_res, key=lambda x: order.get(x[0], 3)):
            L.append(f"- [{impact}] `{loc}` {check} - {desc}")

    for title, _, why in recon.DETECTORS:
        hits = sorted(recon_res[title], key=lambda h: h[4])
        shown = [h for h in hits if h[4] <= 1][:args.top] or hits[:args.top]
        L.append(f"\n## {title}  ({len(hits)})\n_{why}_")
        if not hits:
            L.append("  (none)")
            continue
        for rel, ln, snip, note, prio in shown:
            L.append(f"- {MARK[prio]} `{rel}:{ln}` - {note}")
        rest = len(hits) - len(shown)
        if rest:
            L.append(f"  ... and {rest} more")

    report = "\n".join(L)
    print(report)
    if args.out:
        open(args.out, "w", encoding="utf-8").write(report)
        print(f"\n[written to {args.out}]")


if __name__ == "__main__":
    main()
