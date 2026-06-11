#!/usr/bin/env python3
"""analyze.py - L2: our heuristics (recon.py) + Slither (AST/dataflow).

    python analyze.py <repo> [--out report.md]

Always runs our custom detectors. Additionally runs Slither IF it is installed
and the target compiles. The headline feature: CROSS-CORROBORATION - leads
flagged by BOTH our heuristics (L1) and Slither's dataflow (L2) at the same
spot are high-confidence and listed first.

Slither can't install on Windows (no MSVC) -> on Windows this AUTO-BRIDGES Slither to the
WSL lane (toolkit/WSL-LANE.md): recon runs locally, Slither runs in WSL, and the L1n L2
corroboration is merged -- so L2/AST is first-class in the normal flow, not WSL-only. On
Linux/CI it uses the local slither. Without either it degrades to recon-only. The target
must COMPILE (deps + a matching solc) for Slither to produce results. ASCII output.
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
        for title, leads in recon.detect_all(text, rel).items():
            res[title].extend(leads)
    return files, res


WSL_DISTRO = "Ubuntu"


def _drive_to_mnt(ap):
    """An ABSOLUTE windows path -> /mnt/<drive>/...; a posix path -> itself. PURE (no abspath, OS-independent)."""
    if len(ap) > 2 and ap[1] == ":":
        return "/mnt/" + ap[0].lower() + ap[2:].replace("\\", "/")
    return ap.replace("\\", "/")


def _win_to_wsl(p):
    """Windows path -> WSL /mnt/<drive>/... (abspath first, then translate)."""
    return _drive_to_mnt(os.path.abspath(p))


def _slither_raw(repo):
    """(raw_json_stdout, source). Local slither if on PATH (Linux/CI); else BRIDGE to the WSL venv on Windows
    (slither can't install on Windows -> toolkit/WSL-LANE.md). (None, None) if neither is available."""
    if shutil.which("slither"):
        p = subprocess.run(["slither", repo, "--json", "-"], capture_output=True, text=True,
                           errors="replace", timeout=900)
        return p.stdout, "local"
    if os.name == "nt" and shutil.which("wsl"):
        # single-line -lc command (no multi-line heredoc -> no CRLF corruption); explicit HOME (often empty in -lc)
        cmd = ('export HOME="/home/$(whoami)"; export PATH="$HOME/seclab/bin:$HOME/.foundry/bin:$PATH"; '
               f'slither "{_win_to_wsl(repo)}" --json - 2>/dev/null')
        print("  [analyze] slither not on Windows -> dispatching to the WSL lane...")
        p = subprocess.run(["wsl", "-d", WSL_DISTRO, "--", "bash", "-lc", cmd],
                           capture_output=True, text=True, errors="replace", timeout=900)
        return p.stdout, "WSL"
    return None, None


def run_slither(repo):
    """Returns (findings, error). findings = list of (impact, check, fname, line, desc)."""
    try:
        raw, src = _slither_raw(repo)
    except Exception as e:
        return None, f"slither failed to run: {e}"
    if raw is None:
        return None, "slither unavailable (pip install slither-analyzer on Linux/CI, or set up the WSL lane: toolkit/WSL-LANE.md)"
    try:
        data = json.loads(raw)
    except Exception:
        i = raw.find("{")  # slither may emit a banner before the JSON
        try:
            data = json.loads(raw[i:]) if i >= 0 else {}
        except Exception:
            return None, f"could not parse slither JSON (via {src}) -- did the target compile? (deps / solc version)"
    if not data.get("results"):
        return None, f"slither (via {src}) produced no results (compile/deps issue?)"
    out = []
    for d in data["results"].get("detectors", []):
        impact = d.get("impact", "?")
        if impact in ("Informational", "Optimization"):
            continue
        fname, line = "?", 0
        els = d.get("elements", [])
        if els:
            sm = els[0].get("source_mapping", {})
            fname = os.path.basename(sm.get("filename_relative") or sm.get("filename_short") or "?")
            lines = sm.get("lines") or [0]
            line = lines[0]
        desc = (d.get("description", "") or "").strip().splitlines()
        out.append((impact, d.get("check", ""), fname, line, desc[0][:110] if desc else ""))
    return out, None


def corroborate(recon_res, slither_res):
    """Leads flagged by BOTH L1 (recon) and L2 (Slither) at the same spot."""
    if not slither_res:
        return []
    sl = [(f, ln) for (_, _, f, ln, _) in slither_res if ln]
    hits = []
    seen = set()
    for title, _, _ in recon.DETECTORS:
        for rel, ln, snip, note, prio in recon_res[title]:
            if prio >= 2:           # only corroborate genuine leads, not "likely OK"
                continue
            fb = os.path.basename(rel)
            if (fb, ln) in seen:
                continue
            if any(fb == f and abs(ln - l) <= 3 for f, l in sl):
                seen.add((fb, ln))
                hits.append((fb, ln, note))
    return hits


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

    # ── headline: cross-corroborated (L1 + L2 agree) ──
    corr = corroborate(recon_res, slither_res)
    L.append(f"## *** CORROBORATED by L1 + L2 (high confidence)  ({len(corr)}) ***")
    if slither_res is None:
        L.append("  (slither did not run -> no corroboration)")
    elif not corr:
        L.append("  (no spot flagged by both heuristics and Slither)")
    else:
        for fb, ln, note in corr:
            L.append(f"- *** `{fb}:{ln}` - flagged by BOTH recon + Slither - {note}")

    # ── Slither (L2) ──
    L.append("\n## Slither (AST/dataflow) - High/Medium impact")
    if slither_res is None:
        L.append(f"  [skipped] {slither_err}")
    elif not slither_res:
        L.append("  (no High/Medium findings)")
    else:
        order = {"High": 0, "Medium": 1, "Low": 2}
        for impact, check, fname, line, desc in sorted(slither_res, key=lambda x: order.get(x[0], 3)):
            L.append(f"- [{impact}] `{fname}:{line}` {check} - {desc}")

    # ── recon (L1) ──
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
