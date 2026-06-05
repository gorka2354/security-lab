#!/usr/bin/env python3
"""diffscan.py - hunt where bugs actually live: in CHANGED code (audit drift).

An audited protocol is clean at the audited commit; the bugs slip in AFTER, in
new facets / versions that the audit never saw (Infrared V1_5's missing modifier
was exactly this). diffscan runs recon's detectors only on files changed since a
reference (a tag, a date, or N commits) and flags leads that fall INSIDE the
changed hunks - the freshest, least-audited lines in the repo.

    python toolkit/diffscan.py <repo> --tags            # list tags -> pick a ref
    python toolkit/diffscan.py <repo> --since v1.4.0     # diff HEAD vs a tag/commit
    python toolkit/diffscan.py <repo> --since-days 120    # diff HEAD vs ~120 days ago

NEEDS git history. orchestrate clones --depth 1 (no history); to diff-hunt, deepen
the clone first:  git -C <dir> fetch --unshallow --tags   (or clone without --depth).
Reuses recon detectors + the triage ledger (already-judged leads are suppressed).
ASCII output for Windows consoles.
"""

import argparse
import os
import re
import subprocess

import ledger  # same folder
import recon   # same folder


def git(repo, *args):
    try:
        r = subprocess.run(["git", "-C", repo, *args],
                           capture_output=True, text=True, timeout=120)
    except Exception:
        return ""
    return r.stdout if r.returncode == 0 else ""


def has_history(repo):
    return bool(git(repo, "rev-parse", "HEAD")) and \
        git(repo, "rev-list", "--count", "HEAD").strip() not in ("", "1")


def changed_files(repo, ref):
    out = git(repo, "diff", "--name-only", ref, "HEAD", "--", "*.sol")
    return [f.strip() for f in out.splitlines() if f.strip().endswith(".sol")]


def changed_lines(repo, ref, relfile):
    """Line numbers (HEAD side) that fall inside an added/modified hunk."""
    out = git(repo, "diff", "-U0", ref, "HEAD", "--", relfile)
    lines = set()
    for m in re.finditer(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", out, re.M):
        start, count = int(m.group(1)), int(m.group(2) or "1")
        for ln in range(start, start + max(count, 1)):
            lines.add(ln)
    return lines


def date_ref(repo, days):
    return git(repo, "rev-list", "-1", f"--before={days} days ago", "HEAD").strip()


def main():
    ap = argparse.ArgumentParser(description="Scan only code changed since a ref (audit drift)")
    ap.add_argument("repo")
    ap.add_argument("--since", help="git ref (tag/commit/branch) to diff HEAD against")
    ap.add_argument("--since-days", type=int, help="diff HEAD vs the commit ~N days ago")
    ap.add_argument("--tags", action="store_true", help="list tags and exit")
    ap.add_argument("--target", help="name for ledger lookups (default: repo basename)")
    ap.add_argument("--out", help="also write the report to this markdown file")
    a = ap.parse_args()

    repo = os.path.abspath(a.repo)
    if not os.path.isdir(os.path.join(repo, ".git")):
        print(f"[!] {repo} is not a git repo (no .git).")
        return

    if a.tags:
        tags = git(repo, "tag", "--sort=-creatordate")
        print(tags.strip() if tags.strip() else
              "(no tags - shallow clone? try: git -C <dir> fetch --unshallow --tags)")
        return

    if not has_history(repo):
        print("[!] no usable git history (shallow --depth 1 clone).")
        print("    Deepen it:  git -C %s fetch --unshallow --tags" % repo)
        return

    ref = a.since
    if a.since_days:
        ref = date_ref(repo, a.since_days)
        if not ref:
            print("[!] could not resolve a commit that many days ago (deepen the clone).")
            return
    if not ref:
        print("[!] give --since <ref> or --since-days N (or --tags to list refs).")
        return
    if not git(repo, "rev-parse", "--verify", "--quiet", ref).strip() and not a.since_days:
        print(f"[!] ref '{ref}' not found. Use --tags to list refs, or --since-days N.")
        return

    files = changed_files(repo, ref)
    if not files:
        print(f"[ok] no .sol files changed between {ref[:12]} and HEAD.")
        return

    target = a.target or os.path.basename(repo)
    led = ledger.load()
    fresh, other = [], []   # (prio, title, rel, ln, snip, note)
    suppressed = 0
    for rel in files:
        path = os.path.join(repo, rel)
        if not os.path.isfile(path) or recon._TESTRE.search(rel):
            continue
        try:
            text = open(path, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        hot = changed_lines(repo, ref, rel)
        for title, fn, _ in recon.DETECTORS:
            key = recon.det_key(title)
            for (r, ln, snip, note, prio) in fn(text, rel):
                if ledger.is_silenced(ledger.verdict_for(led, target, r, key, snip)):
                    suppressed += 1
                    continue
                (fresh if ln in hot else other).append((prio, title, r, ln, snip, note))
    fresh.sort(key=lambda x: x[0])
    other.sort(key=lambda x: x[0])

    mark = {0: "[!]", 1: "[.]", 2: "[ ]"}
    L = [f"# Diff-scan: {target}  (changed since {ref[:12]})",
         f"\n{len(files)} .sol files changed. {len(fresh)} leads INSIDE changed code "
         f"(freshest), {len(other)} elsewhere in changed files. "
         f"{suppressed} suppressed by ledger.\n",
         "## >>> Leads INSIDE changed code (audit drift - hunt these first)"]
    if fresh:
        for prio, title, r, ln, snip, note in fresh:
            L.append(f"- {mark[prio]} `{r}:{ln}`  `{snip}`  [{recon.det_key(title)}] - {note}")
    else:
        L.append("  (none - changed files touched no detector lines)")
    L.append("\n## Leads elsewhere in changed files (lower freshness)")
    if other:
        for prio, title, r, ln, snip, note in other[:30]:
            L.append(f"- {mark[prio]} `{r}:{ln}`  `{snip}`  [{recon.det_key(title)}] - {note}")
        if len(other) > 30:
            L.append(f"  ... and {len(other) - 30} more")
    else:
        L.append("  (none)")

    report = "\n".join(L)
    print(report)
    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        open(a.out, "w", encoding="utf-8").write(report)
        print(f"\n[written to {a.out}]")


if __name__ == "__main__":
    main()
