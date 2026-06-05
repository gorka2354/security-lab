#!/usr/bin/env python3
"""ledger.py - persistent triage memory: never re-judge the same lead twice.

The volume engine re-surfaces the SAME leads every run, and our verdicts
(FP / known / real) otherwise live only in chat - the clones in hunts/_volume/
are gitignored, so the knowledge is lost next session. This ledger records each
verdict keyed by (target, file, detector, snippet) so orchestrate.py can
auto-suppress already-judged leads. Noise then falls monotonically: you only
ever look at NEW leads.

    python toolkit/ledger.py add --target stakelink \
        --file contracts/.../WithdrawalPool.sol \
        --detector sibling --snippet "function updateWithdrawalBatchIdCutoff(...)" \
        --line 424 --verdict fp --reason "public-good bookkeeping poke"

    python toolkit/ledger.py list [--target stakelink] [--verdict fp]
    python toolkit/ledger.py stats

Verdicts:  fp | known | wontfix   -> SILENCE the lead (hidden next run)
           real | todo            -> kept visible (active leads), just tracked

Matching is on (target, file, detector, snippet) with whitespace normalized, so
a verdict survives line-number drift after a re-clone. ASCII output (Windows).
"""

import argparse
import json
import os
import re

LEDGER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "triage-ledger.json")
SILENCING = {"fp", "known", "wontfix"}
VERDICTS = ["fp", "known", "wontfix", "real", "todo"]


def _norm(s):
    return re.sub(r"\s+", " ", (s or "").replace("\\", "/")).strip()


# detectors that ask the SAME question ("is this function properly gated?") share
# a group, so one verdict silences the lead under either detector.
_GROUPS = {"sibling": "ac", "access": "ac"}


def _group(det_key):
    k = _norm(det_key)
    return _GROUPS.get(k, k)


def signature(target, rel, det_key, snippet):
    """Stable identity of a lead: target|file|detector-group|normalized-snippet.
    The detector is grouped (sibling+access -> 'ac') so a verdict survives a
    re-clone AND covers both access-control detectors for the same function."""
    return "|".join([_norm(target), _norm(rel), _group(det_key), _norm(snippet)])


def load(path=LEDGER):
    """Return {signature: entry}. Recomputes the key from fields (not the stored
    'sig') so a grouping change applies to old entries without a migration."""
    if not os.path.isfile(path):
        return {}
    try:
        data = json.load(open(path, encoding="utf-8"))
    except Exception:
        return {}
    return {signature(e["target"], e["file"], e["detector"], e["snippet"]): e
            for e in data.get("entries", [])}


def save(index, path=LEDGER):
    entries = sorted(index.values(), key=lambda e: (e["target"], e["file"], e.get("line", 0)))
    json.dump({"entries": entries}, open(path, "w", encoding="utf-8"), indent=2)


def verdict_for(index, target, rel, det_key, snippet):
    return index.get(signature(target, rel, det_key, snippet))


def is_silenced(entry):
    return bool(entry) and entry.get("verdict") in SILENCING


def add(target, rel, line, det_key, snippet, verdict, reason, date, path=LEDGER):
    index = load(path)
    sig = signature(target, rel, det_key, snippet)
    index[sig] = {"sig": sig, "target": _norm(target), "file": _norm(rel),
                  "line": int(line or 0), "detector": _norm(det_key),
                  "snippet": _norm(snippet), "verdict": verdict,
                  "reason": reason, "date": date}
    save(index, path)
    return sig


_MARK = {"fp": "[FP ]", "known": "[KNW]", "wontfix": "[WON]",
         "real": "[!!!]", "todo": "[ . ]"}


def main():
    ap = argparse.ArgumentParser(description="Triage ledger (persistent verdict memory)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("add", help="record a verdict for a lead")
    a.add_argument("--target", required=True)
    a.add_argument("--file", required=True)
    a.add_argument("--line", type=int, default=0)
    a.add_argument("--detector", required=True, help="short key: sibling/access/supply/...")
    a.add_argument("--snippet", default="", help="recon's snippet, e.g. 'function foo(...)'")
    a.add_argument("--verdict", required=True, choices=VERDICTS)
    a.add_argument("--reason", default="")
    a.add_argument("--date", default="", help="YYYY-MM-DD (defaults to today)")

    li = sub.add_parser("list", help="show recorded verdicts")
    li.add_argument("--target")
    li.add_argument("--verdict", choices=VERDICTS)

    sub.add_parser("stats", help="counts by verdict / target")

    args = ap.parse_args()

    if args.cmd == "add":
        date = args.date
        if not date:
            import datetime
            date = datetime.date.today().isoformat()
        add(args.target, args.file, args.line, args.detector, args.snippet,
            args.verdict, args.reason, date)
        silenced = " (SILENCED next run)" if args.verdict in SILENCING else ""
        print(f"[ledger] {args.verdict.upper()}{silenced}  {args.target}  "
              f"{args.file}:{args.line}  ({args.detector})")
        return

    index = load()
    rows = sorted(index.values(), key=lambda e: (e["target"], e["file"], e.get("line", 0)))

    if args.cmd == "stats":
        if not rows:
            print("(ledger empty)")
            return
        byv, byt = {}, {}
        for r in rows:
            byv[r["verdict"]] = byv.get(r["verdict"], 0) + 1
            byt[r["target"]] = byt.get(r["target"], 0) + 1
        print(f"{len(rows)} verdicts in {LEDGER}\n")
        print("by verdict: " + ", ".join(f"{k}={v}" for k, v in sorted(byv.items())))
        print("by target:  " + ", ".join(f"{k}={v}" for k, v in sorted(byt.items())))
        sil = sum(v for k, v in byv.items() if k in SILENCING)
        print(f"\n{sil} leads will be auto-suppressed by orchestrate.")
        return

    # list
    if args.target:
        rows = [r for r in rows if r["target"] == args.target]
    if args.verdict:
        rows = [r for r in rows if r["verdict"] == args.verdict]
    if not rows:
        print("(no matching entries)")
        return
    for r in rows:
        print(f"{_MARK.get(r['verdict'], '[?] ')} {r['target']:<12} "
              f"{r['file']}:{r.get('line', 0)}  ({r['detector']})")
        if r.get("reason"):
            print(f"            {r['reason']}  [{r.get('date', '')}]")
    print(f"\n{len(rows)} entries.")


if __name__ == "__main__":
    main()
