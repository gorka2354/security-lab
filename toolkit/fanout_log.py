#!/usr/bin/env python3
"""fanout_log.py - persist a fan-out triage run: a typed candidate TABLE + ledger-suppress.

The fan-out Workflow returns N structured verdicts (reach/gate/fork/recommendation/leads), but they were
EPHEMERAL -- next session would re-triage the same targets and burn tokens. This writes them down so the
funnel's OUTCOME end stops leaking:

  1. hunts/_fanout/<date>-<label>.md  -- a candidate TABLE (target | type | chain | gate | fork | rec | leads)
  2. ledger-suppress the dead ends    -- SKIP/UNREACHABLE -> known, PARK -> wontfix (won't resurface)
  3. queue the live ones              -- DIG / DIG-CAREFUL -> todo (the deep-dive backlog)

Verdicts are TRIAGE-LEVEL: `top_leads` are HYPOTHESES from a shallow skim, NOT verified findings -- the deep
L4 happens LATER, by hand, on the DIG candidates (the eva/mezo lesson: triage "High" leads can be conserved).
The ledger key uses a STABLE snippet (the zone) so a re-run UPDATES a target's verdict instead of duplicating.

    python toolkit/fanout_log.py verdicts.json --label abstract --chain 2741 [--date YYYY-MM-DD] [--no-ledger]
    # verdicts.json = the Workflow result array, or {"result":[...]} (the task .output file works directly)
"""

import argparse
import datetime
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ledger  # noqa: E402

# fan-out recommendation -> ledger verdict. DIG stays VISIBLE (a todo backlog); dead ends are SILENCED.
REC_TO_VERDICT = {
    "DIG": "todo", "DIG-CAREFUL": "todo",
    "PARK": "wontfix", "SKIP": "known", "UNREACHABLE": "known",
}
_ORDER = {"DIG": 0, "DIG-CAREFUL": 1, "PARK": 2, "SKIP": 3, "UNREACHABLE": 4}


def parse_verdicts(data):
    """PURE: a Workflow result (list, or {result|verdicts|candidates: [...]}) -> clean verdict list."""
    if isinstance(data, dict):
        data = data.get("result") or data.get("verdicts") or data.get("candidates") or []
    return [v for v in data if isinstance(v, dict) and v.get("name")]


def load_verdicts(path):
    return parse_verdicts(json.load(open(path, encoding="utf-8")))


def leads_str(v, n=3):
    """PURE: first n lead titles, joined, pipe-safe for a markdown cell."""
    leads = v.get("top_leads") or []
    s = "; ".join((l.get("title") or "")[:50] for l in leads[:n] if isinstance(l, dict))
    return (s or "-").replace("|", "/")


def write_table(verdicts, label, chain, date, root):
    os.makedirs(root, exist_ok=True)
    path = os.path.join(root, f"{date}-{label}.md")
    rows = sorted(verdicts, key=lambda v: _ORDER.get(v.get("recommendation"), 9))
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# Fan-out triage: {label}  (chain {chain})  {date}\n\n")
        f.write(f"{len(verdicts)} targets triaged. **TRIAGE-LEVEL** -- `top_leads` are HYPOTHESES from a "
                "shallow skim, NOT verified findings; deep L4 happens later on the DIG queue.\n\n")
        f.write("| target | type | chain | gate | fork/audit | rec | top leads (hypotheses) |\n")
        f.write("|---|---|---|---|---|---|---|\n")
        for v in rows:
            f.write("| %s | %s | %s | %s | %s | **%s** | %s |\n" % (
                v.get("name", "?"), v.get("zone") or v.get("type") or "-",
                v.get("chain") or chain or "-", (v.get("deployment_gate") or "-")[:18],
                (v.get("fork_or_audit") or "-")[:24], v.get("recommendation", "?"), leads_str(v)))
        digs = [v for v in rows if v.get("recommendation") in ("DIG", "DIG-CAREFUL")]
        if digs:
            f.write("\n## Deep-dive queue (DIG / DIG-CAREFUL) -- verify these by hand\n")
            for v in digs:
                f.write(f"\n### {v['name']}  ({v.get('recommendation')})\n")
                aa = v.get("aa_footgun")
                if aa and aa.lower() not in ("none seen", "none", "n/a", "-", ""):
                    f.write(f"- AA / chain footgun: {aa}\n")
                f.write(f"- {v.get('rationale', '')}\n")
                for l in (v.get("top_leads") or []):
                    if isinstance(l, dict):
                        f.write(f"  - lead: {l.get('title', '')}  [{l.get('file', '')}] "
                                f"({l.get('severity_guess', '?')})\n")
    return path


def main():
    ap = argparse.ArgumentParser(description="Persist a fan-out triage run (typed table + ledger-suppress)")
    ap.add_argument("verdicts", help="JSON file: the Workflow result array (or the task .output file)")
    ap.add_argument("--label", required=True, help="run label, e.g. abstract / defillama-wave")
    ap.add_argument("--chain", default="", help="chain id/name for the run")
    ap.add_argument("--date", default="", help="YYYY-MM-DD (default today)")
    ap.add_argument("--root", default=os.path.join("hunts", "_fanout"))
    ap.add_argument("--no-ledger", action="store_true", help="write the table only, skip ledger-suppress")
    a = ap.parse_args()

    date = a.date or datetime.date.today().isoformat()
    verdicts = load_verdicts(a.verdicts)
    if not verdicts:
        print("[!] no verdicts parsed from", a.verdicts)
        return 1
    path = write_table(verdicts, a.label, a.chain, date, a.root)
    print(f"[fanout-log] wrote {len(verdicts)} candidates -> {path}")

    if not a.no_ledger:
        n = {"todo": 0, "known": 0, "wontfix": 0}
        for v in verdicts:
            verdict = REC_TO_VERDICT.get(v.get("recommendation"))
            if not verdict:
                continue
            # stable snippet (zone) so a re-run UPDATES the target's verdict, not duplicates it
            ledger.add(v["name"], "(fanout)", 0, "fanout", "fanout triage: %s" % (v.get("zone") or "-"),
                       verdict, ("[%s/%s] %s" % (v.get("recommendation"), a.label,
                                                 (v.get("rationale") or "")))[:260], date)
            n[verdict] += 1
        print(f"[fanout-log] ledger: {n['todo']} todo (deep-dive queue), "
              f"{n['known'] + n['wontfix']} suppressed (dead ends won't resurface)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
