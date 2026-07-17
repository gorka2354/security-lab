#!/usr/bin/env python3
"""calibrate.py - the feedback loop: are our verdicts actually RIGHT?

The engine makes verdicts (real / clean / dead / fp) every session but never
learns whether they held. shadow.py benchmarks detector recall on SOLVED
contests; this closes the loop on our LIVE work, on two fronts:

  FINDINGS    - each claimed finding tracked to its real-world OUTCOME
                (disclosed -> acknowledged -> accepted|disputed|duplicate|fixed|
                 ignored; the severity we CLAIMED vs the one AWARDED; bounty
                 expected vs paid). Ground truth = the operator (he discloses, he sees
                 the reply). This is the project's real KPI - not detector recall.

  CALIBRATION - for a target we CLOSED (clean/dead/audited/fp), when public
                ground truth later appears (a contest result / audit report /
                Solodit entry), record what WAS there vs what we said -> TP/FN/
                severity-drift. A miss (we said clean, the audit found H/M) is the
                highest-signal datum we get: it names a blind spot to fix next.

    python toolkit/calibrate.py finding add --target ledgity --title "WrappedLToken insolvency" \
        --sev Medium --channel direct --file src/protocol-v1/WrappedLToken.sol --line 114
    python toolkit/calibrate.py finding outcome --id ledgity-1 --status accepted --awarded Medium --bounty 0
    python toolkit/calibrate.py calib add --target monetrix --source "C4 2026-04" \
        --public "M-01 backing undercount" --ours found --result TP --lesson "L4 Accountant+coupled-state"
    python toolkit/calibrate.py report          # the instrument panel: precision / recall / blind spots

Verdicts are stored in calibration.json next to the triage ledger. ASCII output
(Windows console is cp1251 - no unicode in printed strings).
"""

import argparse
import datetime
import json
import os
import re

STORE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "calibration.json")

# finding lifecycle: where a disclosed finding can end up
FINDING_STATUS = ["drafted", "disclosed", "acknowledged", "accepted", "disputed",
                  "duplicate", "fixed-silent", "no-response", "withdrawn"]
# Gate-0 class (ORTHOGONAL to the disclosure status): is the bug exploitable on a LIVE target, or a real
# code-bug on a dead/empty/non-callable one? Keeps live findings (capyfi) from being lumped with academic
# ones (ledgity not-deployed, death.fun non-callable). hardened/known cases aren't findings at all -> ledger.
FINDING_KIND = ["live", "non-live"]
# a finding "counts as correct" (true positive) if the team agreed it was real:
ACCEPTED_LIKE = {"accepted", "fixed-silent", "duplicate"}   # duplicate = real, just not first
REJECTED_LIKE = {"disputed", "withdrawn"}                    # we were wrong / pulled it
CALIB_RESULTS = ["TP", "FN", "TN", "sev-drift"]             # vs public ground truth
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _today():
    return datetime.date.today().isoformat()


def _norm(s):
    return re.sub(r"\s+", " ", (s or "")).strip()


def load():
    if not os.path.isfile(STORE):
        return {"findings": [], "calibrations": []}
    try:
        d = json.load(open(STORE, encoding="utf-8"))
    except Exception:
        return {"findings": [], "calibrations": []}
    d.setdefault("findings", [])
    d.setdefault("calibrations", [])
    return d


def save(d):
    json.dump(d, open(STORE, "w", encoding="utf-8"), indent=2)


def _next_id(items, target):
    """target-N, stable per target so a re-run references the same finding."""
    n = sum(1 for it in items if it.get("target") == target) + 1
    return "%s-%d" % (_norm(target), n)


# ---------- findings ----------

def finding_add(a):
    d = load()
    fid = _next_id(d["findings"], a.target)
    d["findings"].append({
        "id": fid, "target": _norm(a.target), "title": _norm(a.title),
        "sev_claimed": (a.sev or "").lower(), "channel": _norm(a.channel),
        "file": _norm(a.file), "line": int(a.line or 0),
        "status": a.status or "drafted", "sev_awarded": "",
        "kind": (getattr(a, "kind", "") or "live"),    # Gate-0 class; default live (you usually log a live one)
        "bounty_expected": a.bounty_expected or 0, "bounty_received": 0,
        "found": a.date or _today(), "updated": _today(), "notes": _norm(a.notes)})
    save(d)
    print("[calib] FINDING +%s  %s  (%s, %s, %s)"
          % (fid, a.target, a.sev or "?", getattr(a, "kind", "") or "live", a.status or "drafted"))


def finding_outcome(a):
    d = load()
    for f in d["findings"]:
        if f["id"] == a.id:
            if a.status:
                if a.status not in FINDING_STATUS:
                    print("status must be one of:", ", ".join(FINDING_STATUS)); return
                f["status"] = a.status
            if a.awarded:
                f["sev_awarded"] = a.awarded.lower()
            if getattr(a, "kind", ""):
                if a.kind not in FINDING_KIND:
                    print("kind must be one of:", ", ".join(FINDING_KIND)); return
                f["kind"] = a.kind
            if a.bounty is not None:
                f["bounty_received"] = a.bounty
            if a.notes:
                f["notes"] = (f.get("notes", "") + " | " + _norm(a.notes)).strip(" |")
            f["updated"] = _today()
            save(d)
            print("[calib] OUTCOME %s -> %s  awarded=%s bounty=%s"
                  % (a.id, f["status"], f["sev_awarded"] or "-", f["bounty_received"]))
            return
    print("no finding with id", a.id)


# ---------- calibration vs public ground truth ----------

def calib_add(a):
    d = load()
    if a.result not in CALIB_RESULTS:
        print("result must be one of:", ", ".join(CALIB_RESULTS)); return
    cid = _next_id(d["calibrations"], a.target)
    d["calibrations"].append({
        "id": cid, "target": _norm(a.target), "source": _norm(a.source),
        "public": _norm(a.public), "ours": _norm(a.ours), "result": a.result,
        "sev": (a.sev or "").lower(), "lesson": _norm(a.lesson), "date": a.date or _today()})
    save(d)
    flag = "  <-- BLIND SPOT" if a.result == "FN" else ""
    print("[calib] CALIB +%s  %s  %s%s" % (cid, a.target, a.result, flag))


# ---------- metrics (pure, testable) ----------

def precision_stats(F):
    """(accepted, decided, pending) over tracked findings. Precision = accepted/decided."""
    acc = [f for f in F if f.get("status") in ACCEPTED_LIKE]
    decided = [f for f in F if f.get("status") in ACCEPTED_LIKE | REJECTED_LIKE]
    pending = [f for f in F if f.get("status") not in ACCEPTED_LIKE | REJECTED_LIKE]
    return acc, decided, pending


def recall_stats(C):
    """(true_positives, false_negatives) vs public ground truth. Recall = TP/(TP+FN)."""
    return ([c for c in C if c.get("result") == "TP"],
            [c for c in C if c.get("result") == "FN"])


# ---------- the instrument panel ----------

def report(_a):
    d = load()
    F, C = d["findings"], d["calibrations"]
    print("=" * 64)
    print("FEEDBACK LOOP  (calibration.json)   %s" % _today())
    print("=" * 64)

    print("\n-- FINDINGS (our claims -> real outcome) --")
    if not F:
        print("  (none tracked yet)")
    else:
        for f in sorted(F, key=lambda x: x["target"]):
            sev = f["sev_claimed"] or "?"
            drift = ""
            if f["sev_awarded"] and f["sev_awarded"] != f["sev_claimed"]:
                drift = "  sev: %s->%s" % (sev, f["sev_awarded"])
            paid = (" $%s" % f["bounty_received"]) if f["bounty_received"] else ""
            print("  [%-12s] %-12s %-8s %-12s%s%s" %
                  (f["status"], f["id"], sev, f["channel"] or "-", drift, paid))
            if f.get("title"):
                print("      %s" % f["title"][:78])
        acc, decided, pend = precision_stats(F)
        prec = ("%.0f%%" % (100.0 * len(acc) / len(decided))) if decided else "n/a"
        paid_total = sum(f["bounty_received"] for f in F)
        print("  ---")
        print("  precision (accepted/decided): %s  (%d accepted, %d disputed, %d pending)"
              % (prec, len(acc), len(decided) - len(acc), len(pend)))
        print("  bounty received total: $%s" % paid_total)

    print("\n-- CALIBRATION (our verdict vs public ground truth) --")
    if not C:
        print("  (none recorded yet)")
    else:
        tp, fn = recall_stats(C)
        for c in sorted(C, key=lambda x: (x["result"] != "FN", x["target"])):
            flag = "  <-- BLIND SPOT" if c["result"] == "FN" else ""
            print("  [%-3s] %-12s %-22s %s%s" %
                  (c["result"], c["target"], (c["source"] or "")[:22], c["public"][:30], flag))
            if c["result"] == "FN" and c.get("lesson"):
                print("        lesson: %s" % c["lesson"][:74])
        rec = ("%.0f%%" % (100.0 * len(tp) / (len(tp) + len(fn)))) if (tp or fn) else "n/a"
        print("  ---")
        print("  recall on public-truth targets (TP/(TP+FN)): %s  (%d found, %d MISSED)"
              % (rec, len(tp), len(fn)))
        if fn:
            print("  blind spots to fix:", ", ".join(c["target"] for c in fn))
    print()


def main():
    ap = argparse.ArgumentParser(description="Feedback loop: track finding outcomes + calibrate verdicts")
    sub = ap.add_subparsers(dest="cmd", required=True)

    fa = sub.add_parser("finding", help="finding lifecycle")
    fsub = fa.add_subparsers(dest="fcmd", required=True)
    add = fsub.add_parser("add")
    add.add_argument("--target", required=True); add.add_argument("--title", required=True)
    add.add_argument("--sev", default=""); add.add_argument("--channel", default="")
    add.add_argument("--file", default=""); add.add_argument("--line", type=int, default=0)
    add.add_argument("--status", default="drafted"); add.add_argument("--bounty-expected", type=int, dest="bounty_expected", default=0)
    add.add_argument("--kind", default="live", choices=FINDING_KIND, help="Gate-0 class: live | non-live")
    add.add_argument("--date", default=""); add.add_argument("--notes", default="")
    out = fsub.add_parser("outcome")
    out.add_argument("--id", required=True); out.add_argument("--status", default="")
    out.add_argument("--awarded", default=""); out.add_argument("--bounty", type=int, default=None)
    out.add_argument("--kind", default="", choices=["", *FINDING_KIND], help="reclassify Gate-0: live | non-live")
    out.add_argument("--notes", default="")

    ca = sub.add_parser("calib", help="calibrate a verdict vs public ground truth")
    csub = ca.add_subparsers(dest="ccmd", required=True)
    cadd = csub.add_parser("add")
    cadd.add_argument("--target", required=True); cadd.add_argument("--source", default="")
    cadd.add_argument("--public", required=True); cadd.add_argument("--ours", default="")
    cadd.add_argument("--result", required=True, choices=CALIB_RESULTS)
    cadd.add_argument("--sev", default=""); cadd.add_argument("--lesson", default=""); cadd.add_argument("--date", default="")

    sub.add_parser("report", help="print the instrument panel")

    a = ap.parse_args()
    if a.cmd == "finding" and a.fcmd == "add":
        finding_add(a)
    elif a.cmd == "finding" and a.fcmd == "outcome":
        finding_outcome(a)
    elif a.cmd == "calib" and a.ccmd == "add":
        calib_add(a)
    elif a.cmd == "report":
        report(a)


if __name__ == "__main__":
    main()
