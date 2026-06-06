#!/usr/bin/env python3
"""scope.py - COMPLETE attack-surface inventory + COVERAGE checklist (head-to-toe).

recon/hypothesize are LEAD-driven (surface suspicious things). A full audit must be
COVERAGE-driven: enumerate EVERYTHING and track what's reviewed so nothing is missed.
scope.py produces that map - the checklist you walk item-by-item to 100%.

    python toolkit/scope.py <repo> [--out coverage.md]

Output:
  1. ENTRY-POINT CHECKLIST  - every external/public state-changing fn, grouped by file,
     with access (GATED/UNGATED), the state roots it writes, and whether it makes an
     EXTERNAL call. Each is a `[ ]` to tick off (+ verdict) as you review it.
  2. INVENTORY            - state variables, roles/modifiers, external dependencies,
     declared invariants (what their fuzzer checks).
  3. COVERAGE counter     - N entry points; reviewed X/N. 100% = head-to-toe done.

Reuses recon's auth detection. ASCII output. Heuristic (regex) - the map, you do the review.
"""

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import recon  # for INLINE_AUTH + iter_sol + det_key  # noqa: E402

ACC = r"(?:state|s|ds|\$)"
FUNC = re.compile(r"function\s+(\w+)\s*(\([^{};]*?)\{", re.S)
ASSIGN = re.compile(r"\s*(=(?!=)|\+=|-=|\*=|/=|\+\+|--|\bdelete\b|\.push\b|\.pop\b)")
STATE = re.compile(r"\b" + ACC + r"(?:\.\w+){1,3}")
ROOTRE = re.compile(ACC + r"\.data\.\w+|" + ACC + r"\.\w+")
EXTCALL = re.compile(r"\.call\s*[\({]|\.delegatecall\s*\(|\.safeTransfer\w*\s*\(|"
                     r"\.transfer(From)?\s*\(|\bI[A-Z]\w*\s*\([^)]*\)\s*\.\w+\s*\(")
MODIFIER = re.compile(r"\bonly\w+|\b(re)?initializer\b|nonReentrant|whenNotPaused")


def writes(body):
    out = set()
    for m in STATE.finditer(body):
        if ASSIGN.match(body[m.end():m.end() + 8]):
            r = ROOTRE.match(m.group(0))
            out.add(r.group(0) if r else m.group(0))
    return out


def gated(blob, body):
    return ("only" in blob.lower() or re.search(r"\b(re)?initializer\b", blob)
            or bool(recon.INLINE_AUTH.search(body))
            or bool(re.search(r"\[\s*(msg\.sender|_msgSender\(\))\s*\]", body[:280])))


def main():
    ap = argparse.ArgumentParser(description="Attack-surface inventory + coverage checklist")
    ap.add_argument("repo")
    ap.add_argument("--out")
    a = ap.parse_args()
    base = a.repo if os.path.isdir(a.repo) else os.path.dirname(a.repo)

    by_file = {}            # rel -> [ (name, line, gated, nstate, extcall) ]
    state_vars, roles, deps, invs = set(), set(), set(), []
    n_entry = 0
    for path in recon.iter_sol(a.repo):
        try:
            text = open(path, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        rel = os.path.relpath(path, base).replace("\\", "/")
        if recon._TESTRE.search(rel):           # collect invariants from tests, skip for entry pts
            for m in re.finditer(r"function\s+(invariant_?\w+|propert\w+|echidna_?\w+)\s*\(", text):
                invs.append((os.path.basename(path), m.group(1)))
            continue
        for mo in MODIFIER.finditer(text):
            roles.add(mo.group(0))
        for d in re.finditer(r"\bI[A-Z]\w+\b", text):   # interface types = external deps (rough)
            deps.add(d.group(0))
        ms = list(FUNC.finditer(text))
        for i, m in enumerate(ms):
            name, blob = m.group(1), m.group(2)
            end = ms[i + 1].start() if i + 1 < len(ms) else len(text)
            body = text[m.end():end]
            for w in writes(body):
                state_vars.add(w)
            if not re.search(r"\b(external|public)\b", blob) or re.search(r"\b(view|pure)\b", blob):
                continue
            n_entry += 1
            line = text[:m.start()].count("\n") + 1
            w = writes(body)
            by_file.setdefault(rel, []).append(
                (name, line, gated(blob, body), len(w), bool(EXTCALL.search(body))))

    L = [f"# Coverage checklist: {os.path.basename(os.path.abspath(a.repo))}",
         f"\n**{n_entry} entry points** across {len(by_file)} files. Walk each `[ ]` -> tick `[x]`",
         "with a verdict. 100% ticked = head-to-toe done.\n",
         "Legend: `GATED`/`UNGATED` access · `wN` = N state roots written · `EXT` = makes external call.\n"]

    for rel in sorted(by_file):
        fns = sorted(by_file[rel], key=lambda f: f[1])
        L.append(f"## `{rel}`  ({len(fns)})")
        for name, line, g, nstate, ext in fns:
            tags = ("GATED" if g else "**UNGATED**") + f" w{nstate}" + (" EXT" if ext else "")
            L.append(f"- [ ] `{name}` :{line}  - {tags}")

    L.append(f"\n## Coverage: 0 / {n_entry} entry points reviewed")
    L.append("\n## Inventory - state variables (" + str(len(state_vars)) + ")")
    L.append("  " + ", ".join(sorted(state_vars)[:60]) + (" ..." if len(state_vars) > 60 else ""))
    L.append("\n## Inventory - roles / guards")
    L.append("  " + ", ".join(sorted(roles)) if roles else "  (none found)")
    L.append("\n## Inventory - external dependencies (interface types, rough)")
    L.append("  " + ", ".join(sorted(deps)[:50]) + (" ..." if len(deps) > 50 else ""))
    L.append("\n## Their declared invariants (the fuzzed baseline)")
    if invs:
        for f, nm in invs[:40]:
            L.append(f"- `{f}` {nm}")
    else:
        L.append("  (no invariant harness found - nothing is being fuzzed -> more room + you must add it)")

    L.append("\n---\nNext: review each entry point (who can call? assets touched? which invariant? "
             "reentrancy/access/oracle/rounding?), tick it, record FP/real in the ledger. "
             "Then run/extend the invariant fuzzer for the math layer.")

    report = "\n".join(L)
    print(report)
    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        open(a.out, "w", encoding="utf-8").write(report)
        print(f"\n[written to {a.out}]")


if __name__ == "__main__":
    main()
