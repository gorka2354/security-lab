#!/usr/bin/env python3
"""hypothesize.py - turn a contract's STRUCTURE into attack-hypothesis seeds.

recon.py finds vuln *patterns* (auditor-checklist mode). This is the other mode:
it extracts structural "data" so a human (L4) can build hypotheses for bugs the
audit MISSED - emergent/cross-component, round-trip asymmetry, un-checked state.
(See vault note "Метод - охота гипотезами".)

    python toolkit/hypothesize.py <repo-or-file> [--out worksheet.md]

Outputs a hypothesis worksheet:
  1. OPERATION MAP + INVERSE PAIRS  - deposit<->withdraw, mint<->burn ... -> round-trip
     asymmetry (do X then inverse(X); rounding/fees should not let value leak).
  2. SHARED-STATE MATRIX            - storage fields written by MANY functions ->
     emergent-interaction candidates (interleave A and B; does an invariant break?).
  3. THEIR DECLARED INVARIANTS      - what their test/Echidna harness already asserts
     -> the COMPLEMENT is your hunting ground (write a STRONGER invariant, fuzz it).
ASCII output for Windows consoles. Heuristic (regex), expect noise; it surfaces, you reason.
"""

import argparse
import os
import re

SKIP = {"lib", "node_modules", "out", "artifacts", "cache", ".git", "forge-std", "openzeppelin"}

# verb -> its inverse, for round-trip hypotheses
INVERSE = {
    "deposit": "withdraw", "mint": "burn", "supply": "withdraw", "borrow": "repay",
    "stake": "unstake", "lock": "unlock", "add": "remove", "increase": "decrease",
    "wrap": "unwrap", "enter": "exit", "open": "close", "buy": "sell", "create": "delete",
}
INVERSE.update({v: k for k, v in INVERSE.items()})  # both directions

FUNC = re.compile(r"function\s+(\w+)\s*(\([^{};]*?)\{", re.S)
# storage roots accessed via the State-struct pattern (Size/Rheo) or plain members
STATE = re.compile(r"\bstate(?:\.\w+){1,4}|\b_?[a-z]\w*\[[^\]]+\]\s*(?==)")
ASSIGN = re.compile(r"\s*(=(?!=)|\+=|-=|\*=|/=|\+\+|--|\bdelete\b|\.push\b|\.pop\b)")


def iter_sol(root):
    if os.path.isfile(root):
        yield root
        return
    for cur, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d.lower() not in SKIP]
        for f in files:
            if f.endswith(".sol") and "test" not in cur.lower() and "mock" not in f.lower():
                yield os.path.join(cur, f)


def verb_of(name):
    n = name[0].lower() + name[1:] if name else name
    for v in INVERSE:
        if n.startswith(v):
            return v
    m = re.match(r"(set|get|update|add|remove|claim|liquidate|swap|transfer|redeem|compensate)", n)
    return m.group(1) if m else None


def state_roots(body):
    """Return (writes, reads) sets of storage roots touched in a function body."""
    writes, reads = set(), set()
    for m in re.finditer(r"\bstate(?:\.\w+){1,4}", body):
        root = m.group(0)
        tail = body[m.end():m.end() + 8]
        (writes if ASSIGN.match(tail) else reads).add(root)
    # setter-style writes:  X.setFoo(  /  state...setFoo(
    for m in re.finditer(r"\bstate(?:\.\w+){1,3}", body):
        nxt = body[m.end():m.end() + 40]
        if re.match(r"\.(set|push|pop|increase|decrease|mint|burn|transfer|create|delete)\w*\s*\(", nxt):
            writes.add(m.group(0))
    return writes, reads


def main():
    ap = argparse.ArgumentParser(description="Extract attack-hypothesis seeds from contracts")
    ap.add_argument("path", help="repo dir or single .sol file")
    ap.add_argument("--out")
    ap.add_argument("--top", type=int, default=15)
    a = ap.parse_args()

    funcs = {}          # name -> {file, verb, writes, reads}
    field_writers = {}  # storage root -> set(func names)
    invariants = []     # (file, line, name) from test/invariants
    for path in iter_sol(a.path):
        rel = os.path.relpath(path, a.path if os.path.isdir(a.path) else os.path.dirname(a.path))
        try:
            text = open(path, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        for m in FUNC.finditer(text):
            name, blob = m.group(1), m.group(2)
            if not re.search(r"\b(external|public)\b", blob) or re.search(r"\b(view|pure)\b", blob):
                continue
            nxt = text.find("\n    function ", m.end())
            body = text[m.end():(nxt if nxt > 0 else m.end() + 2500)]
            w, r = state_roots(body)
            funcs[name] = {"file": rel, "verb": verb_of(name), "writes": w, "reads": r}
            for root in w:
                field_writers.setdefault(root, set()).add(name)

    # also scan invariant harnesses (their declared properties)
    for path in iter_sol_all(a.path):
        if not re.search(r"(invariant|propert|echidna|medusa)", path, re.I):
            continue
        try:
            text = open(path, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        for m in re.finditer(r"function\s+(invariant_?\w+|property_?\w+|echidna_?\w+)\s*\(", text):
            invariants.append((os.path.basename(path), text[:m.start()].count("\n") + 1, m.group(1)))

    out = ["# Hypothesis worksheet: " + os.path.basename(os.path.abspath(a.path)),
           f"\n{len(funcs)} state-changing external/public fns scanned. "
           "Heuristic seeds - reason over them (build attack hypotheses).\n"]

    # 1. inverse pairs
    out.append("## 1. Inverse pairs -> ROUND-TRIP asymmetry hypotheses")
    by_verb = {}
    for n, d in funcs.items():
        if d["verb"]:
            by_verb.setdefault(d["verb"], []).append(n)
    seen = set()
    pairs = 0
    for v, names in sorted(by_verb.items()):
        inv = INVERSE.get(v)
        if inv and inv in by_verb and (inv, v) not in seen:
            seen.add((v, inv))
            pairs += 1
            out.append(f"- **{v} <-> {inv}**: `{', '.join(names)}`  vs  `{', '.join(by_verb[inv])}`")
            out.append(f"    -> do {v} then {inv}: can value leak (rounding/fee)? is it a clean round-trip?")
    if not pairs:
        out.append("  (no obvious inverse verb pairs)")

    # 2. shared-state matrix
    out.append("\n## 2. Shared-state -> EMERGENT-interaction hypotheses")
    out.append("_storage fields written by MANY fns: interleave them, does an invariant break?_\n")
    ranked = sorted(field_writers.items(), key=lambda kv: -len(kv[1]))
    for root, writers in ranked[:a.top]:
        if len(writers) < 2:
            continue
        out.append(f"- `{root}`  <- written by {len(writers)}: {', '.join(sorted(writers)[:8])}"
                   + (" ..." if len(writers) > 8 else ""))
    out.append("\n  Pick a field written by 3+ fns across DIFFERENT files -> the cross-file pair is the candidate.")

    # 3. their invariants (the complement is your ground)
    out.append("\n## 3. Their DECLARED invariants (write what's NOT here)")
    if invariants:
        for f, ln, nm in invariants[:40]:
            out.append(f"- `{f}:{ln}` {nm}")
        out.append(f"\n  {len(invariants)} declared. Ask: what quantity / cross-component property is MISSING?")
    else:
        out.append("  (no invariant harness found - they may not fuzz; even more room)")

    out.append("\n## 4. Suggested STRONGER invariants (template - adapt per quantity)")
    out.append("- solvency: SUM(user claims) <= protocol assets, at ALL times, across ALL markets")
    out.append("- conservation: total debt issued == total credit owed (no value minted in matching)")
    out.append("- round-trip: deposit(x) then withdraw(all) returns <= x (never more)")
    out.append("- no-free-value: no sequence of ops leaves caller richer with protocol unchanged")
    out.append("- cross-market: an action in market A never reduces market B's solvency backing")

    report = "\n".join(out)
    print(report)
    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        open(a.out, "w", encoding="utf-8").write(report)
        print(f"\n[written to {a.out}]")


def iter_sol_all(root):
    """Like iter_sol but INCLUDES test/ (to find invariant harnesses)."""
    if os.path.isfile(root):
        return
    for cur, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d.lower() not in SKIP]
        for f in files:
            if f.endswith(".sol"):
                yield os.path.join(cur, f)


if __name__ == "__main__":
    main()
