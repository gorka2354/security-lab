#!/usr/bin/env python3
"""hypothesize.py - turn a contract's STRUCTURE into attack-hypothesis seeds.

recon.py finds vuln *patterns* (auditor-checklist mode). This is the other mode:
it extracts structural "data" so a human (L4) builds hypotheses for bugs the audit
MISSED - emergent/cross-component, round-trip asymmetry, un-checked state.
(See vault note "Метод - охота гипотезами".)

    python toolkit/hypothesize.py <repo-or-file> [--out worksheet.md]

Outputs a hypothesis worksheet:
  1. OPERATION MAP + INVERSE PAIRS  - deposit<->withdraw ... -> round-trip asymmetry.
  2. SHARED-STATE MATRIX            - storage fields written by MANY entry-fns ->
     emergent-interaction candidates (interleave A and B; does an invariant break?).
  3. THEIR DECLARED INVARIANTS      - what their fuzz harness asserts -> the COMPLEMENT
     is your hunting ground (write a STRONGER invariant, fuzz it).

COMBINE (analyzer -> hypothesizer): the shared-state matrix follows the CALL GRAPH
(transitive) so writes done via library/internal setters (state.executeX(...),
Lib.foo(state,...)) are attributed to the entry fn - "poor man's dataflow" (Grade A,
runs anywhere). The accurate version uses Slither's `state_variables_written` (Grade B,
CI/Linux); see ROADMAP "combine engines". ASCII output. Heuristic - it surfaces, you reason.
"""

import argparse
import os
import re

SKIP = {"lib", "node_modules", "out", "artifacts", "cache", ".git", "forge-std",
        "openzeppelin", "deprecated", "script", "scripts", "broadcast"}

INVERSE = {
    "deposit": "withdraw", "mint": "burn", "supply": "withdraw", "borrow": "repay",
    "stake": "unstake", "lock": "unlock", "add": "remove", "increase": "decrease",
    "wrap": "unwrap", "enter": "exit", "open": "close", "buy": "sell", "create": "delete",
}
INVERSE.update({v: k for k, v in INVERSE.items()})

FUNC = re.compile(r"function\s+(\w+)\s*(\([^{};]*?)\{", re.S)
ASSIGN = re.compile(r"\s*(=(?!=)|\+=|-=|\*=|/=|\+\+|--|\bdelete\b|\.push\b|\.pop\b)")
STATE = re.compile(r"\bstate(?:\.\w+){1,4}")
SETTER = re.compile(r"\.(set|push|pop|increase|decrease|mint|burn|transfer|create|delete|remove|add)\w*\s*\(")
CALL = re.compile(r"\b([a-zA-Z_]\w*)\s*\(")
ROOT = re.compile(r"state\.data\.\w+|state\.\w+")  # normalize a field to its top root


def iter_sol(root, with_tests=False):
    if os.path.isfile(root):
        yield root
        return
    for cur, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d.lower() not in SKIP]
        for f in files:
            if not f.endswith(".sol"):
                continue
            if not with_tests and ("test" in cur.lower() or "mock" in f.lower()):
                continue
            yield os.path.join(cur, f)


def func_records(text):
    """(name, blob, body) for every function; body bounded by the next function."""
    ms = list(FUNC.finditer(text))
    for i, m in enumerate(ms):
        end = ms[i + 1].start() if i + 1 < len(ms) else len(text)
        yield m.group(1), m.group(2), text[m.end():end]


def direct_writes(body):
    """State roots written DIRECTLY in this body (assignment or setter receiver)."""
    w = set()
    for m in STATE.finditer(body):
        tail = body[m.end():m.end() + 8]
        if ASSIGN.match(tail):
            w.add(_root(m.group(0)))
    for m in re.finditer(r"\bstate(?:\.\w+){0,3}", body):
        if SETTER.match(body[m.end():m.end() + 40]) and m.group(0) != "state":
            w.add(_root(m.group(0)))
    return w


def _root(s):
    m = ROOT.match(s)
    return m.group(0) if m else s


def verb_of(name):
    n = name[0].lower() + name[1:] if name else name
    for v in INVERSE:
        if n.startswith(v):
            return v
    m = re.match(r"(set|get|update|claim|liquidate|swap|transfer|redeem|compensate)", n)
    return m.group(1) if m else None


def main():
    ap = argparse.ArgumentParser(description="Extract attack-hypothesis seeds from contracts")
    ap.add_argument("path")
    ap.add_argument("--out")
    ap.add_argument("--top", type=int, default=18)
    a = ap.parse_args()
    base = a.path if os.path.isdir(a.path) else os.path.dirname(a.path)

    # 1) parse EVERY function (incl internal/library) -> direct writes + callees
    dwrites, callees, entry = {}, {}, {}
    for path in iter_sol(a.path):
        try:
            text = open(path, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        rel = os.path.relpath(path, base)
        for name, blob, body in func_records(text):
            dwrites.setdefault(name, set()).update(direct_writes(body))
            callees.setdefault(name, set()).update(CALL.findall(body))
            statey = re.search(r"\b(external|public)\b", blob) and not re.search(r"\b(view|pure)\b", blob)
            if statey:
                entry[name] = rel

    known = set(dwrites)
    for n in callees:
        callees[n] &= known  # keep only calls we can resolve by name

    # 2) transitive (call-graph) effective writes per function
    memo = {}

    def effective(n, stack):
        if n in memo:
            return memo[n]
        if n in stack:
            return set()
        stack = stack | {n}
        acc = set(dwrites.get(n, ()))
        for g in callees.get(n, ()):
            acc |= effective(g, stack)
        memo[n] = acc
        return acc

    field_writers = {}
    for n in entry:
        for root in effective(n, set()):
            field_writers.setdefault(root, set()).add(n)

    # 3) their declared invariants (scan tests too)
    invs = []
    for path in iter_sol(a.path, with_tests=True):
        if not re.search(r"(invariant|propert|echidna|medusa)", path, re.I):
            continue
        try:
            text = open(path, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        for m in re.finditer(r"function\s+(invariant_?\w+|propert\w+|echidna_?\w+)\s*\(", text):
            invs.append((os.path.basename(path), text[:m.start()].count("\n") + 1, m.group(1)))

    out = ["# Hypothesis worksheet: " + os.path.basename(os.path.abspath(a.path)),
           f"\n{len(entry)} entry fns; {len(dwrites)} total fns parsed (call-graph transitive). "
           "Heuristic seeds - reason over them.\n"]

    # section 1: inverse pairs
    out.append("## 1. Inverse pairs -> ROUND-TRIP asymmetry hypotheses")
    by_verb = {}
    for n in entry:
        v = verb_of(n)
        if v:
            by_verb.setdefault(v, []).append(n)
    seen = set()
    for v in sorted(by_verb):
        inv = INVERSE.get(v)
        if inv in by_verb and (inv, v) not in seen:
            seen.add((v, inv))
            out.append(f"- **{v} <-> {inv}**: `{', '.join(by_verb[v])}` vs `{', '.join(by_verb[inv])}`")
            out.append(f"    -> {v} then {inv}: value leak (rounding/fee)? clean round-trip?")
    if not seen:
        out.append("  (no obvious inverse verb pairs)")

    # section 2: shared-state (transitive)
    out.append("\n## 2. Shared-state -> EMERGENT-interaction hypotheses  (call-graph transitive)")
    out.append("_storage roots written by MANY entry-fns: interleave a CROSS-FILE pair; invariant break?_\n")
    ranked = sorted(((r, w) for r, w in field_writers.items() if len(w) >= 2), key=lambda kv: -len(kv[1]))
    if not ranked:
        out.append("  (none with >=2 writers - try --slither/Grade B for accurate dataflow)")
    for root, writers in ranked[:a.top]:
        ws = sorted(writers)
        out.append(f"- `{root}`  <- {len(writers)} fns: {', '.join(ws[:9])}" + (" ..." if len(ws) > 9 else ""))
    out.append("\n  Pick a root written by 3+ entry-fns -> those fns are emergent-interaction candidates.")

    # section 3: their invariants
    out.append("\n## 3. Their DECLARED invariants (write what's NOT here)")
    if invs:
        for f, ln, nm in invs[:40]:
            out.append(f"- `{f}:{ln}` {nm}")
        out.append(f"\n  {len(invs)} declared. Ask: what cross-component / cross-market / round-trip "
                   "property is MISSING? Write it stronger, fuzz it.")
    else:
        out.append("  (no invariant harness found - point at the repo ROOT to scan test/; "
                   "or they don't fuzz -> even more room)")

    out.append("\n## 4. Suggested STRONGER invariants (template)")
    for s in ["solvency: SUM(user claims) <= protocol assets, ALL times, ALL markets",
              "conservation: total debt issued == total credit owed (no value minted in matching)",
              "round-trip: do(x) then undo() leaves caller <= start (never richer)",
              "cross-component: an op in A never breaks B's invariant via shared state",
              "no-free-value: no op sequence leaves caller richer with protocol unchanged"]:
        out.append(f"- {s}")

    report = "\n".join(out)
    print(report)
    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        open(a.out, "w", encoding="utf-8").write(report)
        print(f"\n[written to {a.out}]")


if __name__ == "__main__":
    main()
