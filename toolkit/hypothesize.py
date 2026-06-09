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

Section 5 closes the bridge: it AUTO-PROPOSES hypothesis TEXT (deterministic templates -
NO LLM/API) from the seeds, and fuses recon's pattern flags in - a fn that recon flagged
AND that shares state with others is a sharper emergent seed. The creative verification
stays with L4 (Claude in the console, interactive = free); an API is only needed for the
fully-autonomous mode. Generation is pure math; judgement is L4.
"""

import argparse
import os
import re

try:
    import recon  # same toolkit dir: bridge recon's pattern flags into the structural seeds
except Exception:  # recon optional; the structural seeds still work without it
    recon = None

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
# storage accessor conventions: `state.` (Size/Rheo), `s.`/`ds.` (diamond AppStorage),
# `$.` (OZ namespaced). Universal Grade-A heuristic; Grade B (Slither) is exact regardless.
ACC = r"(?:state|s|ds|\$)"
STATE = re.compile(r"\b" + ACC + r"(?:\.\w+){1,4}")
SETTER = re.compile(r"\.(set|push|pop|increase|decrease|mint|burn|transfer|create|delete|remove|add)\w*\s*\(")
CALL = re.compile(r"\b([a-zA-Z_]\w*)\s*\(")
ROOT = re.compile(ACC + r"\.data\.\w+|" + ACC + r"\.\w+")  # normalize a field to its top root

# getter-function storage accessors (diamond / AppStorage): `gs()`, `ws()`, `gameStorage()` -- a
# write looks like `gs().planets[id] = x`. Learned from Dark Forest (the s./state. matrix was BLIND
# to gs()/ws()). Detect the getter NAMES dynamically (low FP: only fns declared `returns (X storage)`),
# then treat `getter().field` as state access too. (Storage-pointer-aliased writes still need Grade B.)
GETTER_DECL = re.compile(r"function\s+(\w+)\s*\(\s*\)\s*internal\s+(?:pure\s+|view\s+)?returns\s*\(\s*\w+\s+storage\b")


def find_getters(text):
    """Storage-getter fn names declared `function NAME() internal ... returns (X storage)`."""
    return set(GETTER_DECL.findall(text))


def build_state_re(getters):
    """STATE regex covering local accessors (state./s./ds./$.) AND getter-fn accessors
    (gs()./ws().) so the shared-state matrix sees diamond/AppStorage-getter storage."""
    alts = [r"state|s|ds|\$"]
    if getters:
        alts.append("|".join(re.escape(g) + r"\(\)" for g in sorted(getters)))
    return re.compile(r"(?<![A-Za-z0-9_])(?:" + "|".join(alts) + r")(?:\.\w+){1,4}")


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


def direct_writes(body, state_re=None):
    """State roots written DIRECTLY in this body (assignment or setter receiver). `state_re`
    defaults to the base STATE; main() passes a getter-aware regex (gs()/ws()) per repo."""
    state_re = state_re or STATE
    w = set()
    for m in state_re.finditer(body):
        tail = body[m.end():m.end() + 8]
        if ASSIGN.match(tail):
            w.add(_root(m.group(0)))
    for m in re.finditer(r"\b" + ACC + r"(?:\.\w+){0,3}", body):
        if SETTER.match(body[m.end():m.end() + 40]) and "." in m.group(0):
            w.add(_root(m.group(0)))
    return w


def _root(s):
    gm = re.match(r"\w+\(\)\.\w+", s)   # getter form gs().planets... -> root gs().planets
    if gm:
        return gm.group(0)
    m = ROOT.match(s)
    return m.group(0) if m else s


def verb_of(name):
    n = name[0].lower() + name[1:] if name else name
    for v in INVERSE:
        if n.startswith(v):
            return v
    m = re.match(r"(set|get|update|claim|liquidate|swap|transfer|redeem|compensate)", n)
    return m.group(1) if m else None


def slither_field_writers(target):
    """Grade B (accurate): per-entry-fn state writes via Slither's dataflow
    (`all_state_variables_written` is transitive through internal/library calls).
    Returns {field: set(fn names)} or None if Slither/compile unavailable. Slither
    needs the project to compile (solc/forge) -> runs in CI/Linux, not this Windows box."""
    try:
        from slither import Slither
    except Exception:
        return None
    try:
        sl = Slither(target)
    except Exception:
        return None
    fw = {}
    for c in sl.contracts:
        for f in c.functions:
            if f.visibility not in ("public", "external"):
                continue
            try:
                written = f.all_state_variables_written()  # view/pure write nothing
            except Exception:
                continue
            for sv in written:
                fw.setdefault(getattr(sv, "canonical_name", str(sv)), set()).add(f.name)
    return fw or None


def flags_from_text(text, rel):
    """Bridge: {function name -> set(recon detector keys)} for one file. A function that
    recon FLAGGED (a known pattern) and that also shares mutable state with others (the
    shared-state matrix) is a sharper emergent-attack seed than either signal alone.
    Pure structural join - no API."""
    out = {}
    if recon is None:
        return out
    for title, fn, _ in recon.DETECTORS:
        try:
            leads = fn(text, rel)
        except Exception:
            continue
        for tup in leads:
            m = re.search(r"function\s+(\w+)", tup[2] or "")
            if m:
                out.setdefault(m.group(1), set()).add(recon.det_key(title))
    return out


def auto_propose(by_verb, pairs, ranked, rflags, invs):
    """Deterministic hypothesis TEXT from the structural seeds (NO LLM/API): round-trips from
    inverse pairs, emergent interactions from shared state (prioritized when recon also flagged
    a writer), and the missing-invariant complement. L4 picks the sharpest and proves it; this
    just drafts candidates from math."""
    props = []
    for (v, inv) in pairs:
        a = (by_verb.get(v) or [None])[0]
        b = (by_verb.get(inv) or [None])[0]
        if a and b:
            props.append(f"ROUND-TRIP `{a}` -> `{b}`: assert the caller is NEVER richer after "
                         f"(rounding/fee leak); fuzz forall amounts -> post <= pre.")
    for root, writers in ranked[:6]:
        ws = sorted(writers)
        flagged = [w for w in ws if w in rflags]
        if flagged:
            f = flagged[0]
            others = [w for w in ws if w != f][:2]
            keys = ",".join(sorted(rflags[f]))
            props.append(f"EMERGENT+RECON `{f}` (recon:{keys}) shares `{root}` with {others} -> "
                         f"interleave: can a co-writer re-trigger {f}'s effect or desync `{root}`? "
                         f"(assert `{root}` conservation across the pair)")
        elif len(ws) >= 3:
            props.append(f"EMERGENT `{root}`: {len(ws)} writers ({', '.join(ws[:3])} ...) -> interleave "
                         f"the 2 most cross-file; assert the `{root}` invariant survives.")
    declared = " ".join(nm for _, _, nm in invs).lower()
    std = [("solvency", "SUM(user claims) <= protocol assets, all markets/times"),
           ("conservation", "total debt issued == total credit owed (no value minted in matching)"),
           ("round", "do(x) then undo() leaves the caller <= start (never richer)"),
           ("cross", "an op in A never breaks B's invariant via shared state"),
           ("free", "no op sequence leaves caller richer with protocol unchanged")]
    missing = [d for k, d in std if k not in declared]
    if missing:
        props.append("INVARIANT-GAP (not asserted by their harness): " + "; ".join(missing[:3])
                     + " -> write STRONGER + fuzz.")
    return props


def main():
    ap = argparse.ArgumentParser(description="Extract attack-hypothesis seeds from contracts")
    ap.add_argument("path")
    ap.add_argument("--out")
    ap.add_argument("--top", type=int, default=18)
    ap.add_argument("--no-slither", action="store_true", help="force Grade A (call-graph regex)")
    ap.add_argument("--no-recon", action="store_true", help="skip the recon->hypothesizer bridge")
    a = ap.parse_args()
    base = a.path if os.path.isdir(a.path) else os.path.dirname(a.path)

    # 0) pre-pass: learn storage-getter accessors (gs()/ws()/gameStorage()) across the repo so
    #    the shared-state matrix sees diamond/AppStorage-getter storage (Dark Forest fix).
    getters = set()
    for path in iter_sol(a.path):
        try:
            getters |= find_getters(open(path, encoding="utf-8", errors="ignore").read())
        except Exception:
            pass
    dyn_state = build_state_re(getters)

    # 1) parse EVERY function (incl internal/library) -> direct writes + callees
    dwrites, callees, entry = {}, {}, {}
    for path in iter_sol(a.path):
        try:
            text = open(path, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        rel = os.path.relpath(path, base)
        for name, blob, body in func_records(text):
            dwrites.setdefault(name, set()).update(direct_writes(body, dyn_state))
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

    backend = "call-graph regex (Grade A)"
    field_writers = None if a.no_slither else slither_field_writers(a.path)
    if field_writers:
        backend = "Slither dataflow (Grade B)"
        # keep only fields written by entry fns we parsed (drop library-internal noise)
        field_writers = {f: {n for n in w if n in entry} for f, w in field_writers.items()}
        field_writers = {f: w for f, w in field_writers.items() if w}
    else:
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
           f"\n{len(entry)} entry fns parsed. State-write backend: **{backend}**. "
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

    # bridge: recon pattern flags per function (analyzer -> hypothesizer), then auto-propose
    rflags = {}
    if recon is not None and not a.no_recon:
        for path in iter_sol(a.path):
            try:
                t = open(path, encoding="utf-8", errors="ignore").read()
            except Exception:
                continue
            for fn_name, keys in flags_from_text(t, os.path.relpath(path, base)).items():
                rflags.setdefault(fn_name, set()).update(keys)

    out.append("\n## 5. AUTO-PROPOSED hypotheses (deterministic templates; NO LLM/API)")
    bridged = sum(1 for r, w in ranked if any(x in rflags for x in w))
    out.append(f"_pure-math draft from sections 1-3 + recon ({len(rflags)} flagged fns, "
               f"{bridged} shared-state roots touch a flagged fn). L4 verifies; no API in interactive mode._\n")
    props = auto_propose(by_verb, seen, ranked, rflags, invs)
    if props:
        for p in props[:14]:
            out.append(f"- {p}")
    else:
        out.append("  (not enough structure -> reason over sections 1-4 manually)")

    report = "\n".join(out)
    print(report)
    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        open(a.out, "w", encoding="utf-8").write(report)
        print(f"\n[written to {a.out}]")


if __name__ == "__main__":
    main()
