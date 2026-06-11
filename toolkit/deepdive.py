#!/usr/bin/env python3
"""deepdive.py - spin up a per-target BESPOKE-tooling workspace for a deep dive.

Universal recon/hypothesize AIM (which file, which function). The FIND almost always comes from a
tool built FOR this one protocol - the Ledgity verbatim-formula reimplementation, a chimera
invariant. This kills the blank-page friction of a deep dive: it seeds a workspace from what we
already know (recon leads, ROUTED to the right bespoke-tool form) + drops runnable skeletons for
the three forms.

    python deepdive.py <target-src-dir> [--name NAME] [--out DIR]

Writes <out>/ (default hunts/<name>/model/):
  NOTES.md            - deep-dive worksheet: target summary, recon leads routed to a tool form, menu
  model.py            - Python differential-model skeleton (reimplement core math, diff vs live/fork)
  Differential.t.sol  - Foundry differential-test skeleton (reference reimpl, fuzz-diff, NO RPC)
and prints the `scaffold.py --engine chimera` command for the fuzz-harness form.

Two-speed model: universal pipeline = breadth/aim (cheap, on everything); this = depth/find (only
after you COMMIT to a target). The bespoke tool is disposable; the recipe for building it is not.
ASCII output.
"""

import argparse
import os

import recon  # reuse our detectors (same folder)

# Route a recon lead to the bespoke-tool form most likely to FIND its bug.
# math/formula leads (reimplement the number -> diff) vs state/auth leads (a property / state-machine).
# Keep this to genuine NUMERIC-formula detectors; replay/auth/MEV go to the invariant route.
MATH_HINTS = ("ERC4626", "INTEREST-INDEX", "LIQUIDATION", "ORACLE", "REWARD")


def lead_form(detector_title):
    """'differential' for math/formula detectors, else 'invariant' (state/auth)."""
    return "differential" if any(h.lower() in detector_title.lower() for h in MATH_HINTS) else "invariant"


def collect_leads(src_dir, max_prio=1):
    """Run recon over src_dir; return [(rel, line, title, note, prio, form)] for prio <= max_prio."""
    out = []
    for path in recon.iter_sol(src_dir):
        rel = os.path.relpath(path, src_dir).replace("\\", "/")
        if "/test" in ("/" + rel) or rel.startswith("test") or "/echidna/" in ("/" + rel):
            continue  # skip the target's own test/fuzz harnesses
        try:
            text = open(path, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        for title, fn, _ in recon.DETECTORS:
            for lead in fn(text, rel):
                rel_, line, _snip, note, prio = lead
                if prio <= max_prio:
                    out.append((rel_, line, title, note, prio, lead_form(title)))
    out.sort(key=lambda x: (x[4], x[0], x[1]))  # by priority, then file, then line
    return out


def top_files(leads, n=5):
    """Files with the most high-signal ([!] prio 0) leads -> the Tier-1 deep-dive targets."""
    counts = {}
    for rel, _line, _t, _note, prio, _form in leads:
        if prio == 0:
            counts[rel] = counts.get(rel, 0) + 1
    return sorted(counts.items(), key=lambda kv: -kv[1])[:n]


def _lead_block(leads, form):
    rows = [l for l in leads if l[5] == form]
    if not rows:
        return "  (none surfaced by recon -- read the core by hand; recon AIMS, it doesn't FIND)\n"
    out = []
    for rel, line, title, note, prio, _form in rows[:18]:
        mark = "[!]" if prio == 0 else "[.]"
        out.append(f"- {mark} `{rel}:{line}` -- {note}  _( {title} )_")
    if len(rows) > 18:
        out.append(f"  ... and {len(rows) - 18} more")
    return "\n".join(out) + "\n"


def gen_notes(name, src_dir, leads):
    tf = top_files(leads)
    tier1 = "\n".join(f"- `{f}`  ({c} high-signal lead{'s' if c != 1 else ''})" for f, c in tf) \
        or "  (no [!] leads -- pick the most economically central file by hand)"
    return f"""# Deep dive: {name}

Target src: `{src_dir}`  |  recon leads: {len(leads)} (<= [.] prio)  |  fill the worklog as you go.

> Two-speed reminder: recon/hypothesize AIMED you here; the FIND comes from a tool built for THIS
> protocol. Pick a form below, build the smallest thing that can be RED, make it red, then fix-diff.

## Tier-1 files (most high-signal leads -> read these first)
{tier1}

## Route A -- DIFFERENTIAL MODEL  (math/formula leads; the Ledgity method)
Reimplement the suspect formula cleanly (Python `model.py` OR Solidity `Differential.t.sol`) and
diff it against the contract over fuzzed inputs. Catches rounding / precision / off-by-one / wrong
operator that generic invariants miss. Best when the bug is "the math is subtly wrong".
{_lead_block(leads, 'differential')}
## Route B -- BESPOKE INVARIANT  (state/auth leads; chimera fuzz)
A property meaningful only for THIS protocol, dropped into a chimera harness and fuzzed under
Foundry+Echidna+Medusa. Best when the bug is "a reachable state breaks an accounting/auth rule".
Generate the harness:
    python toolkit/scaffold.py {src_dir}/<Core>.sol <Core> --engine chimera --out {os.path.dirname(src_dir) or '.'}/recon
Then write the protocol-specific `property_*` (e.g. `sum(local) == global` across EVERY path).
{_lead_block(leads, 'invariant')}
## Bespoke-invariant starters (curate for this target; full menu: `hypothesize.py {src_dir}`)
- conservation: SUM(per-user accounting) == the global aggregate, at ALL times, across EVERY path
  (mint/burn/redeem/liquidate/redistribute) -- the #1 fork-CDP / vault break.
- round-trip: do(x) then undo() never leaves the caller richer (rounding must favor the protocol).
- accrual-before-change: any setRate/setFee/addPrincipal accrues/settles the OLD state FIRST.
- price-source parity: liquidation and settlement read the SAME price; no cheaper bypass path.
- monotonic-where-promised: an index/share-price only moves in the direction the design promises.

## Route C -- STATE-MACHINE MODEL  (when the bug is an illegal transition)
Encode the intended states + legal transitions; fuzz the real contract; flag any reachable state
the model calls impossible. Heavier -- reach for it when A/B don't fit (e.g. multi-phase auctions,
queue/epoch lifecycles). Sketch the states here before coding.

## Worklog
- [ ] picked form: ___  (file/formula: ___)
- [ ] smallest RED check written  -> reproduces? ___
- [ ] verified vs VERIFY kill-gates (FP? known? severity honest?)
- [ ] -> HUNT.md verdict + ledger
"""


def gen_model_py(name):
    return f'''#!/usr/bin/env python3
"""Differential model for {name} - the Ledgity method, generalized.

Reimplement the suspect formula CLEANLY here, then diff it against the live contract. A clean
reference catches rounding / precision / off-by-one / wrong-operator bugs that a generic invariant
never sees. Prefer Differential.t.sol (Foundry fuzz, no RPC) when you have the source; use this
Python path for a fork eth_call diff or a quick formula sanity-check.
"""


def reference(*args):
    """TODO: a clean, spec-faithful reimplementation of ONE suspect function.

    Write it from the WHITEPAPER / NatSpec, not by copying the contract (copying copies the bug).
    e.g. simple interest: (principal * rate_bps * dt) // (10_000 * SECONDS_IN_YEAR)
    """
    raise NotImplementedError


def fuzz_diff(n=100_000):
    """Feed `reference` and the contract the SAME inputs; assert equality; print the first divergence.

    No-RPC: just compare `reference` against a hand-derived expected table.
    Fork mode: web3 -> contract.functions.<view>(x).call(block_identifier=BLOCK) vs reference(x).
    """
    # import random  # vary inputs by index, not Math.random
    # for i in range(n):
    #     x = ...
    #     got = reference(x)
    #     exp = ...            # contract eth_call OR expected
    #     if got != exp:
    #         print(f"DIVERGENCE at {{x}}: ref={{got}} contract={{exp}}"); return False
    # print("no divergence in", n, "samples"); return True
    raise NotImplementedError


if __name__ == "__main__":
    fuzz_diff()
'''


def gen_differential_sol(name):
    return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {{Test}} from "forge-std/Test.sol";
// import {{{name}}} from "../src/{name}.sol";   // TODO: fix path

// Foundry DIFFERENTIAL test for {name}: a clean REFERENCE reimplementation of ONE suspect formula,
// fuzzed against the live contract. assertEq(reference(x), target.f(x)) for ALL x -> any divergence
// is a bug in one of them. No RPC needed when you have the source. The Ledgity method, in-repo.
//   run (WSL/CI): forge test --mc {name}Differential

library {name}Reference {{
    // TODO: reimplement the suspect function from the SPEC (not by copying the contract).
    function f(uint256 x) internal pure returns (uint256) {{
        return x; // <-- replace with the spec-faithful formula
    }}
}}

contract {name}Differential is Test {{
    // {name} internal target;

    function setUp() public {{
        // target = new {name}(/* concrete ctor args */);
    }}

    function testFuzz_diff(uint256 x) public {{
        x = bound(x, 0, 1e30);
        // assertEq({name}Reference.f(x), target.f(x), "DIVERGENCE -> a bug in the contract or the ref");
    }}
}}
'''


def main():
    ap = argparse.ArgumentParser(description="Per-target bespoke-tooling workspace generator (deep dive)")
    ap.add_argument("src", help="target source dir (e.g. hunts/_volume/<t>/src)")
    ap.add_argument("--name", default=None, help="workspace name (default: basename of the repo)")
    ap.add_argument("--out", default=None, help="output dir (default: hunts/<name>/model)")
    args = ap.parse_args()

    if not os.path.isdir(args.src):
        print(f"[!] not a directory: {args.src}")
        return 1
    name = args.name or os.path.basename(os.path.abspath(args.src).rstrip("/\\")) or "target"
    out = args.out or os.path.join("hunts", name, "model")

    leads = collect_leads(args.src)
    files = {
        "NOTES.md": gen_notes(name, args.src, leads),
        "model.py": gen_model_py(name),
        f"{name}Differential.t.sol": gen_differential_sol(name),
    }
    os.makedirs(out, exist_ok=True)
    for fn, content in files.items():
        with open(os.path.join(out, fn), "w", encoding="utf-8") as fh:
            fh.write(content)

    diff = sum(1 for l in leads if l[5] == "differential")
    inv = len(leads) - diff
    print(f"[deep-dive workspace -> {out}]  ({len(leads)} leads: {diff} differential / {inv} invariant)")
    print("  NOTES.md (start here) + model.py (Python diff) + "
          f"{name}Differential.t.sol (Foundry diff)")
    print(f"  next: pick a Tier-1 file in NOTES.md, build the smallest RED check, make it red.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
