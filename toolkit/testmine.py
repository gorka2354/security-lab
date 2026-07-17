#!/usr/bin/env python3
"""testmine.py - mine a project's OWN test suite for the invariants it checks, accumulate CROSS-PROJECT
frequency stats, and surface the frequently-tested properties as a detector / invariant-seed backlog.

The idea: what real projects TEST is what actually matters. A property asserted across MANY projects is
a universal invariant worth a detector (or an ItyFuzz/echidna seed). So every project we touch becomes a
compounding data asset (monitor/test-stats.json) that drives DATA-DRIVEN detector creation - the same loop as
our DeFiHackLabs hack-PoC mining, but on the projects' OWN test suites instead of curated hacks.

    python toolkit/testmine.py <repo> --project <name>   # mine its tests + record into the stats
    python toolkit/testmine.py --stats [--top 30]        # most frequently-tested properties (cross-project)
    python toolkit/testmine.py --backlog [--min 3]       # frequent + not yet a detector -> candidate backlog

Pure extraction (mine_repo) -> golden-tested. Stdlib only. White-hat: reads public test code only.
"""
import argparse
import datetime
import json
import os
import re
import sys
from collections import Counter

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
STATS = "monitor/test-stats.json"

# test files across the common stacks
_TESTFILE = re.compile(r"(?i)(\.t\.sol|\.spec\.(ts|js)|\.test\.(ts|js)|(^|/)(test|tests|invariant|echidna|"
                       r"medusa|properties|fuzz)/)")
# invariant / property entry points (foundry invariant_, echidna_, medusa property_, scribble)
_INVFN = re.compile(r"function\s+(invariant_\w+|echidna_\w+|property_\w+|prop_\w+|inv_\w+)\s*\(")
# an assertion + its argument blob (foundry forge-std + ds-test + chai-style expect)
_ASSERT = re.compile(r"(?:assert\w*|require|expect|invariant)\s*\(([^;{}]{0,300})")
# a method/getter call inside an assertion -> the property surface being checked (totalAssets(), balanceOf(),
# convertToShares(), getReserves()...). The bare camel/snake name is the "subject".
_CALL = re.compile(r"\b([a-zA-Z_]\w{2,})\s*\(")
# noise: assertion verbs, test/vm scaffolding, types, generic helpers -> not a protocol property
_NOISE = {"assert", "asserteq", "assertgt", "assertge", "assertlt", "assertle", "asserttrue", "assertfalse",
          "assertapproxeqabs", "assertapproxeqrel", "require", "expect", "invariant", "vm", "console", "log",
          "emit", "bound", "uint256", "uint", "int256", "address", "bytes32", "bytes", "string", "keccak256",
          "abi", "encode", "decode", "encodepacked", "to", "be", "equal", "revertedwith", "deal", "prank",
          "startprank", "stopprank", "warp", "roll", "expectrevert", "expectemit", "label", "assume", "if",
          "for", "while", "return", "new", "type", "addr", "makeaddr", "hoax", "msgsender",
          # forge-std string utils + ERC interface casts + ERC20 metadata (tested for completeness, not a
          # security invariant) -> noise, keeps the backlog to real protocol surfaces (max*/convert*/solvency).
          "concat", "tostring", "tohexstring", "ierc20", "ierc721", "ierc1155", "ierc4626", "name", "symbol",
          "vm_addr", "boundprivatekey", "parseuint", "envuint", "envaddress", "readfile",
          "uint8", "uint16", "uint32", "uint64", "uint128", "int128", "bytes4", "version", "getaddress"}


def _testfiles(repo):
    out = []
    for cur, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "lib", "out", "cache", "artifacts")]
        for f in files:
            rel = os.path.relpath(os.path.join(cur, f), repo).replace("\\", "/")
            if _TESTFILE.search("/" + rel) and (f.endswith(".sol") or f.endswith((".ts", ".js"))):
                out.append(os.path.join(cur, f))
    return out


def mine_text(text):
    """Pure: one test file's text -> (invariant_name_stems, subject_counter, n_assertions). Unit-tested."""
    inv = [m.group(1) for m in _INVFN.finditer(text)]
    inv_stems = sorted({re.sub(r"^(invariant_|echidna_|property_|prop_|inv_)", "", n).lower() for n in inv})
    subjects = Counter()
    n_assert = 0
    for m in _ASSERT.finditer(text):
        n_assert += 1
        for c in _CALL.finditer(m.group(1)):
            name = c.group(1).lower()
            if name not in _NOISE and not name.startswith("test"):
                subjects[name] += 1
    return inv_stems, subjects, n_assert


def mine_repo(repo):
    """Mine every test file -> aggregate {invariants[], subjects:Counter, n_test_files, n_assertions}."""
    inv, subjects, n_assert, nfiles = set(), Counter(), 0, 0
    for path in _testfiles(repo):
        try:
            text = open(path, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        nfiles += 1
        i, s, na = mine_text(text)
        inv |= set(i)
        subjects.update(s)
        n_assert += na
    return {"invariants": sorted(inv), "subjects": subjects, "n_test_files": nfiles, "n_assertions": n_assert}


def load_stats():
    p = os.path.join(ROOT, STATS)
    if os.path.exists(p):
        try:
            return json.load(open(p, encoding="utf-8"))
        except Exception:
            pass
    return {"projects": {}, "subjects": {}, "invariant_stems": {}}


def save_stats(st):
    p = os.path.join(ROOT, STATS)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    json.dump(st, open(p, "w", encoding="utf-8"), indent=1, sort_keys=True)


def record(st, project, mined, date):
    """Fold one project's mined patterns into the cross-project stats (idempotent per project)."""
    st["projects"][project] = {"mined": date, "n_test_files": mined["n_test_files"],
                               "n_assertions": mined["n_assertions"]}
    for sub, cnt in mined["subjects"].items():
        e = st["subjects"].setdefault(sub, {"count": 0, "projects": []})
        if project not in e["projects"]:
            e["projects"].append(project)
        e["count"] = len(e["projects"])                    # count = HOW MANY PROJECTS test it (the real signal)
    for inv in mined["invariants"]:
        e = st["invariant_stems"].setdefault(inv, {"count": 0, "projects": []})
        if project not in e["projects"]:
            e["projects"].append(project)
        e["count"] = len(e["projects"])
    return st


# subjects already covered by a recon detector / known invariant menu -> not a NEW candidate
_COVERED = {"latestrounddata", "getpriceunsafe", "totalsupply", "balanceof", "converttoshares",
            "converttoassets", "_mint", "_burn", "transferfrom", "ecrecover", "_authorizeupgrade",
            # access-control (det_access/det_sibling/det_upgrade) + vault accounting (det_vault_share_math /
            # det_decimal_scale) + proxy (radar impl-upgrade): tested everywhere but already in our coverage.
            "hasrole", "owner", "default_admin_role", "allowance", "decimals", "asset", "implementation"}


def main():
    ap = argparse.ArgumentParser(description="Mine project test suites -> cross-project invariant stats")
    ap.add_argument("repo", nargs="?", help="path to a cloned repo to mine")
    ap.add_argument("--project", help="project name (key in the stats)")
    ap.add_argument("--stats", action="store_true", help="show the top frequently-tested properties")
    ap.add_argument("--backlog", action="store_true", help="frequent + not yet a detector -> candidates")
    ap.add_argument("--top", type=int, default=30)
    ap.add_argument("--min", type=int, default=3, help="backlog: min #projects testing a property")
    ap.add_argument("--date", default=datetime.date.today().isoformat())
    a = ap.parse_args()

    st = load_stats()
    if a.stats or a.backlog:
        subs = sorted(st["subjects"].items(), key=lambda kv: -kv[1]["count"])
        invs = sorted(st["invariant_stems"].items(), key=lambda kv: -kv[1]["count"])
        if a.backlog:
            cand = [(s, e) for s, e in subs if e["count"] >= a.min and s not in _COVERED]
            print(f"# testmine backlog: properties tested by >= {a.min} projects, no detector yet "
                  f"({len(st['projects'])} projects mined)")
            for s, e in cand[:a.top]:
                print(f"  {e['count']:>3}x  {s:28}  -> candidate detector/seed  ({', '.join(e['projects'][:4])})")
            if invs:
                print("  -- invariant function stems (already echidna/ItyFuzz-able directly) --")
                for s, e in [iv for iv in invs if iv[1]["count"] >= a.min][:10]:
                    print(f"  {e['count']:>3}x  invariant:{s}")
        else:
            print(f"# testmine stats: {len(st['projects'])} projects, top tested properties (by #projects)")
            for s, e in subs[:a.top]:
                print(f"  {e['count']:>3}x  {s}")
        return

    if not a.repo or not a.project:
        print("usage: testmine.py <repo> --project <name>   |   --stats   |   --backlog")
        return
    mined = mine_repo(a.repo)
    record(st, a.project, mined, a.date)
    save_stats(st)
    top = mined["subjects"].most_common(8)
    print(f"[testmine] {a.project}: {mined['n_test_files']} test file(s), {mined['n_assertions']} assertions, "
          f"{len(mined['invariants'])} invariants")
    print("  top tested here: " + ", ".join(f"{s}({c})" for s, c in top))
    print(f"  -> folded into {STATS} ({len(st['projects'])} projects total). `--backlog` for candidates.")


if __name__ == "__main__":
    main()
