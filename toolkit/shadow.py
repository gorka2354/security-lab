#!/usr/bin/env python3
"""shadow.py - measure recon's RECALL against a labelled corpus of real bug types (where are we blind?).

We tune detectors by intuition + the targets we happen to hit. This measures it with DATA: run recon
over DeFiVulnLabs (SunWeb3Sec/DeFiVulnLabs -- 48 vulnerability types, each a self-contained Foundry test
with the vulnerable contract INLINE + the type in the filename). For each file we know the expected bug
class; we check whether the recon detector that SHOULD fire actually does.

    python shadow.py [--repo <DeFiVulnLabs path>] [--clone] [--show hit|miss|uncovered|unmapped|all]

Verdict per file:
  HIT       - an expected detector fired (recon catches this class)
  MISS      - recon HAS a detector for this class but it didn't fire here -> a precision/regex gap to fix
  UNCOVERED - recon has NO detector for this class -> a NEW-detector candidate (the blind spot)
  UNMAPPED  - the filename didn't match our bench map -> refine BENCH (printed so we can)

Output: recall over COVERED classes + a ranked blind-spot list (the data-driven detector backlog).
Reuses recon.detect_all / recon.det_key. ASCII.
"""

import argparse
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import recon  # noqa: E402

DEFIVULNLABS_URL = "https://github.com/SunWeb3Sec/DeFiVulnLabs.git"

# filename-keyword -> expected recon det_key(s). None = recon has NO detector for this class (a blind spot
# we WANT to surface). Keywords are matched against the normalized (lowercased, separators->'-') filename;
# first match wins, so list more-specific keywords first.
BENCH = [
    ("read-only-reentrancy", None),          # reasoning-tier; recon can't (yet)
    ("readonlyreentrancy", None),
    ("reentrancy", {"reentrancy", "nftcallback"}),
    ("unsafe-downcast", {"downcast"}),
    ("downcast", {"downcast"}),
    ("divide-before-multiply", {"precision"}),
    ("divmultiply", {"precision"}),
    ("precision-loss", {"precision"}),
    ("precision", {"precision"}),
    ("abi-encodepacked", {"encodepacked"}),
    ("encodepacked", {"encodepacked"}),
    ("hash-collision", {"encodepacked"}),
    ("fee-on-transfer", {"feeontransfer"}),
    ("deflation", {"feeontransfer"}),
    ("delete", {"delmap"}),
    ("signature-replay", {"signature"}),
    ("signature", {"signature"}),
    ("replay", {"signature"}),
    ("ecdsa", {"signature"}),
    ("ecrecover", {"signature"}),
    ("array-deletion", {"delmap"}),
    ("struct-deletion", {"delmap"}),
    ("deletion", {"delmap"}),
    ("returnvalue", {"unchecked"}),
    ("returnfalse", {"unchecked"}),
    ("return-break", {"unchecked"}),
    ("unsafecall", {"arbcall", "danger"}),
    ("storage-collision", None),             # proxy slot collision - reasoning
    ("storagecollision", None),
    ("unsafe-delegatecall", {"danger", "arbcall"}),
    ("delegatecall", {"danger", "arbcall"}),
    ("selfdestruct", {"danger"}),
    ("txorigin", {"danger"}),
    ("tx-origin", {"danger"}),
    ("access-control", {"access", "sibling"}),
    ("accesscontrol", {"access", "sibling"}),
    ("visibility", {"access"}),
    ("unprotected", {"access"}),
    ("unchecked-return", {"unchecked"}),
    ("unchecked", {"unchecked"}),
    ("return-value", {"unchecked"}),
    ("random", {"weakrand"}),
    ("weak-random", {"weakrand"}),
    ("price-oracle", {"oracle"}),
    ("oracle", {"oracle"}),
    ("price-manipulation", {"oracle"}),
    ("slippage", {"swapguard"}),
    ("sandwich", {"swapguard"}),
    ("first-deposit", {"erc4626"}),
    ("vault-inflation", {"erc4626"}),
    ("erc4626", {"erc4626"}),
    ("inflation", {"erc4626"}),
    ("uninitialized", {"upgrade", "danger"}),
    ("phantom", None),                       # phantom function (fallback permit)
    ("flashloan", None),                     # missing initiator/lender check
    ("erc777", None),                        # extend nft-callback to tokensReceived
    ("self-transfer", None),
    ("transient", None),                     # EIP-1153 misuse
    ("dos", None),                           # generic DoS
    ("overflow", None),                      # pre-0.8 / unchecked block math
    ("underflow", None),
    ("bypasscontract", None),                # bypass isContract (we have l2-footgun, but different framing)
    ("bypass-contract", None),
]


def normalize_name(fname):
    """A test filename -> a lowercase keyword-friendly slug (drop dir/ext, separators -> '-')."""
    base = os.path.basename(fname).rsplit(".", 1)[0].lower()
    for ch in ("_", " ", "."):
        base = base.replace(ch, "-")
    return base


def expected_keys(slug):
    """(matched_keyword, expected_det_keys|None) for a slug, or (None, None) if UNMAPPED."""
    for kw, keys in BENCH:
        if kw in slug:
            return kw, keys
    return None, None


def fired_keys(text, rel):
    """The set of recon det_keys whose detector produced >=1 lead on this file."""
    res = recon.detect_all(text, rel)
    return {recon.det_key(title) for title, leads in res.items() if leads}


def classify(expected, fired):
    """HIT / MISS / UNCOVERED / UNMAPPED from (matched_keyword, expected_keys) + fired keys."""
    kw, keys = expected
    if kw is None:
        return "UNMAPPED"
    if keys is None:
        return "UNCOVERED"          # recon has no detector for this class
    return "HIT" if (fired & keys) else "MISS"


def _iter_corpus(repo):
    """Yield (relpath, text) for DeFiVulnLabs vuln files (src/test/*.sol)."""
    for root in (os.path.join(repo, "src", "test"), os.path.join(repo, "test"), repo):
        if not os.path.isdir(root):
            continue
        for dp, _dn, fns in os.walk(root):
            parts = dp.replace("\\", "/").split("/")
            if any(seg in parts for seg in ("lib", "node_modules", ".git", "out")):
                continue  # skip build/dep dirs by path SEGMENT (not substring -> 'cache/' parent is fine)
            for fn in fns:
                if fn.endswith(".sol"):
                    p = os.path.join(dp, fn)
                    try:
                        yield os.path.relpath(p, repo).replace("\\", "/"), open(p, encoding="utf-8", errors="ignore").read()
                    except Exception:
                        continue
        break  # only the first existing root


def main():
    ap = argparse.ArgumentParser(description="recon recall benchmark on DeFiVulnLabs (find recon's blind spots)")
    ap.add_argument("--repo", default="cache/DeFiVulnLabs", help="path to a DeFiVulnLabs clone")
    ap.add_argument("--clone", action="store_true", help="git clone DeFiVulnLabs into --repo first")
    ap.add_argument("--show", default="miss,uncovered,unmapped",
                    help="comma list of verdicts to print per-file (hit/miss/uncovered/unmapped/all)")
    args = ap.parse_args()

    if args.clone or not os.path.isdir(args.repo):
        os.makedirs(os.path.dirname(os.path.abspath(args.repo)) or ".", exist_ok=True)
        print(f"[cloning {DEFIVULNLABS_URL} -> {args.repo}]")
        subprocess.run(["git", "clone", "--depth", "1", DEFIVULNLABS_URL, args.repo],
                       capture_output=True, text=True)
    if not os.path.isdir(args.repo):
        print(f"[!] no corpus at {args.repo} (clone failed?) -- pass --repo or --clone")
        return 1

    show = {s.strip() for s in args.show.lower().split(",")}
    buckets = {"HIT": [], "MISS": [], "UNCOVERED": [], "UNMAPPED": []}
    for rel, text in _iter_corpus(args.repo):
        slug = normalize_name(rel)
        exp = expected_keys(slug)
        verdict = classify(exp, fired_keys(text, rel))
        buckets[verdict].append((slug, exp[0], exp[1], rel))

    print(f"\n# shadow benchmark: recon vs DeFiVulnLabs  ({sum(len(v) for v in buckets.values())} files)\n")
    for v in ("MISS", "UNCOVERED", "UNMAPPED", "HIT"):
        if "all" not in show and v.lower() not in show:
            continue
        rows = buckets[v]
        if not rows:
            continue
        print(f"## {v}  ({len(rows)})")
        for slug, kw, keys, _rel in sorted(rows):
            tail = f"expected={sorted(keys)}" if keys else ("(no recon detector for this class)" if kw else "(no bench keyword matched)")
            print(f"  {slug:42}  {tail}")
        print()

    hit, miss, unc = len(buckets["HIT"]), len(buckets["MISS"]), len(buckets["UNCOVERED"])
    covered = hit + miss
    recall = (hit / covered * 100) if covered else 0.0
    print("=" * 64)
    print(f"RECALL over covered classes: {hit}/{covered} = {recall:.0f}%   "
          f"(MISS={miss} precision-gaps, UNCOVERED={unc} blind-spots, UNMAPPED={len(buckets['UNMAPPED'])})")
    print("-> MISS = fix the regex of an EXISTING detector. UNCOVERED = the data-ranked NEW-detector backlog.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
