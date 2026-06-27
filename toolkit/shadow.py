#!/usr/bin/env python3
"""shadow.py - measure recon's RECALL against a labelled corpus of real bug types (where are we blind?).

We tune detectors by intuition + the targets we happen to hit. This measures it with DATA. Two corpora:

  --corpus defivulnlabs (default): SunWeb3Sec/DeFiVulnLabs -- 48 vuln types, each a self-contained Foundry
    test with the vulnerable contract INLINE + the type in the filename. Minimal repros -> ideal conditions.
        python shadow.py [--repo <path>] [--clone] [--show hit|miss|uncovered|unmapped|all]
      HIT/MISS/UNCOVERED/UNMAPPED per file; recall over COVERED classes.

  --corpus defihacklabs: a labelled sample of REAL DeFiHackLabs hacks -- the victim's DEPLOYED verified source
    pulled by fetch_source (proxy-resolved). The HONEST recall on production code (library noise, proxies, the
    works). Many victims are unverified -> a real limit of static recon.
        python shadow.py --corpus defihacklabs [--no-fetch]
      HIT (a detector fired) / MISS (a detector exists but didn't fire -> regex gap) / UNCOVERED (no T0 detector
      -> reasoning-tier, a hypothesize seed) / UNREACHABLE (victim source unverified).

Output: recall + a ranked blind-spot list (the data-driven backlog). Reuses recon.detect_all / recon.det_key. ASCII.
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
    ("read-only-reentrancy", {"roreentrancy"}),  # det_readonly_reentrancy (view-side guard tell)
    ("readonlyreentrancy", {"roreentrancy"}),
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
    ("phantom", None),                       # phantom function (fallback permit) - still uncovered
    ("flashloan", {"flashloan"}),            # det_flashloan (initiator/sender check)
    ("erc777", None),                        # extend nft-callback to tokensReceived - still uncovered
    ("self-transfer", {"selftransfer"}),  # det_self_transfer (mapping fix: was a false blind-spot)
    ("transient", None),                     # EIP-1153 misuse - still uncovered
    ("dos", None),                           # generic DoS - still uncovered
    ("overflow", {"overflow"}),              # det_overflow (pre-0.8 pragma / unchecked block)
    ("underflow", {"overflow"}),
    ("bypasscontract", {"l2"}),              # det_l2_footgun (extcodesize isContract) -- was mis-mapped
    ("bypass-contract", {"l2"}),
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


# ---- DeFiHackLabs real-hack corpus (victim on-chain source, NOT inline minimal repros) ----
# Labelled sample of REAL DeFiHackLabs hacks: the victim's DEPLOYED verified source (pulled by fetch_source,
# proxy-resolved) vs the recon det_key(s) that SHOULD fire. This is the HONEST recall on production code
# (library noise, proxies, the works) -- and many victims are unverified -> UNREACHABLE, itself a real limit of
# static recon. keys=None => recon has no T0 detector for the class (reasoning-tier blind spot, a hypothesize seed).
DEFIHACKLABS_SAMPLE = [
    {"label": "BYToken-2026-06",          "chain": 56,    "addr": "0x6f50cffEcd4e00EcF7E442774C08c089450B62Ca", "keys": {"pairreserve"},  "cls": "pair-reserve (reflection BSC)",            "note": ""},
    {"label": "LPC-2022-07",              "chain": 56,    "addr": "0x1E813fA05739Bf145c1F182CB950dA7af046778d", "keys": {"selftransfer"}, "cls": "self-transfer inflation",                  "note": ""},
    {"label": "GPU-2024-05",              "chain": 56,    "addr": "0xf51CBf9F8E089Ca48e454EB79731037a405972ce", "keys": {"selftransfer"}, "cls": "self-transfer inflation",                  "note": ""},
    # reasoning-tier (keys=None): the broad caller-auth / bare-param ERC-1271 shapes are deliberately NOT T0
    # (they FP on routers/permit) -> covered by the caller-supplied-authority hypothesize seed, not a regex.
    {"label": "MAPProtocol-2026-05",      "chain": 1,     "addr": "0x0000317Bec33Af037b5fAb2028f52d14658F6A56", "keys": None,             "cls": "caller-supplied-authority (bridge helper)", "note": "Helper._safeTransferFrom + memory-decoded authority -> reasoning-tier"},
    {"label": "NewMarketTrading-2026-05", "chain": 1,     "addr": "0x1f1d37a3Bf840e35c6a860c7C2dA71Fe555123ca", "keys": None,             "cls": "caller-supplied-authority (Safe-module)",   "note": "Safe-module exec + encodeWithSelector -> reasoning-tier"},
    {"label": "MureDistribution-2026-05", "chain": 1,     "addr": "0x365083717eFB17F3895290BA38f20F568C7A4D8a", "keys": None,             "cls": "signature (ERC-1271 bare-param verifier)",  "note": "bare-param 1271 verifier (permit-ambiguous) -> reasoning-tier; T0 covers only struct-field"},
    {"label": "Renegade-2026-05",         "chain": 42161, "addr": "0x30bD8eAb29181F790D7e495786d4B96d7AfDC518", "keys": {"uinit"},        "cls": "unprotected-init",                          "note": "proxy resolves to a PATCHED impl (no init) -> version-drift, not a regex gap"},
    {"label": "PikeFinance-2024-04",      "chain": 1,     "addr": "0xFC7599cfFea9De127a9f9C748CCb451a34d2F063", "keys": {"uinit"},        "cls": "unprotected-init / upgrade",                "note": "impl unverified"},
    {"label": "TrustedVolumes-2026-05",   "chain": 1,     "addr": "0xeEeEEe53033F7227d488ae83a27Bc9A9D5051756", "keys": None,             "cls": "caller-supplied-authority (RFQ signer)",    "note": "impl unverified + reasoning-tier"},
]


def _fired_keys_dir(d):
    """Union of recon det_keys that fire across every non-lib .sol under a fetched source dir."""
    fired = set()
    for dp, dns, fns in os.walk(d):
        dns[:] = [x for x in dns if x.lower() not in recon.SKIP_DIRS and x != "node_modules"]
        for fn in fns:
            if not fn.endswith(".sol"):
                continue
            try:
                fired |= fired_keys(open(os.path.join(dp, fn), encoding="utf-8", errors="ignore").read(), fn)
            except Exception:
                continue
    return fired


def _resolve_or_fetch(addr, chain, do_fetch):
    """Locate the fetched verified-source dir for (addr, chain); fetch (proxy-resolved) if missing and do_fetch.
    Returns the dir path, or None if the victim source is unverified/unreachable."""
    import re as _re
    direct = os.path.join("fetched", f"{chain}_{addr}")
    if os.path.isdir(direct):
        return direct
    if not do_fetch:
        return None
    here = os.path.dirname(os.path.abspath(__file__))
    r = subprocess.run([sys.executable, os.path.join(here, "fetch_source.py"), addr, "--chain", str(chain), "--proxy"],
                       capture_output=True, text=True)
    if "no verified source" in r.stdout:
        return None
    m = _re.search(r"->\s*(fetched[\\/]\S+)", r.stdout)
    if m:
        dd = m.group(1).replace("\\", "/").rstrip(".")
        if os.path.isdir(dd):
            return dd
    return None


def classify_dhl(keys, fired, reachable):
    """HIT/MISS/UNCOVERED/UNREACHABLE for one DeFiHackLabs sample entry."""
    if not reachable:
        return "UNREACHABLE"      # victim source unverified -> static recon can't see it (a real recall limit)
    if keys is None:
        return "UNCOVERED"        # recon has no T0 detector for this class (reasoning-tier -> hypothesize seed)
    return "HIT" if (fired & keys) else "MISS"


def bench_defihacklabs(do_fetch=True):
    """Bench recon over the labelled DeFiHackLabs real-victim sample -> honest production-code recall."""
    buckets = {"HIT": [], "MISS": [], "UNCOVERED": [], "UNREACHABLE": []}
    for e in DEFIHACKLABS_SAMPLE:
        d = _resolve_or_fetch(e["addr"], e["chain"], do_fetch)
        fired = _fired_keys_dir(d) if d else set()
        buckets[classify_dhl(e["keys"], fired, d is not None)].append((e, sorted(fired & (e["keys"] or set()))))
    return buckets


def _print_defihacklabs(buckets):
    total = sum(len(v) for v in buckets.values())
    print(f"\n# shadow benchmark: recon vs DeFiHackLabs REAL victims  ({total} hacks, deployed verified source)\n")
    for v in ("HIT", "MISS", "UNCOVERED", "UNREACHABLE"):
        rows = buckets[v]
        if not rows:
            continue
        print(f"## {v}  ({len(rows)})")
        for e, hitkeys in sorted(rows, key=lambda r: r[0]["label"]):
            tail = f"keys={sorted(e['keys'])}" if e["keys"] else "(no T0 detector -> reasoning-tier)"
            if v == "HIT":
                tail += f" fired={hitkeys}"
            elif e.get("note"):
                tail += f"  [{e['note']}]"
            print(f"  {e['label']:26} {e['cls']:46} {tail}")
        print()
    hit, miss, unc, unr = (len(buckets[k]) for k in ("HIT", "MISS", "UNCOVERED", "UNREACHABLE"))
    cov = hit + miss
    recall = (hit / cov * 100) if cov else 0.0
    print("=" * 70)
    print(f"REAL-HACK RECALL (reachable & covered): {hit}/{cov} = {recall:.0f}%   "
          f"(MISS={miss} regex-gaps, UNCOVERED={unc} reasoning-tier, UNREACHABLE={unr} unverified)")
    print("-> MISS = a detector exists but didn't fire on real code (regex gap). UNCOVERED = reasoning-tier "
          "(a hypothesize seed). UNREACHABLE = victim source unverified -> a hard limit of STATIC recall.")


def main():
    ap = argparse.ArgumentParser(description="recon recall benchmark (DeFiVulnLabs inline repros OR DeFiHackLabs real victims)")
    ap.add_argument("--corpus", default="defivulnlabs", choices=["defivulnlabs", "defihacklabs"],
                    help="defivulnlabs = inline minimal repros; defihacklabs = real on-chain victim source (fetched)")
    ap.add_argument("--no-fetch", action="store_true", help="(defihacklabs) only use already-fetched sources, don't network-fetch")
    ap.add_argument("--repo", default="cache/DeFiVulnLabs", help="path to a DeFiVulnLabs clone")
    ap.add_argument("--clone", action="store_true", help="git clone DeFiVulnLabs into --repo first")
    ap.add_argument("--show", default="miss,uncovered,unmapped",
                    help="comma list of verdicts to print per-file (hit/miss/uncovered/unmapped/all)")
    args = ap.parse_args()

    if args.corpus == "defihacklabs":
        _print_defihacklabs(bench_defihacklabs(do_fetch=not args.no_fetch))
        return 0

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
