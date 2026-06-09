#!/usr/bin/env python3
"""scout.py - optimize Stage 0 (target sourcing), the hunter's bottleneck.

Auto-discovers FRESH, in-scope, cloneable audit-contest targets so we stop hand-searching
GitHub/contest sites every hunt. Pulls recent repos from audit-contest GitHub orgs (where
the scoped code is public the moment a contest opens), filters to our criteria, suppresses
already-hunted targets via the ledger, and RANKS by freshness x our-wheelhouse fit.

    python toolkit/scout.py [--orgs sherlock-audit,hats-finance] [--days 150]
                            [--out hunts/_volume/scout-queue.md]

Output: a ranked candidate queue with ready-to-run `git clone` lines. You (L4) pick the top
fit, clone, then run recon + hypothesize. Discovery only -- it does NOT clone (avoids pulling
giants like Fluid: 431 files/assembly -> our regex engines are blind; flagged as LARGE here).

Sources (no-KYC-friendly, public scope at contest start):
  - sherlock-audit : every contest is a public `YYYY-MM-<name>` repo (skip the `-judging` mirrors).
  - hats-finance   : audit-competition repos go public at start (no-KYC, our PLAYBOOK favourite).
  (Cantina/Code4rena: largely private/defunct -> not API-discoverable; curate by hand.)

Stdlib only. Set GITHUB_TOKEN env for a higher rate limit (unauth = 60 req/hr).
ASCII output (Windows console).
"""

import argparse
import json
import os
import re
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ledger  # same folder: skip already-hunted targets

# our zone -- a keyword in the repo name/description bumps the fit score (where our detectors bite)
WHEELHOUSE = [
    "vault", "erc4626", "erc-4626", "stablecoin", "stable", "lend", "borrow", "oracle",
    "bridge", "cross-chain", "crosschain", "layerzero", "oft", "stake", "restake", "lrt",
    "lst", "perp", "dex", "amm", "yield", "collateral", "liquidat", "lending", "money-market",
    "game", "nft", "gamefi", "rwa", "savings", "redeem", "deposit", "queue",
]
# anti-fit: our regex engines are blind to heavily-assembly / huge codebases
LARGE_KB = 6000          # repo size over this -> flag "LARGE: verify fit (assembly/giant?)"
SKIP_NAME = re.compile(r"-judging$|template|example|test|report|docs?$|\.github$", re.I)


def gh(url):
    """GET the GitHub API; returns parsed JSON or None (graceful on rate-limit / network)."""
    req = urllib.request.Request(url, headers={
        "User-Agent": "security-lab-scout",
        "Accept": "application/vnd.github+json",
    })
    tok = os.environ.get("GITHUB_TOKEN")
    if tok:
        req.add_header("Authorization", f"Bearer {tok}")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.load(r)
    except Exception as e:
        print(f"  [warn] {url}: {e}", file=sys.stderr)
        return None


def target_key(name):
    """Short target key from a contest repo name: strip the trailing -0x.. hats hash and the
    sherlock `YYYY-MM-` date prefix. `2025-07-mellow-flexible-vaults` -> `mellow-flexible-vaults`;
    `dTRINITY-0xee5c..` -> `dtrinity`. Used to suppress already-hunted targets via the ledger."""
    k = re.sub(r"-0x[0-9a-fA-F]{6,}$", "", name)
    return re.sub(r"^\d{4}-\d{2}-", "", k).lower()


def org_repos(org, per_page=40):
    """Recent repos of an org, newest first."""
    data = gh(f"https://api.github.com/orgs/{org}/repos?sort=created&direction=desc&per_page={per_page}")
    return data if isinstance(data, list) else []


def age_days(created_iso, now_iso):
    """Whole days between two ISO-8601 'YYYY-MM-DD...' strings (date-only, no clock needed)."""
    def ord_(s):
        y, m, d = int(s[0:4]), int(s[5:7]), int(s[8:10])
        return (y * 372) + (m * 31) + d   # monotonic day-ish ordinal; fine for sorting/threshold
    return ord_(now_iso) - ord_(created_iso)


def score(repo, kw_hits):
    """Freshness (newer ranks first) + 2x wheelhouse hits. Higher = hunt sooner."""
    created = (repo.get("created_at") or "")[:10]
    fresh = max(0, 400 - age_days(created, _TODAY))   # ~newer -> bigger
    return fresh + 2 * kw_hits * 30


def main():
    ap = argparse.ArgumentParser(description="Discover + rank fresh audit-contest targets (Stage 0)")
    ap.add_argument("--orgs", default="sherlock-audit,hats-finance",
                    help="comma-separated GitHub orgs hosting public contest scopes")
    ap.add_argument("--days", type=int, default=150, help="only repos created within N days")
    ap.add_argument("--top", type=int, default=20)
    ap.add_argument("--today", default="", help="YYYY-MM-DD reference date (default: env DATE or 2026-06-09)")
    ap.add_argument("--out", default="hunts/_volume/scout-queue.md")
    a = ap.parse_args()

    global _TODAY
    _TODAY = a.today or os.environ.get("SCOUT_TODAY") or "2026-06-09"

    led = ledger.load()
    done = {e["target"].lower() for e in led.values()}   # already-hunted -> suppress

    cands = []
    for org in [o.strip() for o in a.orgs.split(",") if o.strip()]:
        for r in org_repos(org):
            name = r.get("name", "")
            # NB: do NOT exclude forks -- audit-contest repos (esp. hats) are forks of the project
            # source by design; excluding them drops the whole contest pool.
            if SKIP_NAME.search(name) or r.get("archived"):
                continue
            if (r.get("language") or "") not in ("Solidity", "", None) and "Solidity" not in (r.get("language") or ""):
                # allow null language (fresh repo not yet classified); drop clearly-non-Solidity
                if r.get("language") not in (None, "", "Solidity"):
                    continue
            created = (r.get("created_at") or "")[:10]
            if not created or age_days(created, _TODAY) > a.days:
                continue
            # short target key (strip the trailing 0x.. hats hash and date prefix)
            key = target_key(name)
            # ledger stores short names (e.g. "mellow"); repo key is "mellow-flexible-vaults".
            # suppress if the key, its first segment, or the full repo name was already hunted.
            seg = key.split("-")[0]
            if key in done or seg in done or name.lower() in done:
                continue
            blob = (name + " " + (r.get("description") or "")).lower()
            kw = sorted({k for k in WHEELHOUSE if k in blob})
            cands.append({
                "org": org, "name": name, "key": key, "created": created,
                "lang": r.get("language") or "?", "size": r.get("size", 0),
                "kw": kw, "desc": (r.get("description") or "")[:60],
                "url": r.get("clone_url") or f"https://github.com/{org}/{name}.git",
                "score": score(r, len(kw)),
            })

    cands.sort(key=lambda c: -c["score"])
    out = ["# Scout queue: fresh audit-contest candidates (Stage 0)",
           f"\nRef date {_TODAY}. Orgs: {a.orgs}. Window: {a.days}d. "
           f"{len(cands)} candidates after ledger-suppression ({len(done)} targets already hunted).",
           "Ranked by freshness x wheelhouse-fit. Pick top fit -> clone -> recon + hypothesize.\n"]
    if not cands:
        out.append("  (none -- widen --days, add an org, or the orgs have no fresh public scope now)")
    for c in cands[:a.top]:
        big = "  [LARGE: verify fit - assembly/giant?]" if c["size"] > LARGE_KB else ""
        kw = (" zone:" + ",".join(c["kw"])) if c["kw"] else " zone:-"
        out.append(f"- **{c['name']}** ({c['org']}, {c['created']}, {c['lang']}, {c['size']}KB){big}"
                   f"\n    {kw}  | {c['desc']}"
                   f"\n    `git clone --depth 1 {c['url']} hunts/_volume/{c['key']}`")
    out.append("\n---\nNote: sherlock = KYC payout (learning/rep); hats = no-KYC. Verify scope is still "
               "OPEN before deep work; LARGE repos may be assembly-heavy (recon/hypothesize blind).")
    report = "\n".join(out)
    print(report)
    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        open(a.out, "w", encoding="utf-8").write(report)
        print(f"\n[written to {a.out}]")


if __name__ == "__main__":
    main()
