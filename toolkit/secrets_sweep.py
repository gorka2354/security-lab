#!/usr/bin/env python3
"""secrets_sweep.py - SECRETS-SWEEP radar: scan the PUBLIC repos of LIVE protocols for committed keys, at
scale, the way nobody does -> the Taiko/Raiko class. An SGX enclave PRIVATE KEY (`enclave-key.pem`) sat in
Taiko's public git for ~2 years before anyone noticed (~$1.7M). It was "in plain sight" - the gap was that
nobody systematically scans the repo population of funded protocols, tree AND history. secrets.py is the
per-repo scanner; THIS is the sourcing+scale layer over it.

    python toolkit/secrets_sweep.py                      # sweep the watchlist -> hunts/_radar/SECRETS.md
    python toolkit/secrets_sweep.py --add <org/repo> [protocol] [chain]   # watch a repo
    python toolkit/secrets_sweep.py --only <org/repo>    # ad-hoc one-off sweep (also auto-adds)
    python toolkit/secrets_sweep.py --list
    python toolkit/secrets_sweep.py --no-history          # tree only (fast pass)

Watchlist: monitor/repos.json. Clones (FULL - history is the point) into hunts/_volume/_secrets/ (gitignored).
INCREMENTAL: a repo's first sweep reports every existing [!] leak (find the 2-year-old key); later runs
git-fetch + scan only new commits since the last HEAD (cron-cheap). Diffs monitor/secrets-seen.json so a
leak alerts once. Only [!] prio-0 (production-path) leads alert - test/fixture keys are downgraded by
secrets.py and never cry wolf. Exit 10 if a NEW leak was queued. Reuses secrets.py. Stdlib only.

White-hat: PUBLIC repos, report-only. A live in-scope key -> rotate-and-disclose path; the researcher decides.
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secrets as S   # the per-repo scanner (scan_tree / scan_history / _TEST_PATH / git)

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CLONE_ROOT = os.path.join(ROOT, "hunts", "_volume", "_secrets")


def load(path, default):
    p = os.path.join(ROOT, path)
    if os.path.exists(p):
        try:
            return json.load(open(p, encoding="utf-8"))
        except Exception:
            pass
    return default


def save(path, obj):
    p = os.path.join(ROOT, path)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    json.dump(obj, open(p, "w", encoding="utf-8"), indent=1, sort_keys=True)


def repo_dir(slug):
    return os.path.join(CLONE_ROOT, slug.replace("/", "__"))


def clone_or_update(slug, run=subprocess.run):
    """Full-clone slug (history needed) into the gitignored volume, or git-fetch if already cloned.
    Returns the local path, or None on failure. `run` is injectable for tests."""
    d = repo_dir(slug)
    if os.path.isdir(os.path.join(d, ".git")):
        run(["git", "-C", d, "fetch", "--quiet", "--all"], capture_output=True, text=True, timeout=600)
        return d
    os.makedirs(CLONE_ROOT, exist_ok=True)
    url = f"https://github.com/{slug}.git"
    try:
        run(["git", "clone", "--quiet", url, d], capture_output=True, text=True, timeout=900)
    except Exception:
        return None
    return d if os.path.isdir(os.path.join(d, ".git")) else None


def high_leads(repo, no_history=False, since_sha=None):
    """[!] prio-0 leads only (production-path secrets). Mirrors secrets.main's test-path downgrade so
    fixture/test keys never alert. History is scanned incrementally when since_sha is given."""
    tree = S.scan_tree(repo)
    rng = f"{since_sha}..HEAD" if since_sha else None
    hist = [] if no_history else S.scan_history(repo, rng=rng)
    leads = tree + hist
    # identical filtering to secrets.main so the radar and the per-repo report agree:
    leads = S.suppress_dev_dumps(leads)                   # hardhat 2k-account / *.config.* dumps -> not [!]
    leads = [(h[0], h[1], h[2], h[3], min(2, h[4] + 1)) if S._TEST_PATH.search(h[0]) else h for h in leads]
    return [h for h in leads if h[4] == 0]


def lead_key(slug, lead):
    """Stable id for a leak so it alerts ONCE (across re-clones / commit hashes that don't change content)."""
    rel, _ln, name, preview, _prio = lead
    # strip the commit prefix from history locs (commit:file) so the same secret keys stably across re-scans
    loc = rel.split(":", 1)[1] if rel[:10].isalnum() and ":" in rel and not rel.startswith("0x") else rel
    return hashlib.sha1(f"{slug}|{name}|{preview}|{loc}".encode()).hexdigest()[:16]


def head_sha(repo):
    return S.git(repo, "rev-parse", "HEAD").strip()


def sweep(today, no_history=False, only=None, cloner=clone_or_update):
    wl = load("monitor/repos.json", {"repos": []})["repos"]
    if only:
        wl = [r for r in wl if r["slug"].lower() == only.lower()] or [{"slug": only, "protocol": only, "chain": "?"}]
    seen = load("monitor/secrets-seen.json", {})
    events = []
    for r in wl:
        slug = r["slug"]
        d = cloner(slug)
        if not d:
            print(f"[secrets-sweep] clone failed: {slug}")
            continue
        prev = seen.get(slug)
        since = prev.get("sha") if prev else None
        leads = high_leads(d, no_history=no_history, since_sha=since)
        now = {lead_key(slug, l): l for l in leads}
        prev_keys = set(prev.get("keys", [])) if prev else set()
        new = [now[k] for k in now if k not in prev_keys]          # first sweep: prev empty -> all reported
        seen[slug] = {"sha": head_sha(d) or (prev or {}).get("sha", ""),
                      "keys": sorted(prev_keys | set(now.keys()))}
        for lead in new:
            events.append({"slug": slug, "protocol": r.get("protocol", slug), "chain": r.get("chain", "?"),
                           "name": lead[2], "loc": lead[0] if lead[1] == 0 else f"{lead[0]}:{lead[1]}",
                           "preview": lead[3]})
    save("monitor/secrets-seen.json", seen)
    write_queue(events, today, len(wl))
    print(f"[secrets-sweep] {len(wl)} repo(s) swept -> "
          + (f"{len(events)} NEW leak(s) [!]" if events else "clean (no new production-path leaks)"))
    return events


def write_queue(events, today, n_repos):
    p = os.path.join(ROOT, "hunts", "_radar", "SECRETS.md")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    L = [f"# Secrets-sweep radar  -- {today}", "",
         "> Committed keys/credentials in the PUBLIC repos of live protocols - tree + full git history "
         "(the Taiko enclave-key class: in plain sight for ~2y). Watchlist: monitor/repos.json. "
         "Only [!] production-path leaks alert (test/fixture keys downgraded).", ""]
    if not events:
        L.append(f"**All quiet** - no new production-path secrets across {n_repos} watched repo(s) this run.")
    else:
        by_repo = {}
        for e in events:
            by_repo.setdefault(e["slug"], []).append(e)
        L.append(f"## {len(events)} NEW leak(s) across {len(by_repo)} repo(s) - VERIFY + responsible-disclose")
        L.append("")
        for slug, evs in by_repo.items():
            e0 = evs[0]
            L.append(f"### {slug}  ({e0['protocol']}, chain {e0['chain']})")
            for e in evs:
                hist = "  [git history]" if "[in git history]" in e["name"] else ""
                L.append(f"- [!] {e['name'].replace(' [in git history]', '')} - `{e['loc']}`  ->  {e['preview']}{hist}")
            L.append(f"- next: confirm it's LIVE + in-scope (key still authoritative on-chain?) -> pair with "
                     f"recon det_trust_anchor (blast radius) -> rotate-and-disclose. the researcher discloses.")
            L.append("")
    open(p, "w", encoding="utf-8").write("\n".join(L) + "\n")


def add_repo(slug, protocol, chain, extra=None, quiet=False):
    wl = load("monitor/repos.json", {"repos": []})
    if any(r["slug"].lower() == slug.lower() for r in wl["repos"]):
        if not quiet:
            print(f"[secrets-sweep] already watched: {slug}")
        return False
    entry = {"slug": slug, "protocol": protocol or slug.split("/")[-1], "chain": chain or "?"}
    entry.update(extra or {})
    wl["repos"].append(entry)
    save("monitor/repos.json", wl)
    print(f"[secrets-sweep] watching repo {slug} (protocol={protocol or '?'}, chain={chain or '?'})")
    return True


# repos that are docs/specs, not deployable code -> no point sweeping for committed keys
_NONCODE = re.compile(r"(?i)(/|^)(api-?docs|docs?|spec|whitepaper|website|landing|brand|media)$")
_IMMUNEFI_JSON = "https://immunefi.com/public-api/bounties.json"


def _slug_from_url(url):
    """org/repo from any github URL (None if it's an org-only link or not github)."""
    m = re.search(r"github\.com/([\w.-]+/[\w.-]+)", url or "")
    if not m:
        return None
    slug = m.group(1).rstrip("/")
    if slug.endswith(".git"):
        slug = slug[:-4]
    return None if _NONCODE.search(slug) else slug


def from_immunefi():
    """Harvest the GitHub repos of LIVE Immunefi programs into the watchlist. These are AUTHORITATIVE in-scope
    repos: a committed key in one is a directly-disclosable, bountied (up to $1M) Taiko-class finding -- the
    highest-value target for this lane. Skips inviteOnly (no access) + docs-only repos. source/bounty tagged."""
    try:
        req = urllib.request.Request(_IMMUNEFI_JSON, headers={"User-Agent": "Mozilla/5.0"})
        data = json.load(urllib.request.urlopen(req, timeout=40))
    except Exception as e:
        print(f"[secrets-sweep] immunefi fetch failed: {e}")
        return 0
    added = 0
    for b in data if isinstance(data, list) else []:
        if b.get("inviteOnly"):
            continue
        slug = _slug_from_url(b.get("githubUrl"))
        if not slug:
            continue
        eco = b.get("ecosystem") or []
        chain = (eco[0].lower() if isinstance(eco, list) and eco else "?")
        if add_repo(slug, (b.get("project") or slug.split("/")[-1]), chain,
                    extra={"source": "immunefi", "bounty": b.get("maxBounty")}, quiet=True):
            added += 1
    print(f"[secrets-sweep] +{added} in-scope Immunefi repo(s) added to the watchlist")
    return added


def from_contests():
    """Harvest the repos of LIVE audit contests (Code4rena + Cantina expose a repo; Sherlock doesn't). The
    contest repo IS the in-scope code under active review -- a committed key there is in-scope. Reuses
    contest_monitor's parsers/feeds so the source list stays in one place."""
    try:
        import time
        import contest_monitor as cm
    except Exception as e:
        print(f"[secrets-sweep] contest_monitor unavailable: {e}")
        return 0
    now = int(time.time())
    feeds = [(cm.CANTINA, cm.parse_cantina), (cm.SHERLOCK, cm.parse_sherlock), (cm.CODE4RENA, cm.parse_code4rena)]
    added = 0
    for url, parser in feeds:
        try:
            recs = parser(cm._get(url))
        except Exception:
            recs = []
        for c in recs:
            if not cm.is_live(c, now):
                continue
            slug = _slug_from_url(c.get("repo"))
            if not slug:
                continue
            if add_repo(slug, c.get("title") or slug.split("/")[-1], c.get("platform", "contest"),
                        extra={"source": "contest", "bounty": c.get("pot")}, quiet=True):
                added += 1
    print(f"[secrets-sweep] +{added} live-contest repo(s) added to the watchlist")
    return added


def main():
    ap = argparse.ArgumentParser(description="Secrets-sweep radar over live-protocol public repos")
    ap.add_argument("--add", nargs="+", metavar="ORG/REPO [PROTOCOL] [CHAIN]")
    ap.add_argument("--from-immunefi", action="store_true",
                    help="harvest in-scope repos from live Immunefi programs (githubUrl) into the watchlist")
    ap.add_argument("--from-contests", action="store_true",
                    help="harvest repos of live audit contests (Code4rena/Cantina) into the watchlist")
    ap.add_argument("--from-all", action="store_true",
                    help="harvest from ALL in-scope sources (immunefi + contests), then continue to the sweep")
    ap.add_argument("--only", metavar="ORG/REPO", help="sweep just this repo (ad-hoc; auto-adds to watchlist)")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--no-history", action="store_true", help="working tree only (skip git history; fast)")
    ap.add_argument("--date", default=datetime.date.today().isoformat())
    a = ap.parse_args()

    if a.add:
        add_repo(a.add[0], a.add[1] if len(a.add) > 1 else "", a.add[2] if len(a.add) > 2 else "")
        return
    if a.from_immunefi:
        from_immunefi()
        return
    if a.from_contests:
        from_contests()
        return
    if a.from_all:
        n = from_immunefi() + from_contests()   # auto-source in-scope repos, then fall through to the sweep
        print(f"[secrets-sweep] harvested {n} new in-scope repo(s) from all sources -> sweeping")
    if a.list:
        for r in load("monitor/repos.json", {"repos": []})["repos"]:
            print(f"  {r['slug']}  (protocol={r.get('protocol','?')}, chain={r.get('chain','?')})")
        return
    if a.only:
        add_repo(a.only, "", "")

    events = sweep(a.date, no_history=a.no_history, only=a.only)
    sys.exit(10 if events else 0)


if __name__ == "__main__":
    main()
