#!/usr/bin/env python3
"""gh_meta.py - fetch GitHub repo metadata for target cards (the reliable slice of "project social data").

For every github link in monitor/links.json, pull the GitHub REST repo object and keep the fields that double
as a LIVENESS/maintenance signal for a hunt: stars, last push date, open issues, archived flag, license,
description. Writes monitor/repo-meta.json keyed by "owner/repo" (so shared repos, e.g. all krystal vaults,
resolve once). labstate joins it onto each target via its github link -> the dashboard's Resources section shows
"GitHub ★N · updated Xd ago (+ ARCHIVED)". Twitter/Discord/Telegram member data is paywalled/anti-bot and is
deliberately NOT fetched.

    python toolkit/gh_meta.py                # refresh all repos in links.json
    python toolkit/gh_meta.py --stale-days 7 # only refetch entries older than 7d (cron-friendly)

Unauthenticated GitHub API is 60 req/hr (plenty for ~15 repos); set GITHUB_TOKEN in the env to raise it.
Stdlib only; best-effort (a 404/403/timeout leaves the prior cached entry intact). ASCII output.
"""
import argparse
import datetime
import json
import os
import re
import urllib.error
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LINKS = os.path.join(ROOT, "monitor", "links.json")
OUT = os.path.join(ROOT, "monitor", "repo-meta.json")
_SLUG = re.compile(r"github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?/?$")


def _load(path, default):
    try:
        return json.load(open(path, encoding="utf-8"))
    except Exception:
        return default


def slugs_from_links(links):
    """The distinct owner/repo slugs referenced by any target's github link."""
    out = set()
    for k, v in (links or {}).items():
        if k.startswith("_") or not isinstance(v, dict):
            continue
        m = _SLUG.search(v.get("github", "") or "")
        if m:
            out.add(m.group(1))
    return sorted(out)


def fetch_repo(slug, token=None, timeout=15):
    """GitHub REST repo object -> the fields we keep. Returns None on any failure (leave cache as-is)."""
    req = urllib.request.Request("https://api.github.com/repos/" + slug,
                                 headers={"Accept": "application/vnd.github+json",
                                          "User-Agent": "security-lab-gh-meta"})
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            d = json.load(r)
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError, OSError):
        return None
    lic = (d.get("license") or {}) or {}
    return {
        "repo": slug,
        "stars": d.get("stargazers_count"),
        "forks": d.get("forks_count"),
        "open_issues": d.get("open_issues_count"),
        "pushed_at": d.get("pushed_at"),          # last code push -> maintenance recency
        "updated_at": d.get("updated_at"),
        "created_at": d.get("created_at"),
        "archived": bool(d.get("archived")),
        "license": lic.get("spdx_id") if lic.get("spdx_id") not in (None, "NOASSERTION") else None,
        "description": d.get("description"),
        "fetched": datetime.date.today().isoformat(),
    }


def _stale(entry, stale_days):
    if not stale_days or not entry or not entry.get("fetched"):
        return True
    try:
        age = (datetime.date.today() - datetime.date.fromisoformat(entry["fetched"])).days
        return age >= stale_days
    except Exception:
        return True


def run(stale_days=0, token=None):
    token = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    cache = _load(OUT, {})
    if not isinstance(cache, dict):
        cache = {}
    slugs = slugs_from_links(_load(LINKS, {}))
    fetched, skipped, failed = 0, 0, 0
    for slug in slugs:
        if not _stale(cache.get(slug), stale_days):
            skipped += 1
            continue
        meta = fetch_repo(slug, token=token)
        if meta:
            cache[slug] = meta
            fetched += 1
            arch = " ARCHIVED" if meta["archived"] else ""
            print(f"[gh] {slug:44} stars={meta['stars']} pushed={ (meta['pushed_at'] or '')[:10] }{arch}")
        else:
            failed += 1
            print(f"[gh] {slug:44} FETCH FAILED (kept prior cache)")
    json.dump(cache, open(OUT, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print(f"[gh] {fetched} fetched, {skipped} fresh-skipped, {failed} failed -> monitor/repo-meta.json "
          f"({len(cache)} repos){'' if token else '  (unauthenticated; set GITHUB_TOKEN to raise the 60/hr limit)'}")
    return cache


def main():
    ap = argparse.ArgumentParser(description="fetch GitHub repo metadata for the dashboard Resources section")
    ap.add_argument("--stale-days", type=int, default=0, help="only refetch entries older than N days (0 = all)")
    ap.add_argument("--token", default=None, help="GitHub token (else GITHUB_TOKEN/GH_TOKEN env)")
    a = ap.parse_args()
    run(stale_days=a.stale_days, token=a.token)


if __name__ == "__main__":
    main()
