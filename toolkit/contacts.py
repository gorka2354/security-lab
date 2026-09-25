#!/usr/bin/env python3
"""contacts.py - best-effort security-DISCLOSURE-contact discovery for target cards (WHERE to send a finding).

A waterfall, most-authoritative first, tagged with a confidence tier so the dashboard shows AT A GLANCE whether
the researcher is about to use an official reward-backed channel or a best-guess fallback:

  PROGRAM      an OPEN bounty/contest (Immunefi/Sherlock/Code4rena/Cantina) via programs.match() -> the OFFICIAL
               channel with safe-harbor + reward; always wins when present.
  GITHUB       the repo's SECURITY.md and/or GitHub "Private Vulnerability Reporting" (Security tab -> Report) --
               a tracked, CVE-eligible, no-email channel; two REST calls off the finding's github link.
  SECURITYTXT  RFC 9116 /.well-known/security.txt (fallback /security.txt) on the project's website -> Contact.

Lower tiers (email-guessing, ENS text records, footer scraping) are deliberately NOT auto-asserted as contacts
(a wrong "sent to nobody" address is worse than none) -- v2, and only ever as clearly-labelled fallbacks.

Reads project website+github from monitor/links.json (same source as the cards). Writes monitor/contacts.json
(pure auto cache, keyed by target key; labstate joins it fuzzily like links.json). Best-effort: a fetch failure
leaves the prior cached entry intact. NEVER sends anything -- discovery only; the researcher composes+sends.
Stdlib only (urllib); GITHUB_TOKEN from env raises the 60/hr GitHub limit. ASCII output.

    python toolkit/contacts.py                 # discover for every links.json target (refresh)
    python toolkit/contacts.py --target <key>  # one target (dashboard "Найти контакт" button)
    python toolkit/contacts.py --stale-days 7  # only re-check entries older than 7d (cron-friendly)
"""
import argparse
import datetime
import json
import os
import re
import sys
import urllib.error
import tlsfix  # noqa: F401,E402  -- current CA bundle on stale-CA Windows hosts (see tlsfix.py)
import urllib.parse
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LINKS = os.path.join(ROOT, "monitor", "links.json")
OUT = os.path.join(ROOT, "monitor", "contacts.json")
_SLUG = re.compile(r"github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?/?$")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import programs
except Exception:
    programs = None


def _load(path, default):
    try:
        return json.load(open(path, encoding="utf-8"))
    except Exception:
        return default


def _get(url, timeout=12, token=None, accept="application/json"):
    req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": "security-lab-contacts"})
    if token and "api.github.com" in url:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="ignore")
            return (r.status, body)
    except urllib.error.HTTPError as e:
        return (e.code, "")
    except (urllib.error.URLError, OSError, ValueError):
        return (None, "")


def _gh_json(slug, path, token):
    st, body = _get("https://api.github.com/repos/%s%s" % (slug, path), token=token)
    if st == 200 and body:
        try:
            return json.loads(body)
        except ValueError:
            return None
    return None


def parse_security_txt(body):
    """RFC 9116 line-based 'Key: value' (# comments ignored). Returns {contact:[...], policy, encryption, expires}."""
    out = {"contact": [], "policy": None, "encryption": None, "expires": None}
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        k, _, v = line.partition(":")
        k, v = k.strip().lower(), v.strip()
        if k == "contact" and v:
            out["contact"].append(v)
        elif k == "policy":
            out["policy"] = v
        elif k == "encryption":
            out["encryption"] = v
        elif k == "expires":
            out["expires"] = v
    return out


def _first_email(contacts):
    for c in contacts or []:
        if c.lower().startswith("mailto:"):
            return c[7:]
        if "@" in c and " " not in c and "://" not in c:
            return c
    return None


def discover(key, entry, token=None):
    """Run the waterfall for one target. `entry` is its links.json record (github/website). Returns the contact
    dict written to monitor/contacts.json[key]. Keeps ALL hits as `candidates`; `preferred_*` = the top tier."""
    entry = entry or {}
    cands = []

    # --- Tier 1: an OPEN bounty/contest program (the official channel) ---
    if programs:
        slug_for_match = ""
        m = _SLUG.search(entry.get("github", "") or "")
        if m:
            slug_for_match = m.group(1).split("/")[-1]
        for q in (slug_for_match, key):
            # OPEN programs only: an open program is THE actionable official channel; a closed/weak match on a
            # generic word (e.g. repo "arcade") is misleading noise, so we drop it rather than surface it.
            hits = [h for h in (programs.match(q) if q else []) if h.get("open")]
            if hits:
                p = hits[0]
                cands.append({"tier": "PROGRAM", "channel": p.get("platform"),
                              "url": p.get("url") or p.get("repo"), "open": True,
                              "reward_usd": p.get("reward_usd"), "confidence": "high"})
                break

    # --- Tier 2: GitHub SECURITY.md + Private Vulnerability Reporting ---
    m = _SLUG.search(entry.get("github", "") or "")
    if m:
        slug = m.group(1)
        prof = _gh_json(slug, "/community/profile", token)
        sec = ((prof or {}).get("files") or {}).get("security") if prof else None
        if sec and sec.get("html_url"):
            cands.append({"tier": "GITHUB", "channel": "SECURITY.md", "url": sec["html_url"], "confidence": "high"})
        pvr = _gh_json(slug, "/private-vulnerability-reporting", token)
        if pvr and pvr.get("enabled"):
            cands.append({"tier": "GITHUB", "channel": "GitHub Private Vulnerability Reporting",
                          "url": "https://github.com/%s/security/advisories/new" % slug, "confidence": "high"})

    # --- Tier 3: security.txt (RFC 9116) ---
    site = entry.get("website") or entry.get("app") or ""
    host = urllib.parse.urlparse(site if "://" in site else "https://" + site).netloc if site else ""
    if host:
        for path in ("/.well-known/security.txt", "/security.txt"):
            st, body = _get("https://%s%s" % (host, path), accept="text/plain")
            if st == 200 and body and ("contact" in body.lower()):
                parsed = parse_security_txt(body)
                cands.append({"tier": "SECURITYTXT", "channel": "security.txt",
                              "url": "https://%s%s" % (host, path), "email": _first_email(parsed["contact"]),
                              "contact": parsed["contact"], "policy": parsed["policy"],
                              "encryption": parsed["encryption"], "confidence": "high"})
                break

    # rank: PROGRAM(open) > GITHUB > SECURITYTXT > PROGRAM(closed); pick the top as preferred
    order = {"PROGRAM": 0, "GITHUB": 1, "SECURITYTXT": 2}
    cands.sort(key=lambda c: (order.get(c["tier"], 9), 0 if c.get("open", True) else 1))
    top = cands[0] if cands else None
    return {
        "key": key,
        "preferred_channel": top["tier"] if top else "NONE",
        "preferred_url": (top.get("url") if top else None),
        "email": next((c.get("email") for c in cands if c.get("email")), None),
        "reward_usd": next((c.get("reward_usd") for c in cands if c.get("tier") == "PROGRAM"), None),
        "confidence": top["confidence"] if top else "none",
        "candidates": cands,
        "checked_at": datetime.date.today().isoformat(),
    }


def _stale(entry, stale_days):
    if not stale_days or not entry or not entry.get("checked_at"):
        return True
    try:
        return (datetime.date.today() - datetime.date.fromisoformat(entry["checked_at"])).days >= stale_days
    except Exception:
        return True


def run(only_key=None, stale_days=0, token=None):
    token = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    links = _load(LINKS, {})
    cache = _load(OUT, {})
    if not isinstance(cache, dict):
        cache = {}
    keys = [only_key] if only_key else [k for k in links if not k.startswith("_") and isinstance(links[k], dict)]
    done = 0
    for k in keys:
        if not only_key and not _stale(cache.get(k), stale_days):
            continue
        entry = links.get(k) if isinstance(links.get(k), dict) else {}
        res = discover(k, entry, token=token)
        cache[k] = res
        done += 1
        pref = res["preferred_channel"]
        extra = (" $%s" % format(res["reward_usd"], ",")) if res.get("reward_usd") else ""
        print("[contacts] %-26s -> %-11s (%s)%s" % (k[:26], pref, res["confidence"], extra))
    json.dump(cache, open(OUT, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print("[contacts] %d discovered -> monitor/contacts.json (%d cached)%s" % (
        done, len(cache), "" if token else "  (unauthenticated GitHub; set GITHUB_TOKEN to raise 60/hr)"))
    return cache


def main():
    ap = argparse.ArgumentParser(description="best-effort disclosure-contact discovery for the dashboard")
    ap.add_argument("--target", default=None, help="discover one target key (dashboard button)")
    ap.add_argument("--stale-days", type=int, default=0, help="only re-check entries older than N days")
    ap.add_argument("--token", default=None, help="GitHub token (else GITHUB_TOKEN/GH_TOKEN env)")
    a = ap.parse_args()
    run(only_key=a.target, stale_days=a.stale_days, token=a.token)


if __name__ == "__main__":
    main()
