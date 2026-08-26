"""Authorized-scope layer -- track LIVE bounty/contest programs so hunting targets PAYABLE + in-scope
code, and every finding can answer "is this in an OPEN program, and what's the reward?".

The session's recurring gap: real findings (Krystal HIGH, EA-Finance, wager-chess...) mostly had NO
program -> disclose for free. This layer flips that: hunt where a program is open, and price a finding.

Sources (accessible JSON APIs; each fetcher is best-effort -- a dead source is skipped, not fatal):
  - Sherlock   https://mainnet-contest.sherlock.xyz/contests           (contests + public bug bounties)
  - Code4rena  https://code4rena.com/api/v1/audits                     (title/status/dates/repo/amount)
  - Cantina    https://cantina.xyz/api/v0/competitions                 (name/status/timeframe/pot/kyc)
  - Immunefi   JS-walled, no clean API -> TODO (reader-scrape best-effort); not in v1.

CLI:
  python toolkit/programs.py fetch                        # refresh monitor/programs.json + summary
  python toolkit/programs.py list [--open] [--min N] [--platform P] [--kind contest|bounty]
  python toolkit/programs.py match <name|repo|addr>       # is a target in an OPEN program? reward?
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import time
import urllib.request

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/126 Safari/537.36")
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORE = os.path.join(_ROOT, "monitor", "programs.json")


def _get(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", errors="ignore"))


def _now():
    return int(time.time())


def _iso_ts(s):
    """ISO-8601 (2026-05-04T20:00:00.000Z) -> unix seconds; None on failure."""
    if not s:
        return None
    try:
        s = s.replace("Z", "+00:00")
        import datetime as _dt
        return int(_dt.datetime.fromisoformat(s).timestamp())
    except Exception:
        return None


def _get_text(url, timeout=35):
    # r.jina.ai reader BLOCKS browser User-Agents (anti-abuse) -> use a plain non-browser UA.
    req = urllib.request.Request(url, headers={"User-Agent": "curl/8.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="ignore")


def _reward_num(v):
    """Best-effort numeric reward (USD) from '$50,000' / 50000 / '$250k' / '$3M' / '50000 USDC'."""
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return int(v)
    m = re.search(r"([\d.]+)\s*([kKmM]?)", str(v).replace(",", "").strip())
    if not m:
        return None
    n = float(m.group(1))
    suf = m.group(2).lower()
    return int(n * (1_000 if suf == "k" else 1_000_000 if suf == "m" else 1))


def _prog(platform, name, kind, is_open, start, end, reward, currency, url, repo=None, kyc=False):
    return {
        "platform": platform, "name": name, "kind": kind, "open": bool(is_open),
        "start": start, "end": end, "reward": reward, "reward_usd": _reward_num(reward),
        "currency": currency, "url": url, "repo": repo, "kyc": bool(kyc),
    }


# ── fetchers ──────────────────────────────────────────────────────────────────────────────────────
def fetch_sherlock():
    out = []
    base = "https://mainnet-contest.sherlock.xyz/contests"
    url, page = base, 1
    while url and page <= 6:
        d = _get(url)
        for it in d.get("items", []):
            kind = "bounty" if "Bounty" in (it.get("type_label") or "") else "contest"
            start, end = it.get("starts_at"), it.get("ends_at")
            is_open = (kind == "bounty") or (start and end and start <= _now() <= end)
            out.append(_prog("sherlock", it.get("title"), kind, is_open, start, end,
                             it.get("rewards") or it.get("prize_pool"), it.get("token") or "USDC",
                             "https://audits.sherlock.xyz/contests/%s" % it.get("id"),
                             kyc=bool(it.get("private"))))
        nxt = d.get("next_page")
        url = ("%s?page=%d" % (base, nxt)) if nxt else None
        page += 1
    return out


def fetch_code4rena():
    d = _get("https://code4rena.com/api/v1/audits")
    out = []
    for a in d.get("data", {}).get("audits", []):
        start, end = _iso_ts(a.get("startTime")), _iso_ts(a.get("endTime"))
        status = (a.get("status") or "").lower()
        is_open = status in ("active", "live", "open") or (
            status not in ("completed", "closed") and start and end and start <= _now() <= end)
        out.append(_prog("code4rena", a.get("title"), "contest", is_open, start, end,
                         a.get("formattedAmount"), "USD",
                         "https://code4rena.com/audits/%s" % (a.get("slug") or ""),
                         repo=a.get("repo"), kyc=(a.get("codeAccess") != "public")))
    return out


def fetch_cantina():
    d = _get("https://cantina.xyz/api/v0/competitions")
    items = d if isinstance(d, list) else d.get("items", d.get("data", []))
    out = []
    for c in items:
        tf = c.get("timeframe") or {}
        start = _iso_ts(tf.get("startDate")) if isinstance(tf, dict) else None
        end = _iso_ts(tf.get("endDate")) if isinstance(tf, dict) else None
        is_open = (c.get("status") or "").lower() in ("live", "active", "open")
        out.append(_prog("cantina", c.get("name"), "contest", is_open, start, end,
                         c.get("totalRewardPot"), c.get("currencyCode") or "USD",
                         c.get("url"), kyc=bool(c.get("kycRequired"))))
    return out


_IMM_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
           "Chrome/124.0 Safari/537.36")
# each bounty is server-rendered into the Next.js RSC blob as an escaped JSON object -> pull slug/url/kyc/maxBounty
_IMM_ROW = re.compile(r'\\"slug\\":\\"([^"\\]+?)\\",\\"url\\":\\"([^"\\]+?)\\".*?'
                      r'\\"kyc\\":(true|false),\\"maxBounty\\":(\d+)', re.S)


def fetch_immunefi():
    """Immunefi is JS-walled (no public API), but its /bug-bounty/ page SERVER-renders the FULL bounty list into a
    Next.js RSC blob. Fetch the raw HTML with a browser UA and parse the escaped {slug,url,kyc,maxBounty} objects
    -> ~180+ standing bounties (always open), vs the ~9 the old r.jina.ai reader saw (page-1 only). No per-asset
    addresses in the listing -> match by name/slug. Best-effort: any failure returns [] (soft dependency).
    Fetched via curl (Python urllib hits a stale-CA SSL error on this host + Immunefi sits behind Cloudflare;
    curl is present on both the workstation and the stand cron host)."""
    try:
        p = subprocess.run(["curl", "-s", "-m", "45", "-L", "-A", _IMM_UA, "https://immunefi.com/bug-bounty/"],
                           capture_output=True, text=True, timeout=60)
        html = p.stdout or ""
    except Exception:
        return []
    out, seen = [], set()
    for slug, url, kyc, mb in _IMM_ROW.findall(html):
        if slug in seen or slug == "immunefi":
            continue
        seen.add(slug)
        out.append(_prog("immunefi", slug.replace("-", " ").title(), "bounty", True, None, None,
                         int(mb) or None, "USD", "https://immunefi.com" + url, repo=slug, kyc=(kyc == "true")))
    return out


def fetch_cantina_bounties():
    """Cantina's PUBLIC bug bounties (the /repositories/public route) - distinct from /competitions (contests).
    Live-verified: ~51 open standing bounties (Uniswap $15.5M, Euler, Coinbase, Polymarket, ...), each with
    gitRepoUrl + commitHash pre-resolved -> `match <repo>` picks them up and forkdrift gets a pinned target."""
    d = _get("https://cantina.xyz/api/v0/repositories/public")
    items = d if isinstance(d, list) else d.get("items", d.get("data", []))
    out = []
    for c in items:
        if (c.get("kind") or "") != "public_bounty":
            continue
        is_open = (c.get("status") or "").lower() == "live"
        tf = c.get("timeframe") or {}
        start = _iso_ts(tf.get("startDate")) if isinstance(tf, dict) else None
        end = _iso_ts(tf.get("endDate")) if isinstance(tf, dict) else None
        repo = c.get("gitRepoUrl") or None
        cid = c.get("id") or ""
        out.append(_prog("cantina", c.get("name"), "bounty", is_open, start, end,
                         c.get("totalRewardPot"), c.get("currencyCode") or "USD",
                         c.get("url") or (f"https://cantina.xyz/bounties/{cid}" if cid else "https://cantina.xyz/bounties"),
                         repo=repo, kyc=bool(c.get("kycRequired"))))
    return out


_SOURCES = [("sherlock", fetch_sherlock), ("code4rena", fetch_code4rena),
            ("cantina", fetch_cantina), ("cantina-bounties", fetch_cantina_bounties),
            ("immunefi", fetch_immunefi)]


def refresh():
    progs, errs = [], []
    for name, fn in _SOURCES:
        try:
            got = fn()
            progs.extend(got)
            print("  [%s] %d programs (%d open)" % (name, len(got), sum(p["open"] for p in got)))
        except Exception as e:
            errs.append("%s: %s" % (name, e))
            print("  [%s] FAILED: %s" % (name, str(e)[:80]))
    payload = {"fetched": _now(), "count": len(progs), "errors": errs, "programs": progs}
    os.makedirs(os.path.dirname(STORE), exist_ok=True)
    with open(STORE, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=1, ensure_ascii=False)
    return payload


def _load():
    if not os.path.exists(STORE):
        return None
    with open(STORE, encoding="utf-8") as f:
        return json.load(f)


def _fmt(p):
    rw = ("$%s" % format(p["reward_usd"], ",")) if p["reward_usd"] else str(p["reward"] or "?")
    kyc = " KYC" if p["kyc"] else ""
    return "  [%-9s] %-26s %-8s %-10s%s  %s" % (
        p["platform"], (p["name"] or "?")[:26], p["kind"], rw, kyc, p["repo"] or p["url"] or "")


def cmd_list(args):
    data = _load()
    if not data:
        print("no store -- run: python toolkit/programs.py fetch")
        return
    progs = data["programs"]
    if args.open:
        progs = [p for p in progs if p["open"]]
    if args.platform:
        progs = [p for p in progs if p["platform"] == args.platform]
    if args.kind:
        progs = [p for p in progs if p["kind"] == args.kind]
    if args.min:
        progs = [p for p in progs if (p["reward_usd"] or 0) >= args.min]
    progs.sort(key=lambda p: -(p["reward_usd"] or 0))
    print("== %d programs%s (store %dh old) ==" % (
        len(progs), " OPEN" if args.open else "", (_now() - data["fetched"]) // 3600))
    for p in progs:
        print(_fmt(p))
    if data.get("errors"):
        print("  (source errors: %s)" % "; ".join(data["errors"]))


def match(query):
    """Programmatic match (reused by contacts.py for disclosure-channel discovery): return the programs
    whose name/repo/url match `query`, ranked OPEN-first then reward desc. [] if no store / no match."""
    data = _load()
    if not data:
        return []
    q = (query or "").lower().strip()
    q_norm = re.sub(r"[^a-z0-9]", "", q)
    if not q_norm:
        return []
    hits = []
    for p in data["programs"]:
        hay = " ".join(str(p.get(k) or "") for k in ("name", "repo", "url")).lower()
        hay_norm = re.sub(r"[^a-z0-9]", "", hay)
        if (q and q in hay) or (len(q_norm) >= 4 and q_norm in hay_norm):
            hits.append(p)
    hits.sort(key=lambda p: (not p["open"], -(p["reward_usd"] or 0)))
    return hits


def cmd_match(args):
    data = _load()
    if not data:
        print("no store -- run: python toolkit/programs.py fetch")
        return
    q = args.query.lower().strip()
    q_norm = re.sub(r"[^a-z0-9]", "", q)
    hits = []
    for p in data["programs"]:
        hay = " ".join(str(p.get(k) or "") for k in ("name", "repo", "url")).lower()
        hay_norm = re.sub(r"[^a-z0-9]", "", hay)
        if (q and q in hay) or (len(q_norm) >= 4 and q_norm in hay_norm):
            hits.append(p)
    if not hits:
        print("== no program matches '%s' ==" % args.query)
        print("  -> likely NO authorized program (disclose responsibly, no bounty). NOTE: list APIs")
        print("     carry program NAME/repo, not per-asset addresses -- an address match needs a")
        print("     per-contest scope fetch (TODO). Also Immunefi (standing bounties) is not yet a source.")
        return
    hits.sort(key=lambda p: (not p["open"], -(p["reward_usd"] or 0)))
    print("== '%s' -> %d candidate program(s) ==" % (args.query, len(hits)))
    for p in hits:
        print("  %s %s" % ("OPEN " if p["open"] else "closed", _fmt(p).strip()))
    op = [p for p in hits if p["open"]]
    print("  -> %s" % ("IN AN OPEN PROGRAM -> submit there (verify the exact in-scope asset list on the platform)."
                        if op else "matches only CLOSED programs -> no live payout; responsible disclosure."))


def cmd_scope(args):
    """Resolve the exact in-scope code for a program -> hunt it precisely. Sherlock detail carries the
    scope repo+commit AND the contest report (already-judged issues -> don't dup; hunt the long tail)."""
    data = _load()
    if not data:
        print("no store -- run: python toolkit/programs.py fetch")
        return
    q = args.query.lower()
    hits = [p for p in data["programs"]
            if q in " ".join(str(p.get(k) or "") for k in ("name", "repo", "url")).lower()]
    hits.sort(key=lambda p: (not p["open"], -(p["reward_usd"] or 0)))
    if not hits:
        print("== no program matches '%s' ==" % args.query)
        return
    p = hits[0]
    print("== scope: %s [%s] %s%s ==" % (
        p["name"], p["platform"], ("$%s" % format(p["reward_usd"], ",")) if p["reward_usd"] else "?",
        "" if p["open"] else " (CLOSED)"))
    if p["platform"] == "sherlock":
        m = re.search(r"/contests/(\d+)", p["url"] or "")
        if m:
            try:
                d = _get("https://mainnet-contest.sherlock.xyz/contests/%s" % m.group(1))
                for s in (d.get("scope") or []):
                    print("  scope repo: %s @ %s (%s)" % (
                        s.get("repo"), (s.get("commit_hash") or "")[:12], s.get("branch_name")))
                rep = d.get("report") or ""
                n = len(re.findall(r"^#\s*Issue\s", rep, re.M)) or rep.count("Issue ")
                print("  contest report: ~%d judged issue(s) -> those are KNOWN, hunt what they MISSED" % n
                      if rep else "  (no contest report -> a standing bounty, no prior contest)")
            except Exception as e:
                print("  (detail fetch failed: %s)" % str(e)[:60])
    elif p["repo"]:
        print("  scope repo: %s" % p["repo"])
    else:
        print("  scope: see %s (per-asset addresses on the platform page)" % p["url"])


def cmd_watch(args):
    """Diff vs the previous store, surface NEW open programs (fresh CONTESTS = the timing-edge sweet
    spot: fresh code + pays + first-mover). Wire to a scheduler for an always-on payable-target radar."""
    old = _load()
    old_open = set((p["platform"], p["name"]) for p in (old["programs"] if old else []) if p["open"])
    new = refresh()
    new_open = [p for p in new["programs"] if p["open"]]
    fresh = [p for p in new_open if (p["platform"], p["name"]) not in old_open]
    fresh.sort(key=lambda p: (p["kind"] != "contest", -(p["reward_usd"] or 0)))
    print("== watch: %d open (%d NEW since last fetch) ==" % (len(new_open), len(fresh)))
    for p in fresh:
        tag = "CONTEST(fresh+pays!)" if p["kind"] == "contest" else "bounty"
        print("  NEW %-20s %s" % (tag, _fmt(p).strip()))
    if not fresh:
        print("  (no new open programs)")


def main():
    ap = argparse.ArgumentParser(description="Authorized-scope layer: live bounty/contest programs")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("fetch")
    sub.add_parser("watch")
    lp = sub.add_parser("list")
    lp.add_argument("--open", action="store_true")
    lp.add_argument("--min", type=int, default=0)
    lp.add_argument("--platform", default=None)
    lp.add_argument("--kind", default=None, choices=["contest", "bounty"])
    mp = sub.add_parser("match")
    mp.add_argument("query")
    scp = sub.add_parser("scope")
    scp.add_argument("query")
    args = ap.parse_args()
    if args.cmd == "fetch":
        d = refresh()
        print("== %d programs (%d open) -> %s ==" % (
            d["count"], sum(p["open"] for p in d["programs"]), STORE))
    elif args.cmd == "list":
        cmd_list(args)
    elif args.cmd == "match":
        cmd_match(args)
    elif args.cmd == "scope":
        cmd_scope(args)
    elif args.cmd == "watch":
        cmd_watch(args)


if __name__ == "__main__":
    main()
