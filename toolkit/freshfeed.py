#!/usr/bin/env python3
"""freshfeed.py - FRESHNESS feeds: be FIRST on brand-new code (the #1 bottleneck, Tier-1 of the tooling roadmap).

Two free, no-key sources that surface code in its first hours:
  - DefiLlama `listedAt`: protocols listed in the last N days (a NEW protocol = un-hardened, often un-audited).
  - Sourcify newest-verified: contracts freshly verified on our chains (brand-new source to read, any protocol).

Diffs vs monitor/freshfeed-seen.json so only NEW listings/verifications alert -> hunts/_radar/FRESH-FEED.md.
Complements freshdeploy.py (which watches KNOWN deployers); this is the WIDE net for all new code. Stdlib only.

    python toolkit/freshfeed.py [--days 5] [--tvl-min 100000] [--chains eth,base,arbitrum,bsc]
    python toolkit/freshfeed.py --no-sourcify   # DefiLlama only (faster)

Exit 10 if anything NEW was queued (cron-friendly). Reuses ledger.py suppression.
"""

import argparse
import datetime
import json
import os
import re
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import ledger
except Exception:
    ledger = None

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ZONES = ("lend", "borrow", "dex", "amm", "perp", "deriv", "bridge", "crosschain", "vault", "rwa", "yield",
         "stable", "cdp", "restak", "stak", "oracle", "lottery", "luck", "gambl", "predict", "option",
         "money market", "savings", "game", "casino", "raffle", "bet")
CHAIN_ID = {"eth": 1, "ethereum": 1, "base": 8453, "arbitrum": 42161, "arb": 42161, "optimism": 10, "op": 10,
            "polygon": 137, "bsc": 56, "linea": 59144}


def _get(url, browser=False):
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124" if browser else "security-lab-freshfeed"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": ua})
        with urllib.request.urlopen(req, timeout=40) as r:
            return json.load(r)
    except Exception:
        return None


def _suppressed(key):
    if not ledger:
        return False
    try:
        idx = ledger.load_index() if hasattr(ledger, "load_index") else None
    except Exception:
        idx = None
    # cheap fallback: substring in the raw ledger file
    try:
        return key.lower() in open(os.path.join(ROOT, "toolkit", "triage-ledger.json"), encoding="utf-8").read().lower()
    except Exception:
        return False


def norm(name):
    return re.sub(r"[^a-z0-9]+", "-", str(name).lower()).strip("-")


def defillama_fresh(days, tvl_min, today, data=None):
    data = data if data is not None else (_get("https://api.llama.fi/protocols") or [])
    cutoff = (datetime.datetime.utcnow() - datetime.timedelta(days=days)).timestamp()
    out = []
    for p in data:
        la = p.get("listedAt")
        if not la or la < cutoff:
            continue
        blob = (str(p.get("category", "")) + " " + str(p.get("name", "")) + " " +
                " ".join(p.get("audits", []) if isinstance(p.get("audits"), list) else [])).lower()
        zones = sorted({z for z in ZONES if z in blob})
        if not zones:
            continue                                     # off-zone -> skip the noise
        out.append({
            "name": p.get("name"), "key": norm(p.get("name")), "category": p.get("category"),
            "tvl": p.get("tvl") or 0, "chains": p.get("chains", [])[:4],
            "listed": datetime.datetime.utcfromtimestamp(la).date().isoformat(),
            "audits": p.get("audits", "0"), "url": p.get("url", ""), "zones": zones,
        })
    # newest first; keep funded-enough
    out = [c for c in out if c["tvl"] >= tvl_min or c["tvl"] == 0]
    return sorted(out, key=lambda c: c["listed"], reverse=True)


def sourcify_fresh(chains, per_chain=8):
    out = {}
    for ch in chains:
        cid = CHAIN_ID.get(ch.lower())
        if not cid:
            continue
        d = _get(f"https://sourcify.dev/server/v2/contracts/{cid}?sort=desc&limit={per_chain}", browser=True)
        rows = (d or {}).get("results", []) if isinstance(d, dict) else []
        out[ch] = [{"addr": r.get("address"), "verifiedAt": (r.get("verifiedAt") or "")[:19]} for r in rows if r.get("address")]
    return out


def load(path, default):
    p = os.path.join(ROOT, path)
    if os.path.exists(p):
        try:
            return json.load(open(p, encoding="utf-8"))
        except Exception:
            pass
    return default


def main():
    ap = argparse.ArgumentParser(description="Freshness feeds (DefiLlama listedAt + Sourcify newest-verified)")
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--tvl-min", type=int, default=50000)
    ap.add_argument("--chains", default="eth,base,arbitrum,bsc")
    ap.add_argument("--sourcify", action="store_true",
                    help="also pull Sourcify newest-verified (NOISY: ~hundreds/hr of mostly-junk -> opt-in/manual)")
    ap.add_argument("--date", default=datetime.date.today().isoformat())
    a = ap.parse_args()

    seen = load("monitor/freshfeed-seen.json", {"defillama": [], "sourcify": {}})
    first_run = not seen["defillama"] and not seen["sourcify"]

    dl = defillama_fresh(a.days, a.tvl_min, a.date)
    new_dl = [c for c in dl if c["key"] not in set(seen["defillama"]) and not _suppressed(c["key"])]
    seen["defillama"] = sorted(set(seen["defillama"]) | {c["key"] for c in dl})

    new_src = {}
    if a.sourcify:
        sf = sourcify_fresh(a.chains.split(","))
        for ch, rows in sf.items():
            prev = set(seen["sourcify"].get(ch, []))
            fresh = [r for r in rows if r["addr"].lower() not in prev]
            seen["sourcify"][ch] = sorted(prev | {r["addr"].lower() for r in rows})
            if fresh:
                new_src[ch] = fresh

    os.makedirs(os.path.join(ROOT, "monitor"), exist_ok=True)
    json.dump(seen, open(os.path.join(ROOT, "monitor", "freshfeed-seen.json"), "w"), indent=1, sort_keys=True)

    n = len(new_dl) + sum(len(v) for v in new_src.values())
    write_queue(new_dl, new_src, a, first_run)
    print(f"[freshfeed] {len(dl)} fresh-listed our-zone protocols, {n} NEW since last run "
          + ("(baseline)" if first_run else ""))
    sys.exit(10 if (n and not first_run) else 0)


def write_queue(dl, src, a, first_run):
    p = os.path.join(ROOT, "hunts", "_radar", "FRESH-FEED.md")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    L = [f"# Fresh-feed radar  -- {a.date}", "",
         "> Brand-new code, WIDE net (vs freshdeploy's watched deployers): DefiLlama newly-listed our-zone "
         "protocols + Sourcify freshly-verified contracts. Newest = un-hardened/un-audited = the timing edge.", ""]
    if first_run:
        L.append("_First run: baseline seeded. New listings/verifications alert from next run._")
    else:
        L.append(f"## DefiLlama: {len(dl)} NEW our-zone protocol(s) listed (last {a.days}d)")
        L.append("")
        for c in dl[:20]:
            au = c["audits"] if c["audits"] not in (None, "", "0") else "audits=0"
            L.append(f"- **{c['name']}** ({c['category']}, {c['listed']}, TVL ${c['tvl']/1e6:.1f}M, {au}) "
                     f"zone:{','.join(c['zones'][:3])} chains:{','.join(c['chains'])}  {c['url']}")
        L.append("")
        if src:
            tot = sum(len(v) for v in src.values())
            L.append(f"## Sourcify: {tot} freshly-verified contract(s) on watched chains")
            for ch, rows in src.items():
                for r in rows[:8]:
                    L.append(f"- {ch}: `{r['addr']}` verified {r['verifiedAt']}  -> fetch_source + recon if our-zone")
            L.append("")
        if not dl and not src:
            L.append("**All quiet** - no new listings/verifications this run.")
    open(p, "w", encoding="utf-8").write("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
