#!/usr/bin/env python3
"""contest_monitor.py - the TIMING EDGE: alert on freshly-launched audit contests so we hunt them in the
FIRST hours (fresh surface), not on day 13 when the wardens have picked it clean.

Session lesson (2026-06): the reachable hunting space is dominated by audited/formally-verified code; the
only channel where code is GUARANTEED genuinely-under-reviewed is a LIVE audit contest -- but only while it's
FRESH. This polls Cantina + Sherlock + Code4rena, normalizes their listings, and flags:
  [NEW]   - appeared since the last run (diff vs monitor/contests-seen.json)
  [FRESH] - started < --fresh-hours ago (default 48) AND still live  -> HUNT NOW
Rank = freshness x pot x our-zone (GameFi gets a bonus -- egor's edge). Built for cron (like watch.py).

    python toolkit/contest_monitor.py [--fresh-hours 48] [--min-pot 0] [--no-state]

ASCII output. Stdlib only (urllib). Pure parsers (parse_*/classify/rank) are unit-tested; only fetch + the
seen-state file touch IO. Chain/zone is best-effort from title+desc (the listing rarely states EVM cleanly).
"""

import argparse
import datetime
import json
import os
import re
import time
import urllib.request

CANTINA = "https://cantina.xyz/api/v0/competitions?status=active&limit=50"
SHERLOCK = "https://mainnet-contest.sherlock.xyz/contests"
CODE4RENA = "https://code4rena.com/api/v1/audits"
STATE_FILE = "monitor/contests-seen.json"

# our wheelhouse (smart-contract DeFi/RWA) + GameFi (egor's edge -> bonus). Lowercase substring match on
# title+desc. NON_EVM markers down-rank a listing (Solana/Move/consensus-client = our Solidity engine can't).
ZONE = ["lend", "lending", "borrow", "vault", "yield", "stablecoin", "stable", "cdp", "collateral",
        "perp", "derivativ", "oracle", "stak", "restak", "liquid", "amm", "dex", "swap", "rwa",
        "bridge", "cross-chain", "synthetic", "fixed-rate", "credit", "debt", "options", "lst", "lrt",
        "predict", "prediction", "betting", "wager", "gambl", "lottery", "luck", "payout", "odds"]
GAMEFI = ["game", "gaming", "gamefi", "nft", "on-chain game", "p2e", "play-to-earn", "metaverse",
          "raffle", "lottery", "gambl", "betting", "wager", "sportsbook", "casino", "luck", "jackpot",
          "predict", "prediction", "dice", "roulette", "coinflip", "gacha", "loot"]
NON_EVM = ["solana", "sealevel", "anchor ", "move ", "aptos", "sui ", "cairo", "starknet", "cosmwasm",
           "cosmos sdk", "substrate", "consensus client", "beacon", "rust client", "stellar", "soroban",
           "ton ", "near ", "fuel ", "tact "]


def _iso_to_unix(s):
    """ISO-8601 (with 'Z' or offset) -> unix seconds. Returns 0 on failure. PURE."""
    if not s:
        return 0
    try:
        return int(datetime.datetime.fromisoformat(str(s).replace("Z", "+00:00")).timestamp())
    except Exception:
        return 0


def _unix_to_iso(u):
    try:
        return datetime.datetime.fromtimestamp(int(u), datetime.timezone.utc).strftime("%Y-%m-%d")
    except Exception:
        return "?"


def _pot_int(v):
    """Parse a reward pot to int USD: handles 12345, '12345', '$100,000', '100000 USDC'. PURE."""
    if isinstance(v, (int, float)):
        return int(v)
    digits = re.sub(r"[^0-9]", "", str(v or "").split(".")[0])
    return int(digits) if digits else 0


def parse_cantina(data):
    """Cantina /competitions list -> normalized records. PURE (data = parsed JSON list)."""
    out = []
    for c in (data or []):
        if not isinstance(c, dict):
            continue
        tf = c.get("timeframe") or {}
        out.append({
            "platform": "cantina", "title": c.get("name", "?"),
            "url": c.get("url", ""), "id": str(c.get("id", "")),
            "pot": _pot_int(c.get("totalRewardPot")),
            "start_unix": _iso_to_unix(tf.get("start")), "end_unix": _iso_to_unix(tf.get("end")),
            "status": (c.get("status") or "").lower(),
            "desc": (c.get("instructions") or "")[:400],
            "repo": ((c.get("company") or {}).get("github") or ""),
        })
    return out


def parse_sherlock(data):
    """Sherlock /contests {items:[...]} -> normalized records. PURE."""
    out = []
    for it in (data or {}).get("items", []):
        if not isinstance(it, dict):
            continue
        out.append({
            "platform": "sherlock", "title": it.get("title", "?"),
            "url": f"https://audits.sherlock.xyz/contests/{it.get('id','')}", "id": str(it.get("id", "")),
            "pot": _pot_int(it.get("rewards") or it.get("prize_pool")),
            "start_unix": int(it.get("starts_at") or 0), "end_unix": int(it.get("ends_at") or 0),
            "status": (it.get("status") or "").lower(),
            "desc": (it.get("short_description") or "")[:400], "repo": "",
        })
    return out


def parse_code4rena(data):
    """Code4rena /api/v1/audits {data:{audits:[...]}} -> normalized records. PURE."""
    out = []
    audits = ((data or {}).get("data") or {}).get("audits") or []
    for a in audits:
        if not isinstance(a, dict):
            continue
        out.append({
            "platform": "code4rena", "title": a.get("title", "?"),
            "url": f"https://code4rena.com/audits/{a.get('slug','')}", "id": str(a.get("uid") or a.get("slug", "")),
            "pot": _pot_int(a.get("formattedAmount")),
            "start_unix": _iso_to_unix(a.get("startTime")), "end_unix": _iso_to_unix(a.get("endTime")),
            "status": (a.get("status") or "").lower(),
            "desc": (a.get("details") or a.get("title") or "")[:400], "repo": a.get("repo") or "",
        })
    return out


def is_live(c, now_unix):
    """Within the contest window (or status says live/running), and a real end in the future. PURE."""
    s, e = c.get("start_unix", 0), c.get("end_unix", 0)
    if e and e < now_unix:
        return False
    st = c.get("status", "")
    if st in ("complete", "completed", "judging", "escalation", "finished", "sherlock_judging"):
        return False
    if s and e:
        return s <= now_unix <= e
    return st in ("live", "running", "active")


def zone_hits(c):
    blob = (c.get("title", "") + " " + c.get("desc", "")).lower()
    return sorted({k for k in ZONE if k in blob})


def is_gamefi(c):
    blob = (c.get("title", "") + " " + c.get("desc", "")).lower()
    return any(k in blob for k in GAMEFI)


def looks_non_evm(c):
    blob = (c.get("title", "") + " " + c.get("desc", "")).lower()
    return any(k in blob for k in NON_EVM)


def hours_since_start(c, now_unix):
    s = c.get("start_unix", 0)
    return (now_unix - s) / 3600.0 if s else 9e9


def score(c, now_unix, fresh_hours):
    """Rank = freshness (fresher=more) + pot (bounded) + zone + GameFi bonus - non-EVM penalty. PURE."""
    age_h = hours_since_start(c, now_unix)
    fresh = max(0.0, 1.0 - age_h / max(fresh_hours, 1)) * 200      # decays to 0 at fresh_hours
    return (fresh
            + min(c.get("pot", 0), 1_000_000) / 10_000              # pot, capped at 100 pts
            + 20 * len(zone_hits(c))
            + (60 if is_gamefi(c) else 0)
            - (120 if looks_non_evm(c) else 0))


def contest_key(c):
    return f"{c['platform']}:{c.get('id') or c.get('title','')}".lower()


def alertable(live, new_keys, now_unix, fresh_hours):
    """PURE: the contests worth a desktop ALERT this run -- NEW (unseen) AND FRESH (< fresh_hours) AND EVM-likely
    AND in our zone (DeFi-zone hit or GameFi). This is the timing-edge trigger: a freshly-launched, in-scope,
    hunt-able contest we haven't seen before. Returns them ranked (best first)."""
    out = [c for c in live
           if contest_key(c) in new_keys
           and hours_since_start(c, now_unix) < fresh_hours
           and not looks_non_evm(c)
           and (zone_hits(c) or is_gamefi(c))]
    return sorted(out, key=lambda c: -score(c, now_unix, fresh_hours))


def _get(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (security-lab contest-monitor)"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception as e:
        print(f"  [warn] {url}: {e}")
        return None


def load_seen(path):
    try:
        return set(json.load(open(path, encoding="utf-8")))
    except Exception:
        return set()


def save_seen(path, keys):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    json.dump(sorted(keys), open(path, "w", encoding="utf-8"), indent=0)


def main():
    ap = argparse.ArgumentParser(description="Monitor audit-contest platforms; flag NEW + FRESH live contests")
    ap.add_argument("--fresh-hours", type=float, default=48, help="a contest started < N hours ago = FRESH (hunt now)")
    ap.add_argument("--min-pot", type=float, default=0, help="hide contests with pot < N USD")
    ap.add_argument("--no-state", action="store_true", help="don't read/write the seen-state (no [NEW] flagging)")
    ap.add_argument("--state", default=STATE_FILE)
    ap.add_argument("--alert", action="store_true",
                    help="cron/Task mode: on a NEW+FRESH+our-zone contest, append monitor/ALERTS.md and exit 10")
    a = ap.parse_args()
    now = int(time.time())

    contests = []
    # a NULL fetch (platform down / API changed) must NOT silently become "0 contests" -> we'd miss a
    # fresh contest (the timing edge). Warn loudly so degraded coverage is visible, don't fail silent.
    _cant, _sher, _c4 = _get(CANTINA), _get(SHERLOCK), _get(CODE4RENA)
    for _name, _raw in (("Cantina", _cant), ("Sherlock", _sher), ("Code4rena", _c4)):
        if _raw is None:
            print(f"[WARN] {_name} fetch FAILED -> its contests are MISSING this run (coverage degraded, NOT 'none live')")
    contests += parse_cantina(_cant or [])
    contests += parse_sherlock(_sher or {})
    contests += parse_code4rena(_c4 or {})

    live = [c for c in contests if is_live(c, now) and c.get("pot", 0) >= a.min_pot]
    live.sort(key=lambda c: -score(c, now, a.fresh_hours))

    seen = set() if a.no_state else load_seen(a.state)
    new_keys = {contest_key(c) for c in live} - seen

    print(f"# Audit-contest monitor  ({_unix_to_iso(now)})  -- {len(live)} live (of {len(contests)} listed)\n")
    if not live:
        print("  (no live contests across Cantina/Sherlock/Code4rena right now)")
    for c in live:
        age_h = hours_since_start(c, now)
        flags = []
        if contest_key(c) in new_keys:
            flags.append("NEW")
        if age_h < a.fresh_hours:
            flags.append(f"FRESH {age_h:.0f}h")
        if is_gamefi(c):
            flags.append("GAMEFI")
        if looks_non_evm(c):
            flags.append("non-EVM?")
        tag = ("  [" + " | ".join(flags) + "]") if flags else ""
        z = ",".join(zone_hits(c)) or "-"
        print(f"- [{c['platform']:9}] {c['title'][:38]:38} ${c['pot']/1e3:>5.0f}k  "
              f"ends {_unix_to_iso(c['end_unix'])}  zone:{z}{tag}")
        print(f"    {c['url']}" + (f"  repo:{c['repo']}" if c['repo'] else ""))

    fresh = [c for c in live if hours_since_start(c, now) < a.fresh_hours and not looks_non_evm(c)]
    if fresh:
        print(f"\n>>> {len(fresh)} FRESH + EVM-likely -> HUNT NOW (first-hours edge): "
              + ", ".join(c["title"][:24] for c in fresh[:5]))
    print("\nNext: pick a FRESH our-zone contest -> clone its repo -> forkdrift -> recon/hypothesize -> PoC.")
    print("Cron it (like watch.py) to catch launches within the hour: it flags [NEW] vs the seen-state.")

    # --alert: the always-on Task trigger. Compute the NEW+FRESH+our-zone contests, persist an ALERTS.md line,
    # and exit 10 so a Windows-Task / cron wrapper can fire a desktop notification. (State is still saved below,
    # so the SAME contest won't re-alert next run.)
    hits = alertable(live, new_keys, now, a.fresh_hours) if a.alert else []
    if a.alert and hits:
        os.makedirs("monitor", exist_ok=True)
        with open("monitor/ALERTS.md", "a", encoding="utf-8") as f:
            for c in hits:
                f.write(f"- {_unix_to_iso(now)}  [{c['platform']}] {c['title'][:60]}  ${c['pot']/1e3:.0f}k  "
                        f"ends {_unix_to_iso(c['end_unix'])}  zone:{','.join(zone_hits(c)) or 'gamefi'}  {c['url']}\n")
        print("ALERT: " + str(len(hits)) + " new fresh our-zone contest(s): "
              + "; ".join(c["title"][:30] for c in hits))

    if not a.no_state:
        save_seen(a.state, seen | {contest_key(c) for c in live})
    if a.alert and hits:
        raise SystemExit(10)


if __name__ == "__main__":
    main()
