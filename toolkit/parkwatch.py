#!/usr/bin/env python3
"""parkwatch.py - monitor our PARKED leads: alert when a deferred/non-deployed finding goes LIVE.

We sometimes find a bug in code that isn't deployed yet (e.g. Malda's LZUnifiedBridge.lzCompose
drain) or in live code with no in-scope bounty (Panoptic V2 / Vena / GAIB) -> NOT a target now, but
if it ships / a program opens, our lead becomes live + disclosable. This polls each lead's "go-live"
condition (monitor/watchlist.json) and reports the ones that FIRED.
Run it on a schedule (cron / .github/workflows/watch.yml) so we passively watch every parked lead.

    python toolkit/parkwatch.py [monitor/watchlist.json]

NB: this was toolkit/watch.py until 2026-08-21, when watch.py became the VALUE/LIVENESS change-event
monitor (monitor/watch-targets.json) and the parked-lead engine was dropped by accident -- the daily
job then ran the wrong script and every run exited 2 (argparse usage error), which the workflow read
as "FIRED". Restored here under its own name on 2026-09-25; the two watchers are separate on purpose.

Check types (per lead):
  url_appears     - fetch url(s); FIRE if `needle` (regex) now appears, JSON-aware: a status-bearing
                    item fires only if ACTIVE (a completed Cantina comp does not)
  code_at         - eth_getCode(chain,address); FIRE when bytecode appears (contract just deployed)
  call            - eth_call(chain,to,data); FIRE when the returned word is non-zero
                    (e.g. Rebalancer.whitelistedBridges(lzAddr) flips to true)
  github_new_repo - FIRE when a new repo appears in a GitHub org after `since`
  proxy_upgraded  - FIRE when a tracked proxy's impl != the reviewed `known_impl`
Stdlib only. Exit code 10 if anything FIRED (same convention as watch.py run / contest_monitor /
secrets_sweep); any other non-zero exit is a real error, never a fire.
"""

import json
import os
import re
import sys
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import fetch_source as fs  # reuse _rpc / DEFAULT_RPC for the on-chain checks
except Exception:
    fs = None

FIRED_EXIT = 10


def _get(url):
    # browser UA: some bounty/contest hosts (Immunefi/Cloudflare) vary content or 403 a bot UA
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", "replace")


# statuses that mean "huntable right now" (a fire condition). Anything else (complete/ended/
# paused/draft/judging/upcoming...) is NOT a live authorized program -> do not fire.
_ACTIVE_STATUS = {"active", "live", "open", "ongoing", "running", "in progress", "in_progress"}
_STATUS_KEYS = ("status", "state", "phase")


def _iter_dicts(node):
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from _iter_dicts(v)
    elif isinstance(node, list):
        for v in node:
            yield from _iter_dicts(v)


def _active_match(body, rx):
    """JSON-aware match: find per-item dicts whose OWN scalar values hit the needle AND that carry a
    status field; fire only if such an item is ACTIVE. Returns (fired, reason, decided).
    `decided` is False when the feed has no status-bearing item matching the needle -> caller falls
    back to the raw substring check (covers presence-based feeds like Immunefi bounties.json)."""
    try:
        data = json.loads(body)
    except Exception:
        return False, "", False                      # not JSON -> let caller raw-match (HTML feeds)
    candidates = []
    for d in _iter_dicts(data):
        st = next((str(d[k]).lower() for k in _STATUS_KEYS if k in d and isinstance(d[k], (str, int))), None)
        if st is None:
            continue
        # shallow re-dump (scalars only) so quote-anchored needles like '"panoptic' still match,
        # while nested children (which belong to their own item dict) are excluded.
        own = json.dumps({k: v for k, v in d.items() if isinstance(v, (str, int, float, bool))})
        if rx.search(own):
            candidates.append((st, d))
    if not candidates:
        return False, "", False                      # no status-bearing item matched -> raw fallback
    for st, d in candidates:
        if st in _ACTIVE_STATUS:
            nm = d.get("name") or d.get("title") or d.get("slug") or "?"
            return True, f"ACTIVE program '{nm}' (status={st})", True
    sts = sorted({st for st, _ in candidates})
    return False, f"matched only non-active item(s) (status={','.join(sts)}) -> still parked", True


def check_url_appears(c):
    rx = re.compile(c["needle"])
    urls = c.get("urls", [])
    last = "needle absent in reachable urls (still parked)"
    blind = []
    for u in urls:
        try:
            body = _get(u)
        except Exception as e:
            # not a fire (retry next run), but an unread feed is NOT a quiet feed -> name it in the reason
            blind.append(f"{urllib.parse.urlsplit(u).netloc} ({str(e)[:70]})")
            continue
        fired, reason, decided = _active_match(body, rx)
        if fired:
            return True, f"{reason} in {u}"
        if decided:
            last = reason  # status-bearing feed said not-active here -> remember why, don't raw-match
            continue
        if rx.search(body):                            # presence-based / non-JSON feed
            return True, f"/{c['needle']}/ now present in {u}"
    if urls and len(blind) == len(urls):
        return False, "BLIND: no feed reachable -- " + "; ".join(blind)
    if blind:
        last += " | UNREACHABLE: " + "; ".join(blind)
    return False, last


def check_code_at(c):
    if not fs:
        return False, "no rpc module"
    rpc = c.get("rpc") or fs.DEFAULT_RPC.get(str(c.get("chain")))
    try:
        code = fs._rpc(rpc, "eth_getCode", [c["address"], "latest"]) or "0x"
    except Exception as e:
        return False, f"rpc error: {e}"
    return (len(code) > 2), (f"{c['address']} now has {len(code) // 2 - 1} bytes" if len(code) > 2 else "no code yet")


def check_call(c):
    if not fs:
        return False, "no rpc module"
    rpc = c.get("rpc") or fs.DEFAULT_RPC.get(str(c.get("chain")))
    try:
        res = fs._rpc(rpc, "eth_call", [{"to": c["to"], "data": c["data"]}, "latest"]) or "0x"
    except Exception as e:
        return False, f"rpc error: {e}"
    nonzero = res not in ("0x", "0x" + "0" * 64)
    return nonzero, f"eth_call -> {res}"


def check_github_new_repo(c):
    """FIRE when a NEW repo appears in a GitHub org after `since` (optional name_matches regex).
    Proactive fresh-code signal: a new hats-finance repo = a fresh no-KYC audit competition to hunt FIRST."""
    org = c["org"]
    since = c.get("since", "")
    pat = re.compile(c["name_matches"]) if c.get("name_matches") else None
    try:
        repos = json.loads(_get(f"https://api.github.com/orgs/{org}/repos?sort=created&direction=desc&per_page=30"))
    except Exception as e:
        return False, f"github error: {e}"
    new = []
    for r in repos if isinstance(repos, list) else []:
        if since and (r.get("created_at", "") <= since):
            continue
        if pat and not pat.search(r.get("name", "")):
            continue
        new.append(r.get("name"))
    if new:
        return True, f"new {org} repo(s) since {since}: {', '.join(new[:6])}"
    return False, f"no new {org} repos since {since}"


def check_proxy_upgraded(c):
    """FIRE when a tracked proxy's current implementation != the known/reviewed impl (a post-review
    upgrade -> fresh unverified code = drift to hunt). After triaging, update known_impl."""
    if not fs:
        return False, "no rpc module"
    cur = fs.resolve_impl(c["proxy"], c.get("chain"), c.get("rpc"))
    if not cur:
        return False, "no impl resolved (RPC down / non-proxy?)"
    if cur.lower() != (c.get("known_impl") or "").lower():
        return True, f"impl changed: reviewed {c.get('known_impl')} -> current {cur}"
    return False, f"impl unchanged ({cur})"


CHECKS = {"url_appears": check_url_appears, "code_at": check_code_at, "call": check_call,
          "github_new_repo": check_github_new_repo, "proxy_upgraded": check_proxy_upgraded}


def main():
    default = os.path.join(os.path.dirname(__file__), "..", "monitor", "watchlist.json")
    path = sys.argv[1] if len(sys.argv) > 1 else default
    data = json.load(open(path, encoding="utf-8"))
    findings = data.get("findings", [])
    print(f"parkwatch: {len(findings)} parked lead(s)\n")
    fired = 0
    for f in findings:
        c = f.get("check", {})
        fn = CHECKS.get(c.get("type"))
        if not fn:
            print(f"[ ?? ] {f.get('id')}  (unknown check type: {c.get('type')})")
            continue
        hit, detail = fn(c)
        if hit:
            fired += 1
            print(f"[FIRED] {f.get('id')}")
            print(f"        {f.get('title')}")
            print(f"        signal : {detail}")
            print(f"        action : {f.get('fire_means', '')}\n")
        else:
            print(f"[{'BLIND' if detail.startswith('BLIND') else 'quiet'}] {f.get('id')}  ({detail})")
    print(f"\n{fired} FIRED / {len(findings)}." + ("  >>> a parked lead may be going live - verify + disclose." if fired else ""))
    sys.exit(FIRED_EXIT if fired else 0)


if __name__ == "__main__":
    main()
