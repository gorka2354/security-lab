#!/usr/bin/env python3
"""watch.py - monitor OUR findings: alert when a deferred/non-deployed finding goes LIVE.

We sometimes find a bug in code that isn't deployed yet (e.g. Malda's LZUnifiedBridge.lzCompose
drain) -> NOT a target now (out of scope, may never ship), but if it ships our finding becomes
live + disclosable. This polls each finding's "go-live" condition and reports the ones that FIRED.
Run it on a schedule (cron) so we passively watch every parked finding.

    python toolkit/watch.py [monitor/watchlist.json]

Check types (per finding):
  url_appears - fetch url(s); FIRE if `needle` (regex) now appears (e.g. an LZ bridge lands in a
                deploy registry that currently only lists Across/Everclear)
  code_at     - eth_getCode(chain,address); FIRE when bytecode appears (contract just deployed)
  call        - eth_call(chain,to,data); FIRE when the returned word is non-zero
                (e.g. Rebalancer.whitelistedBridges(lzAddr) flips to true)
Stdlib only. Exit code 2 if anything FIRED (cron-friendly: non-zero => notify).
"""

import json
import os
import re
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import fetch_source as fs  # reuse _rpc / DEFAULT_RPC for the on-chain checks
except Exception:
    fs = None


def _get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "security-lab-watch/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", "replace")


def check_url_appears(c):
    rx = re.compile(c["needle"])
    for u in c.get("urls", []):
        try:
            if rx.search(_get(u)):
                return True, f"/{c['needle']}/ now present in {u}"
        except Exception:
            pass  # transient url error -> treat as no-match (stay quiet, retry next run)
    return False, "needle absent in all urls (still parked)"


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
    print(f"watch: {len(findings)} parked finding(s)\n")
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
            print(f"[quiet] {f.get('id')}  ({detail})")
    print(f"\n{fired} FIRED / {len(findings)}." + ("  >>> a parked finding may be going live - verify + disclose." if fired else ""))
    sys.exit(2 if fired else 0)


if __name__ == "__main__":
    main()
