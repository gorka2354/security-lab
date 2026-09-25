#!/usr/bin/env python3
"""freshdeploy.py - FRESH-DEPLOY radar: watch known deployers/factories for brand-new contracts.

The strategic lever (zero live-findings = the FRESHNESS wall, not detector coverage): be FIRST on genuinely
fresh code, before it's hardened/audited. This watches the DEPLOYERS and FACTORIES of protocols we already
understand and surfaces any NEW contract they create (verified source = reachable + fresh = dig now), in its
first hours. The reasoning-tier bugs that survive in hardened code are still live in fresh unaudited deploys.

    python toolkit/freshdeploy.py                       # scan the watchlist, write hunts/_radar/FRESH-DEPLOY.md
    python toolkit/freshdeploy.py --add <addr> <chain> [label] [--factory]   # watch a deployer (or --factory)
    python toolkit/freshdeploy.py --seed-fetched        # seed deployers from fetched/<chain>_<addr> (their creators)
    python toolkit/freshdeploy.py --list                # show the watchlist

Reuses legacy.deployer_contracts (txlist) + legacy.factory_spawned (txlistinternal) + Etherscan-v2
(getcontractcreation / getsourcecode). Exit 10 if a NEW deploy was queued (cron-friendly). Stdlib only.
"""

import argparse
import datetime
import json
import os
import sys
import urllib.request
import tlsfix  # noqa: F401,E402  -- current CA bundle on stale-CA Windows hosts (see tlsfix.py)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import legacy   # deployer_contracts / factory_spawned (Etherscan-v2 enumeration)

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CHAIN_ID = {"eth": 1, "ethereum": 1, "base": 8453, "arb": 42161, "arbitrum": 42161, "op": 10, "optimism": 10,
            "polygon": 137, "bsc": 56, "linea": 59144, "mantle": 5000, "sonic": 146, "abstract": 2741,
            "apechain": 33139, "ape": 33139, "hyperevm": 999, "mezo": 31612}


def cid(chain):
    return CHAIN_ID.get(str(chain).lower(), str(chain))


def _es(chainid, params):
    key = os.environ.get("ETHERSCAN_API_KEY", "")
    url = f"https://api.etherscan.io/v2/api?chainid={chainid}&{params}&apikey={key}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "security-lab-freshdeploy"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except Exception:
        return {}


def creator_of(addr, chainid):
    """The deployer (EOA/factory) that created `addr`, via getcontractcreation. None if unknown."""
    d = _es(chainid, f"module=contract&action=getcontractcreation&contractaddresses={addr}")
    res = d.get("result")
    if isinstance(res, list) and res:
        return (res[0].get("contractCreator") or "").lower() or None
    return None


def is_verified(addr, chainid):
    """ContractName if the address has verified source, else ''. Marks a fresh child as reachable."""
    d = _es(chainid, f"module=contract&action=getsourcecode&address={addr}")
    res = d.get("result")
    r0 = res[0] if isinstance(res, list) and res else {}
    return (r0.get("ContractName") or "") if (r0.get("SourceCode") or "") else ""


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


def add_deployer(addr, chain, label, factory):
    wl = load("monitor/deployers.json", {"deployers": []})
    chainid = cid(chain)
    kind = "factory" if factory else "deployer"
    if not any(d["addr"].lower() == addr.lower() and str(d["chain"]) == str(chainid) for d in wl["deployers"]):
        wl["deployers"].append({"addr": addr, "chain": str(chainid), "label": label or addr[:10], "kind": kind})
        save("monitor/deployers.json", wl)
        print(f"[freshdeploy] watching {kind} {addr} (chain {chainid}) '{label or ''}'")
    else:
        print("[freshdeploy] already watched")


def children_of(d):
    chainid = d["chain"]
    if d["kind"] == "factory":
        return legacy.factory_spawned(d["addr"], chainid) or []
    return legacy.deployer_contracts(d["addr"], chainid) or []


def scan(today):
    wl = load("monitor/deployers.json", {"deployers": []})["deployers"]
    seen = load("monitor/freshdeploy-seen.json", {})
    first_run = not seen
    events = []
    for d in wl:
        k = f"{d['chain']}_{d['addr'].lower()}"
        kids = [c.lower() for c in children_of(d) if c]
        prev = set(seen.get(k, []))
        new = [c for c in kids if c not in prev]
        seen[k] = sorted(prev | set(kids))
        if new and not first_run:
            for child in new[:25]:
                name = is_verified(child, d["chain"])
                events.append({"deployer": d["addr"], "label": d["label"], "kind": d["kind"],
                               "chain": d["chain"], "child": child, "verified": name})
    save("monitor/freshdeploy-seen.json", seen)
    write_queue(events, today, first_run, wl)
    tag = "(baseline seeded)" if first_run else f"{len(events)} NEW deploy(s)"
    print(f"[freshdeploy] {len(wl)} deployers/factories scanned -> {tag}")
    return events, first_run


def write_queue(events, today, first_run, wl):
    p = os.path.join(ROOT, "hunts", "_radar", "FRESH-DEPLOY.md")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    L = [f"# Fresh-deploy radar  -- {today}", "",
         "> Brand-new contracts from deployers/factories of protocols we understand. A VERIFIED fresh deploy = "
         "reachable + un-hardened = dig FIRST (the timing edge). Watchlist: monitor/deployers.json.", ""]
    if first_run:
        L.append(f"_First run: baseline seeded for {len(wl)} watched deployer(s). New deploys alert from next run._")
    elif not events:
        L.append(f"**All quiet** - no new contracts from the {len(wl)} watched deployer(s) this run.")
    else:
        ver = [e for e in events if e["verified"]]
        L.append(f"## {len(events)} NEW deploy(s) — {len(ver)} verified (reachable, dig first)")
        L.append("")
        for e in sorted(events, key=lambda x: 0 if x["verified"] else 1):
            tag = f"**{e['verified']}** (verified)" if e["verified"] else "_unverified yet_"
            L.append(f"### {e['label']} ({e['kind']}) -> NEW {tag}")
            L.append(f"- contract: {e['child']} on chain {e['chain']}  (from {e['deployer']})")
            nxt = ("fetch_source + forkdrift + recon NOW — fresh, in-context, likely un-audited"
                   if e["verified"] else "watch for verification, then triage")
            L.append(f"- next: {nxt}")
            L.append("")
    open(p, "w", encoding="utf-8").write("\n".join(L) + "\n")


def main():
    ap = argparse.ArgumentParser(description="Fresh-deploy radar over known deployers/factories")
    ap.add_argument("--add", nargs="+", metavar="ADDR CHAIN [LABEL]")
    ap.add_argument("--factory", action="store_true", help="the --add target is a factory (txlistinternal)")
    ap.add_argument("--seed-fetched", action="store_true", help="seed deployers from fetched/<chain>_<addr> creators")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--date", default=datetime.date.today().isoformat())
    a = ap.parse_args()

    if a.add:
        addr, chain = a.add[0], a.add[1]
        label = " ".join(a.add[2:]) if len(a.add) > 2 else ""
        add_deployer(addr, chain, label, a.factory)
        return
    if a.list:
        for d in load("monitor/deployers.json", {"deployers": []})["deployers"]:
            print(f"  [{d['kind']}] {d['addr']} chain {d['chain']}  {d['label']}")
        return
    if a.seed_fetched:
        import re
        fdir = os.path.join(ROOT, "fetched")
        n = 0
        for name in os.listdir(fdir) if os.path.isdir(fdir) else []:
            m = re.match(r"(\d+)_(0x[a-fA-F0-9]{40})$", name)
            if not m:
                continue
            cr = creator_of(m.group(2), m.group(1))
            if cr:
                add_deployer(cr, m.group(1), f"creator-of-{m.group(2)[:8]}", False)
                n += 1
        print(f"[freshdeploy] seeded {n} deployer(s) from fetched/")
        return

    events, first_run = scan(a.date)
    sys.exit(10 if (events and not first_run) else 0)


if __name__ == "__main__":
    main()
