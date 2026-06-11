#!/usr/bin/env python3
"""livecheck.py - find post-audit DRIFT: does a live proxy run code NEWER than the audit?

The Cap lesson: a deployed protocol whose proxies still point at the audited implementation
has NO drift -> low EV (400 contest subs already shredded that code). The high-EV target is a
proxy that was UPGRADED *after* its audit -> the current implementation is unverified code.

This tool walks a proxy on-chain and reports:
  - current implementation (EIP-1967 slot / EIP-1167 bytecode, via fetch_source.resolve_impl)
  - the Upgraded(address) event history (block + date + impl)  [best-effort: needs getLogs]
  - DRIFT verdict: current impl != --audited <impl>, OR an upgrade dated after --since.

    python toolkit/livecheck.py <proxy> [<proxy>...] --chain 1 [--audited 0x..] [--since 2025-08-01]
    python toolkit/livecheck.py --config path/to/deployments.json --chain 1   # auto proxy/impl pairs

Then for any DRIFTed proxy:
    python toolkit/fetch_source.py <proxy> --chain 1 --proxy   # fetch the live (drifted) impl
    diff vs the audited source -> recon the delta. Stdlib only.

LIMITATION: only sees EIP-1967 `Upgraded(address)` + EIP-1167 minimal proxies. Custom router proxies
(e.g. Instadapp Fluid's InfiniteProxy emits `LogSetImplementation(address,bytes4[])`, OZ beacons,
diamond/EIP-2535) are invisible here and their EIP-1967 slot read can return garbage -> verify the
proxy pattern before trusting a "match" on a non-standard proxy.
"""

import argparse
import datetime
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fetch_source as fs  # reuse _rpc, resolve_impl, DEFAULT_RPC  # noqa: E402

# keccak256("Upgraded(address)") - the EIP-1967 upgrade event
UPGRADED_TOPIC = "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b"


def _addr_from_topic(t):
    return "0x" + t[-40:]


def latest_block(chain, rpc=None):
    rpc = rpc or fs.DEFAULT_RPC.get(str(chain))
    try:
        return int(fs._rpc(rpc, "eth_blockNumber", []), 16)
    except Exception:
        return None


def date_to_block(date_str, chain, rpc=None):
    """First block at/after midnight-UTC of date_str (YYYY-MM-DD), via binary search. None on failure."""
    rpc = rpc or fs.DEFAULT_RPC.get(str(chain))
    try:
        target = int(datetime.datetime.strptime(date_str, "%Y-%m-%d")
                     .replace(tzinfo=datetime.timezone.utc).timestamp())
    except Exception:
        return None
    hi = latest_block(chain, rpc)
    if hi is None:
        return None
    lo = 0
    while lo < hi:
        mid = (lo + hi) // 2
        try:
            ts = int(fs._rpc(rpc, "eth_getBlockByNumber", [hex(mid), False])["timestamp"], 16)
        except Exception:
            return None
        if ts < target:
            lo = mid + 1
        else:
            hi = mid
    return lo


def upgrade_history(proxy, chain, from_block, rpc=None, window=50000):
    """(block, impl) Upgraded events from from_block to latest, chunked (public nodes cap getLogs
    at ~50k blocks/call). Scanning only from the audit cutoff keeps it bounded. [] if unavailable."""
    rpc = rpc or fs.DEFAULT_RPC.get(str(chain))
    top = latest_block(chain, rpc)
    if rpc is None or top is None or from_block is None:
        return []
    out, start = [], from_block
    while start <= top:
        end = min(start + window - 1, top)
        try:
            res = fs._rpc(rpc, "eth_getLogs", [{"address": proxy, "topics": [UPGRADED_TOPIC],
                                                "fromBlock": hex(start), "toBlock": hex(end)}])
        except Exception:
            res = None
        if res is None:  # null/error != "no upgrades"; a silent [] here = false "not upgraded" = missed drift
            sys.stderr.write(f"[livecheck] WARN: getLogs failed for {hex(start)}-{hex(end)} -> "
                             "upgrade history may be INCOMPLETE (do not trust a 'no upgrades' result)\n")
            logs = []
        else:
            logs = res
        for lg in logs:
            topics = lg.get("topics", [])
            impl = _addr_from_topic(topics[1]) if len(topics) > 1 else _addr_from_topic(lg.get("data", ""))
            try:
                out.append((int(lg["blockNumber"], 16), impl))
            except Exception:
                pass
        start = end + 1
    return sorted(out)


def block_date(block, chain, rpc=None):
    rpc = rpc or fs.DEFAULT_RPC.get(str(chain))
    try:
        b = fs._rpc(rpc, "eth_getBlockByNumber", [hex(block), False])
        ts = int(b["timestamp"], 16)
        return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%d")
    except Exception:
        return "?"


def check(proxy, chain, audited=None, since=None, rpc=None):
    cur = fs.resolve_impl(proxy, chain, rpc)
    drift, why = False, []
    if audited and cur and cur.lower() != audited.lower():
        drift = True
        why.append(f"current impl {cur} != audited {audited}")
    # history: Upgraded events from the audit cutoff forward. Authoritative verdict is the
    # --audited impl compare above; history is informational UNLESS no audited impl is known
    # (then a post-cutoff upgrade is the best signal, caveat: may include the initial deploy).
    hist = []
    if since and cur:
        fb = date_to_block(since, chain, rpc)
        hist = upgrade_history(proxy, chain, fb, rpc)
        if hist and not audited:
            drift = True
            why.append(f"{len(hist)} Upgraded event(s) after {since} (post-audit upgrade? verify vs initial deploy)")
        elif hist and audited:
            why.append(f"{len(hist)} Upgraded event(s) after {since} (context; impl-compare is authoritative)")
    return {"proxy": proxy, "current_impl": cur, "history": hist, "drift": drift, "why": why}


def _extract_addresses(obj, found):
    if isinstance(obj, dict):
        for v in obj.values():
            _extract_addresses(v, found)
    elif isinstance(obj, list):
        for v in obj:
            _extract_addresses(v, found)
    elif isinstance(obj, str) and re.fullmatch(r"0x[0-9a-fA-F]{40}", obj):
        found.add(obj)


def main():
    ap = argparse.ArgumentParser(description="Find post-audit drift in live proxies")
    ap.add_argument("proxies", nargs="*", help="proxy addresses")
    ap.add_argument("--chain", default="1")
    ap.add_argument("--audited", help="expected audited impl address (DRIFT if current differs)")
    ap.add_argument("--since", help="audit cutoff date YYYY-MM-DD (DRIFT if upgraded after)")
    ap.add_argument("--rpc", help="RPC url (default: public node for the chain)")
    ap.add_argument("--config", help="deployments json to harvest candidate addresses from")
    a = ap.parse_args()

    targets = list(a.proxies)
    if a.config:
        found = set()
        _extract_addresses(json.load(open(a.config, encoding="utf-8")), found)
        targets += sorted(found)
    if not targets:
        ap.error("give proxy address(es) or --config")

    # RPC health probe: a dead/blocked RPC (e.g. llamarpc HTTP 526) otherwise makes resolve_impl
    # raise -> swallowed -> every proxy silently mislabeled "non-proxy". Fail loud instead.
    rpc = a.rpc or fs.DEFAULT_RPC.get(str(a.chain))
    if latest_block(a.chain, rpc) is None:
        print(f"[!] RPC not responding: {rpc or '(no default for chain ' + a.chain + ')'}. "
              f"A dead RPC makes every proxy look like 'non-proxy' - aborting. Pass a working --rpc.")
        return

    print(f"livecheck chain {a.chain} - {len(targets)} address(es) via {rpc}. DRIFT = live code newer than audit.\n")
    drifted = 0
    for p in targets:
        r = check(p, a.chain, a.audited, a.since, a.rpc)
        if not r["current_impl"]:
            print(f"[ skip ] {p}  (EOA / non-proxy / no impl)")
            continue
        tag = ">>> DRIFT" if r["drift"] else "  match "
        print(f"[{tag}] {p}  impl={r['current_impl']}")
        for b, impl in r["history"]:
            print(f"            upgrade @ block {b} ({block_date(b, a.chain, a.rpc)}) -> {impl}")
        for w in r["why"]:
            print(f"            ! {w}")
        drifted += 1 if r["drift"] else 0
    print(f"\n{drifted} drifted / {len(targets)}. Next on DRIFT: fetch_source <proxy> --proxy -> diff vs audit -> recon.")


if __name__ == "__main__":
    main()
