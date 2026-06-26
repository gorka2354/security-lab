#!/usr/bin/env python3
"""radar.py - change/freshness radar over the triaged-target registry (Inc 2 of registry+radar).

AGENT-FIRST design: the output is NOT a notification, it's a SESSION-START WORK QUEUE
(hunts/_radar/QUEUE.md) with prior notes attached, so the hunting agent skips SOURCE+REACH and goes
straight to the fresh, in-context work. Two change signals, both gated on targets we ALREADY triaged
(prior context = the leverage):

  1. BOUNTY-OPEN  - one of our registry targets now has an open Immunefi program (in-scope + paid).
  2. IMPL-UPGRADE - an in-scope proxy of one of our targets points at a NEW implementation
                    (EIP-1967 impl-slot diff = audit-drift on live code we already mapped).

Addresses + chains come from the authoritative Immunefi public-api JSON (full addrs, ecosystem), not
from prose. Dedup via monitor/radar-seen.json (a change already queued never re-fires). Stdlib only.

    python toolkit/radar.py [--root .] [--date YYYY-MM-DD] [--max-assets 20]

Exit 10 if anything NEW was queued (cron-friendly). Reuses fetch_source (_rpc/DEFAULT_RPC), scout
(fetch_immunefi_programs_json), registry (norm_key).
"""

import argparse
import datetime
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fetch_source as fs           # _rpc, DEFAULT_RPC
import scout                        # fetch_immunefi_programs_json
import registry as reg              # norm_key

EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
# Immunefi `ecosystem` tag -> chain id (only chains we have a default RPC for get an impl check)
ECO_CHAIN = {"eth": 1, "ethereum": 1, "base": 8453, "arbitrum": 42161, "arb": 42161, "optimism": 10,
             "op": 10, "polygon": 137, "bsc": 56, "binance": 56, "linea": 59144, "mantle": 5000,
             "sonic": 146, "abstract": 2741, "hyperliquid": 999, "mezo": 31612}


def storage_impl(addr, chainid):
    """EIP-1967 implementation address from the proxy's impl slot, or None for a non-proxy/empty slot."""
    rpc = fs.DEFAULT_RPC.get(str(chainid))
    if not rpc:
        return None
    try:
        raw = fs._rpc(rpc, "eth_getStorageAt", [addr, EIP1967_IMPL_SLOT, "latest"])
    except Exception:
        return None
    if not raw or not raw.startswith("0x"):
        return None
    h = raw[2:].rjust(64, "0")
    impl = "0x" + h[-40:]
    return impl.lower() if int(impl, 16) != 0 else None


def load_json(path, default):
    if os.path.exists(path):
        try:
            return json.load(open(path, encoding="utf-8"))
        except Exception:
            pass
    return default


def main():
    ap = argparse.ArgumentParser(description="Change/freshness radar over the triaged-target registry")
    ap.add_argument("--root", default=os.path.join(os.path.dirname(__file__), ".."))
    ap.add_argument("--date", default=datetime.date.today().isoformat())
    ap.add_argument("--max-assets", type=int, default=20, help="impl-check at most N in-scope addrs/program")
    a = ap.parse_args()
    root = os.path.abspath(a.root)
    today = a.date

    registry = load_json(os.path.join(root, "monitor", "registry.json"), {"targets": {}})["targets"]
    if not registry:
        print("[radar] no registry.json - run `python toolkit/registry.py` first", file=sys.stderr)
        return
    seen_path = os.path.join(root, "monitor", "radar-seen.json")
    seen = load_json(seen_path, {"bounties": {}, "impls": {}})
    first_run = not seen["impls"] and not seen["bounties"]

    progs = scout.fetch_immunefi_programs_json() or []
    events = []   # NEW changes this run

    for p in progs:
        key = reg.norm_key(p.get("name"))
        tgt = registry.get(key)
        if not tgt:
            continue                                    # only signal on targets we've already triaged
        slug = p.get("slug") or key
        chainid = next((ECO_CHAIN[e] for e in (p.get("ecosystem") or []) if e in ECO_CHAIN), None)

        # --- signal 1: BOUNTY-OPEN (target we triaged now has an open Immunefi program) ---
        if slug not in seen["bounties"]:
            seen["bounties"][slug] = today
            if not first_run:                           # first run only seeds the baseline, no flood
                events.append({
                    "type": "BOUNTY-OPEN", "target": tgt["name"], "key": key, "slug": slug,
                    "detail": f"Immunefi program live (max ${p.get('maxBounty',0)/1e6:.2f}M, "
                              f"chains:{','.join(p.get('ecosystem') or []) or '?'}, "
                              f"{len(p.get('assets') or [])} in-scope contracts)",
                    "tgt": tgt,
                })

        # --- signal 2: IMPL-UPGRADE on in-scope proxies (audit-drift on live code) ---
        for addr in (p.get("assets") or [])[:a.max_assets]:
            if not chainid:
                break
            k = f"{chainid}_{addr.lower()}"
            cur = storage_impl(addr, chainid)
            if cur is None:
                continue                                # non-proxy / unreachable
            base = seen["impls"].get(k)
            seen["impls"][k] = cur
            if base and cur != base and not first_run:
                events.append({
                    "type": "IMPL-UPGRADE", "target": tgt["name"], "key": key, "slug": slug,
                    "detail": f"{addr} on chain {chainid}: reviewed impl {base} -> NEW {cur}",
                    "tgt": tgt,
                })

    os.makedirs(os.path.dirname(seen_path), exist_ok=True)
    json.dump(seen, open(seen_path, "w", encoding="utf-8"), indent=1, sort_keys=True)

    write_queue(events, today, first_run, os.path.join(root, "hunts", "_radar", "QUEUE.md"))
    tag = "(baseline seeded - no alerts on first run)" if first_run else f"{len(events)} NEW"
    print(f"[radar] {len(progs)} immunefi programs scanned, {len(registry)} registry targets -> {tag}")
    sys.exit(10 if events else 0)


PRIO = {"IMPL-UPGRADE": 0, "BOUNTY-OPEN": 1}


def write_queue(events, today, first_run, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    L = [f"# Radar queue  -- {today}", ""]
    L.append("> Session-start work-list. `radar.py` (cron) writes it; the agent reads it FIRST and "
             "re-hunts the fresh, in-context items. Prior notes are attached so SOURCE+REACH are skipped.")
    L.append("")
    if first_run:
        L.append("_First run: baseline seeded (impls + open bounties recorded). Real changes alert from next run._")
        open(path, "w", encoding="utf-8").write("\n".join(L) + "\n")
        return
    if not events:
        L.append("**All quiet** - no impl-upgrades or new bounties on our triaged targets this run.")
        open(path, "w", encoding="utf-8").write("\n".join(L) + "\n")
        return
    L.append(f"## {len(events)} NEW change(s) - re-hunt these")
    L.append("")
    for e in sorted(events, key=lambda x: PRIO.get(x["type"], 9)):
        t = e["tgt"]
        L.append(f"### [{e['type']}] {e['target']}")
        L.append(f"- **what:** {e['detail']}")
        L.append(f"- **prior verdict:** {t.get('status','?')}"
                 + (f" | fork-base: {t['fork_base']}" if t.get("fork_base") else "")
                 + (f" | zones: {','.join(t.get('zones',[])[:3])}" if t.get("zones") else ""))
        if t.get("last_reason"):
            L.append(f"- **prior notes:** {t['last_reason']}")
        hunt = f"hunts/{e['key']}/HUNT.md"
        nxt = ("diffscan/forkdrift the NEW impl vs our reviewed one; only the drift is fresh"
               if e["type"] == "IMPL-UPGRADE"
               else "in-scope + paid now -> fetch_source the in-scope addrs -> recon -> PoC, using our prior read")
        L.append(f"- **next:** {nxt}  (notes: {hunt} if present; scope: immunefi.com/bug-bounty/{e['slug']}/scope/)")
        L.append("")
    open(path, "w", encoding="utf-8").write("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
