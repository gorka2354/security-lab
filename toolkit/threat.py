"""Post-finding protocol/contract THREAT assessment (LIVE-FIRST).

After a finding, the severity + disclosure urgency depend on real-world questions a code read
can't answer:
  - is the protocol/contract actually LIVE + ACTIVE, or dormant / ABANDONED?
  - is it value-bearing NOW (funds at risk), and how much?
  - (factory / multi-instance) how many instances exist -> the blast radius?
  - => a THREAT LEVEL that grounds severity, sets disclosure urgency, and FILTERS the
    dead / pre-launch / abandoned findings (the gladiator-not-live + equivaults-pre-launch lesson;
    the Morpho decoy-address lesson: the DefiLlama protocol.address is often NOT the real contract).

This is the "post-osмотр" step: run it on the vulnerable contract (and its factory) after a finding.
Reuses activity.py's probe/txcount + adds recency/abandonment (last-tx age) + a threat classifier.
Read-only (eth_call / Etherscan-v2 txlist). A COARSE liveness+value oracle, not a per-function one --
still confirm the exact bug-path is reachable/used.

Usage:
  python toolkit/threat.py <addr> --chain <id> [--token 0x..[,0x..]] [--count "allVaultsLength()"]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import activity as act  # noqa: E402  (reuse probe / etherscan_txcount / classify helpers)
import fetch_source as fs  # noqa: E402

ETHERSCAN_KEY = os.environ.get("ETHERSCAN_API_KEY", "")

# abandonment thresholds (days since last on-chain tx)
_ACTIVE_D = 30      # <= 30d since last tx -> actively used
_DORMANT_D = 180    # 30..180d -> dormant; > 180d -> abandoned


def _txlist_one(addr, chain, sort):
    """The single most-recent (sort='desc') or first (sort='asc') tx of `addr` via Etherscan-v2 txlist.
    Returns the tx dict or None. The txlist is authoritative for liveness where eth_getLogs false-0s."""
    if not ETHERSCAN_KEY:
        return None
    url = ("https://api.etherscan.io/v2/api?chainid=%s&module=account&action=txlist&address=%s"
           "&startblock=0&endblock=99999999&page=1&offset=1&sort=%s&apikey=%s"
           % (chain, addr, sort, ETHERSCAN_KEY))
    try:
        with urllib.request.urlopen(url, timeout=20) as r:
            data = json.load(r)
        if data.get("status") == "1" and data.get("result"):
            return data["result"][0]
    except Exception:
        return None
    return None


def _age_days(tx):
    try:
        return (int(time.time()) - int(tx["timeStamp"])) / 86400.0
    except Exception:
        return None


def last_activity_days(addr, chain):
    """Days since the LAST on-chain tx (abandonment signal). None if unknown."""
    tx = _txlist_one(addr, chain, "desc")
    return _age_days(tx) if tx else None


def deploy_age_days(addr, chain):
    """Days since the FIRST tx touching the address (rough deploy/first-use age). None if unknown."""
    tx = _txlist_one(addr, chain, "asc")
    return _age_days(tx) if tx else None


def assess(has_code, supply, eth_wei, token_bals, txcount, last_days):
    """-> (threat_level, urgency). Combines liveness + value + recency into a disclosure-relevant verdict.
    Filters the not-live findings (a bug matters only in deployed + active + value-bearing code)."""
    if not has_code:
        return "DEAD / EOA", "no contract at this address (decoy? self-destructed?) -> not a live target."
    has_value = (eth_wei or 0) > 0 or (supply or 0) > 0 or any((b or 0) > 0 for _, b in (token_bals or []))
    if not has_value:
        return ("EMPTY / PRE-LAUNCH",
                "deployed but no shares/value -> LATENT: the bug has nothing to act on yet. Re-assess IF it gets "
                "funded (the ledgity / gladiator / equivaults-pre-launch lesson). Disclosure = low urgency / courtesy.")
    # value-bearing -> recency decides urgency
    if last_days is None:
        recency = ("UNKNOWN-RECENCY", "value-bearing; last-tx age unknown (no Etherscan key?) -> verify recency by hand")
    elif last_days <= _ACTIVE_D:
        recency = ("LIVE + ACTIVE + FUNDED",
                   "value at risk in ACTIVELY-used code (last tx %.1fd ago) -> HIGH urgency, disclose promptly." % last_days)
    elif last_days <= _DORMANT_D:
        recency = ("LIVE-FUNDED but DORMANT",
                   "funds present but last tx %.0fd ago -> real but low-activity; disclose, medium urgency." % last_days)
    else:
        recency = ("FUNDED but ABANDONED",
                   "funds present yet last tx %.0fd ago (>%dd) -> likely abandoned; funds may be stranded/unowned. "
                   "Disclose as courtesy; check the team is reachable." % (last_days, _DORMANT_D))
    return recency


def main():
    ap = argparse.ArgumentParser(description="Post-finding contract/protocol THREAT assessment (LIVE-FIRST)")
    ap.add_argument("address")
    ap.add_argument("--chain", default="1", help="chain id or name (eth/base/arb/op/bsc/polygon)")
    ap.add_argument("--token", default=None, help="ERC20(s) to check the contract's balance of, comma-separated")
    ap.add_argument("--count", default=None, help="a no-arg count view for a FACTORY (e.g. allVaultsLength())")
    ap.add_argument("--rpc", default=None)
    args = ap.parse_args()

    chain = act.resolve_chain(args.chain)
    addr = args.address
    tokens = [t.strip() for t in args.token.split(",")] if args.token else [None]

    # reuse activity.probe (code/eth/supply/txcount/counter), then add any extra token balances
    code_len, events, xfer, eth_wei, token_bal, supply, decimals, txcount, counter_val = act.probe(
        addr, chain, 5000, rpc=args.rpc, token=tokens[0], counter=args.count)
    token_bals = []
    for t in tokens:
        if not t:
            continue
        b = token_bal if t == tokens[0] else _erc20_balance(addr, t, chain, args.rpc)
        token_bals.append((t, b))

    last_days = last_activity_days(addr, chain)
    dep_days = deploy_age_days(addr, chain)
    has_code = code_len > 0

    level, urgency = assess(has_code, supply, eth_wei, token_bals, txcount, last_days)

    print("== THREAT ASSESSMENT: %s  (chain %s) ==" % (addr, chain))
    print("  deployed:      %s%s" % (
        ("yes (code %dB)" % code_len) if has_code else "NO CODE (decoy/EOA/self-destructed)",
        ("  |  first-seen ~%.0fd ago" % dep_days) if dep_days is not None else ""))
    act_str = ("ACTIVE" if (last_days is not None and last_days <= _ACTIVE_D) else
               "DORMANT" if (last_days is not None and last_days <= _DORMANT_D) else
               "ABANDONED?" if last_days is not None else "unknown")
    print("  activity:      %s  (%s recent txns%s)" % (
        act_str, txcount if txcount is not None else "?",
        (", last tx %.1fd ago" % last_days) if last_days is not None else ""))
    val = ["eth %.4f" % (eth_wei / 1e18)]
    if supply is not None:
        val.append("totalSupply %s" % (("%.2f" % (supply / (10 ** (decimals or 0)))) if decimals else str(supply)))
    for t, b in token_bals:
        val.append("token %s: %s" % (t[:10], "%.4f" % (b / 1e18) if b else "0"))
    print("  value-bearing: %s" % " | ".join(val))
    if args.count:
        print("  scope:         %s = %s  (blast radius: N instances -> sample their funding)" % (args.count, counter_val))
    print("  " + "-" * 60)
    print("  THREAT: %s" % level)
    print("          -> %s" % urgency)
    print("  (coarse: confirm the exact bug-PATH is reachable/used; on a factory, a small funded sample can still "
          "grow -- exposure tracks future deposits.)")


def _erc20_balance(addr, token, chain, rpc):
    rpc = rpc or fs.DEFAULT_RPC.get(str(chain))
    data = act.BAL_OF + "000000000000000000000000" + addr[2:].lower()
    raw = fs._rpc(rpc, "eth_call", [{"to": token, "data": data}, "latest"])
    return act._to_int(raw) if raw else 0


if __name__ == "__main__":
    main()
