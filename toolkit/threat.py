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


# Major value-bearing ERC20s per chain id -> auto-checked when the caller doesn't pass --token, so a contract
# holding ERC20 collateral (not native ETH, and with no share token of its own) is NOT mis-read as EMPTY/
# PRE-LAUNCH. Recurring false-negative caught by the fresh-hunt wave (Enhanced/PAXG, Curve LlamaLend, most
# DeFi vaults hold ERC20 value, not ETH). A non-zero balance in ANY of these => value-bearing.
VALUE_TOKENS = {
    1: [("USDC", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"), ("USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7"),
        ("DAI", "0x6B175474E89094C44Da98b954EedeAC495271d0F"), ("WETH", "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"),
        ("WBTC", "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599"), ("PAXG", "0x45804880De22913dAFE09f4980848ECE6EcbAf78"),
        ("wstETH", "0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0")],
    10: [("USDC", "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85"), ("USDT", "0x94b008aA00579c1307B0EF2c499aD98a8ce58e58"),
         ("WETH", "0x4200000000000000000000000000000000000006"), ("wstETH", "0x1F32b1c2345538c0c6f582fCB022739c4A194Ebb")],
    8453: [("USDC", "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"), ("WETH", "0x4200000000000000000000000000000000000006")],
    42161: [("USDC", "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"), ("WETH", "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1"),
            ("WBTC", "0x2f2a2543B76A4166549F7aaB2e75Bef0aefC5B0f")],
    56: [("USDT", "0x55d398326f99059fF775485246999027B3197955"), ("USDC", "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d"),
         ("WBNB", "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c")],
    137: [("USDC", "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359"), ("USDT", "0xc2132D05D31c914a87C6611C10748AEb04B58e8F"),
          ("WETH", "0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619")],
}


def assess(has_code, supply, eth_wei, token_bals, txcount, last_days, holds_erc20=False):
    """-> (threat_level, urgency). Combines liveness + value + recency into a disclosure-relevant verdict.
    Filters the not-live findings (a bug matters only in deployed + active + value-bearing code)."""
    if not has_code:
        return "DEAD / EOA", "no contract at this address (decoy? self-destructed?) -> not a live target."
    has_value = ((eth_wei or 0) > 0 or (supply or 0) > 0
                 or any((b or 0) > 0 for _, b in (token_bals or [])) or holds_erc20)
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

    # auto-detect ERC20 value via major-token balances when --token was not given -> no false EMPTY on a
    # collateral vault that holds ERC20s (not native ETH) and has no share token of its own.
    held_syms = []
    if not args.token and code_len > 0:
        _cid = int(chain) if str(chain).isdigit() else -1
        for sym, taddr in VALUE_TOKENS.get(_cid, []):
            try:
                b = _erc20_balance(addr, taddr, chain, args.rpc)
            except Exception:
                b = 0
            if b and b > 0:
                held_syms.append(sym)

    last_days = last_activity_days(addr, chain)
    dep_days = deploy_age_days(addr, chain)
    has_code = code_len > 0

    level, urgency = assess(has_code, supply, eth_wei, token_bals, txcount, last_days, holds_erc20=bool(held_syms))

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
    if held_syms:
        val.append("holds major ERC20: " + ", ".join(held_syms))
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
