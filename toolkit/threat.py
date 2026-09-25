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
Read-only (eth_call / explorer txlist+tokentx via explorer.py). A COARSE liveness+value oracle, not a
per-function one -- still confirm the exact bug-path is reachable/used.

Never a silent EMPTY: when held ERC20s can't be enumerated (Etherscan's free tier refuses Base/BSC/OP; X Layer
has no Etherscan) the verdict is "NO VALUE SEEN (INCOMPLETE SCAN)" with the reason, and --token is the way out.

Usage:
  python toolkit/threat.py <addr> --chain <id> [--token 0x..[,0x..]] [--count "allVaultsLength()"]
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import activity as act  # noqa: E402  (reuse probe / classify helpers)
import explorer as ex  # noqa: E402  (txlist / tokentx: Etherscan-v2 -> a current Blockscout; a miss says why)
import fetch_source as fs  # noqa: E402

# abandonment thresholds (days since last on-chain tx)
_ACTIVE_D = 30      # <= 30d since last tx -> actively used
_DORMANT_D = 180    # 30..180d -> dormant; > 180d -> abandoned


def _txlist_one(addr, chain, sort):
    """The most-recent (sort='desc') or first (sort='asc') tx of `addr` -> (tx | None, source, why).
    `why` explains a None: the explorers' own refusal, or 'no transactions on record'. No startblock/endblock:
    Etherscan ignores endblock=99999999 but Blockscout applies it literally, hiding every tx past block 1e8 (OP).
    desc asks for the same 20-row page as activity.etherscan_txcount -> one explorer call serves both."""
    rows, src, why = ex.query(chain, {"module": "account", "action": "txlist", "address": addr,
                                      "page": 1, "offset": 20 if sort == "desc" else 1, "sort": sort})
    if rows is None:
        return None, None, why
    return (rows[0], src, None) if rows else (None, src, "no transactions on record")


def _age_days(tx, now=None):
    ts = ex.row_ts(tx)
    return ((now or time.time()) - ts) / 86400.0 if ts else None


def token_transfers(addr, chain):
    """The address's last 100 ERC20 transfers (explorer tokentx) -> (rows | None, source, why)."""
    return ex.query(chain, {"module": "account", "action": "tokentx", "address": addr,
                            "page": 1, "offset": 100, "sort": "desc"})


def real_flow(rows, addr):
    """Tokens with REAL flow through `addr`: it sent them, or >= 2 senders funded it -- and the symbol isn't
    spam-shaped. PURE. A one-sender inbound-only token (airdrop spam, or a lone deposit) is not flow."""
    return {t for t, sym, _d, sent, senders in ex.tokens_moved(rows, addr, limit=10 ** 6)
            if (sent or senders >= 2) and not spam_shaped(sym)}


def last_flow_days(rows, addr, now=None):
    """Days since the newest transfer of a real-flow token; None if none. PURE."""
    real = real_flow(rows, addr)
    ts = [ex.row_ts(r) for r in rows or [] if (r.get("contractAddress") or "").lower() in real]
    ts = [t for t in ts if t]
    return ((now or time.time()) - max(ts)) / 86400.0 if ts else None


def last_activity(addr, chain):
    """(days since the last on-chain activity | None, source, why-unknown) -- the abandonment signal. Activity = the
    newer of the last normal tx and the last real-flow token transfer: an internal-only contract (driven by a
    router/market, never called by an EOA) has no recent normal txs -- Levr's $1.9M USDC vault read 'ABANDONED
    232d' on txlist alone while its USDC kept moving."""
    tx, src, why = _txlist_one(addr, chain, "desc")
    days = _age_days(tx) if tx else None
    rows, tsrc, _twhy = token_transfers(addr, chain)
    flow = last_flow_days(rows, addr) if rows else None
    if flow is not None and (days is None or flow < days):
        return flow, "%s token transfers" % tsrc, None
    return days, src, why


def last_activity_days(addr, chain):
    """Days since the LAST on-chain tx; None if unknown (watch.py's contract)."""
    return last_activity(addr, chain)[0]


def deploy_age_days(addr, chain):
    """Days since the FIRST tx touching the address (rough deploy/first-use age). None if unknown."""
    tx, _src, _why = _txlist_one(addr, chain, "asc")
    return _age_days(tx) if tx else None


# Major value-bearing ERC20s per chain id -> auto-checked when the caller doesn't pass --token, so a contract
# holding ERC20 collateral (not native ETH, and with no share token of its own) is NOT mis-read as EMPTY/
# PRE-LAUNCH. Recurring false-negative caught by the fresh-hunt wave (Enhanced/PAXG, Curve LlamaLend, most
# DeFi vaults hold ERC20 value, not ETH). A non-zero balance in ANY of these => value-bearing. Checked by RPC,
# so it works on chains no explorer serves; everything else comes from discover_holdings().
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


def fmt_units(raw, decimals):
    """Raw ERC20 integer -> human units via the token's decimals. PURE. The old hard-coded /1e18 printed a 6-dec
    USDC balance as 0.0000 -- a false EMPTY to the eye. None -> 'unknown'; unknown decimals -> the raw integer."""
    if raw is None:
        return "unknown"
    if decimals is None:
        return "%d raw" % raw
    n = raw / (10 ** decimals)
    s = ("%.2f" % n) if n >= 1000 else ("%.6f" % n).rstrip("0").rstrip(".")
    return "<0.000001" if (raw and s == "0") else s


def token_meta(token, rpc, call=None):
    """(decimals, symbol) of an ERC20 via eth_call; either is None when the token doesn't say. Best-effort."""
    call = call or fs._rpc
    dec = sym = None
    try:
        r = call(rpc, "eth_call", [{"to": token, "data": act.DECIMALS}, "latest"])
        if r and r != "0x":
            dec = int(r, 16)
            dec = dec if 0 <= dec <= 36 else None   # not a decimals() answer -> print raw, don't mis-scale
    except Exception:
        pass
    try:
        r = call(rpc, "eth_call", [{"to": token, "data": "0x95d89b41"}, "latest"])  # symbol()
        if r and len(r) > 2:
            h = r[2:]
            if len(h) >= 128:  # dynamic string: offset(32) + length(32) + data
                ln = int(h[64:128], 16)
                sym = bytes.fromhex(h[128:128 + ln * 2]).decode("utf-8", "ignore").strip("\x00�").strip()
            if not sym:  # bytes32 fallback (older tokens)
                sym = bytes.fromhex(h[:64]).decode("utf-8", "ignore").strip("\x00�").strip()
    except Exception:
        pass
    return dec, (sym or None)


def _erc20_balance(addr, token, chain, rpc):
    """balanceOf(addr) on `token` -> int, or None when the RPC gave no answer (unknown, NOT 0)."""
    rpc = rpc or fs.DEFAULT_RPC.get(str(chain))
    data = act.BAL_OF + "000000000000000000000000" + addr[2:].lower()
    raw = fs._rpc(rpc, "eth_call", [{"to": token, "data": data}, "latest"])
    return None if raw is None else act._to_int(raw)


_SPAM_SYM = re.compile(r"https?|www|t\.me|\.[a-z]{2,}|claim|visit|airdrop|reward", re.I)


def spam_shaped(symbol):
    """A token symbol that advertises (URL / 'claim' / 'visit' / emoji) = the airdrop-spam shape. PURE. Spam tokens
    also forge Transfer events FROM popular contracts, so 'the address sent it' alone can't vouch for them."""
    s = symbol or ""
    return bool(_SPAM_SYM.search(s)) or not s.isascii()


def _ascii(s):
    return (s or "").encode("ascii", "replace").decode("ascii")


def discover_holdings(addr, chain, rpc, rows, why=None):
    """Every ERC20 in the address's recent transfers (token_transfers() rows) -> its CURRENT balance by RPC.
    -> (held, gap). held = [(symbol, token, raw, decimals, counts)] with raw > 0; counts = the token has real flow
    (real_flow()), else it is printed but not counted -- spam must not turn a dead contract FUNDED.
    gap = None when the scan ran to the end, else why it could not (rows None -> the explorers' refusal)."""
    if rows is None:
        return [], "held ERC20s not enumerable (%s)" % (why or "no explorer answer")
    real, held, failed = real_flow(rows, addr), [], []
    for token, sym, dec, _sent, _senders in ex.tokens_moved(rows, addr):
        try:
            raw = _erc20_balance(addr, token, chain, rpc)
        except Exception:
            raw = None
        if raw is None:
            failed.append(_ascii(sym) or token[:10])
        elif raw > 0:
            held.append((_ascii(sym) or token[:10], token, raw,
                         dec if dec is not None else token_meta(token, rpc)[0], token in real))
    return held, ("balanceOf unanswered for %s" % ", ".join(failed)) if failed else None


def assess(has_code, supply, eth_wei, token_bals, txcount, last_days, holds_erc20=False, scan_gap=None,
           recency_why=None):
    """-> (threat_level, urgency). Combines liveness + value + recency into a disclosure-relevant verdict.
    Filters the not-live findings (a bug matters only in deployed + active + value-bearing code).
    token_bals = [(token, raw | None)]; None = the balance read failed. scan_gap = why held ERC20s could not be
    fully enumerated -- then no value seen is NOT proof of EMPTY (the ea-finance BSC false-EMPTY)."""
    if not has_code:
        return "DEAD / EOA", "no contract at this address (decoy? self-destructed?) -> not a live target."
    has_value = ((eth_wei or 0) > 0 or (supply or 0) > 0
                 or any((b or 0) > 0 for _, b in (token_bals or [])) or holds_erc20)
    if not has_value:
        unread = [t[:10] for t, b in (token_bals or []) if b is None]
        gap = "; ".join(filter(None, [scan_gap, ("balance unread for " + ", ".join(unread)) if unread else None]))
        if gap:
            return ("NO VALUE SEEN (INCOMPLETE SCAN)",
                    "native + checked-token balances are 0, but %s -> NOT proven empty: pass --token <the protocol's "
                    "asset> (or read the explorer) before calling it EMPTY." % gap)
        return ("EMPTY / PRE-LAUNCH",
                "deployed but no shares/value -> LATENT: the bug has nothing to act on yet. Re-assess IF it gets "
                "funded (the ledgity / gladiator / equivaults-pre-launch lesson). Disclosure = low urgency / courtesy.")
    # value-bearing -> recency decides urgency
    if last_days is None:
        recency = ("UNKNOWN-RECENCY", "value-bearing; last-tx age unknown (%s) -> verify recency by hand"
                   % (recency_why or "no explorer answer"))
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
    ap.add_argument("--chain", default="1", help="chain id or name (eth/base/arb/op/bsc/polygon/xlayer/...)")
    ap.add_argument("--token", default=None, help="ERC20(s) to check the contract's balance of, comma-separated")
    ap.add_argument("--count", default=None, help="a no-arg count view for a FACTORY (e.g. allVaultsLength())")
    ap.add_argument("--rpc", default=None)
    args = ap.parse_args()

    chain = act.resolve_chain(args.chain)
    addr = args.address
    rpc = args.rpc or fs.DEFAULT_RPC.get(str(chain))
    tokens = [t.strip() for t in args.token.split(",")] if args.token else [None]

    # reuse activity.probe (code/eth/supply/txcount/counter), then add any extra token balances
    code_len, events, xfer, eth_wei, token_bal, supply, decimals, txcount, counter_val = act.probe(
        addr, chain, 5000, rpc=args.rpc, token=tokens[0], counter=args.count)
    token_bals = []
    for t in tokens:
        if not t:
            continue
        try:
            b = token_bal if t == tokens[0] else _erc20_balance(addr, t, chain, rpc)
        except Exception:
            b = None
        token_bals.append((t, b))

    # no --token: major tokens by RPC (any chain) + every ERC20 the address moved (explorer) -> no false EMPTY on a
    # vault holding ERC20 collateral; a scan that could not run is reported, never read as "holds nothing".
    held, spam, scan_gap, scan_note = [], [], None, "explicit --token only"
    if not args.token and code_len > 0:
        cid = int(chain) if str(chain).isdigit() else -1
        failed = []
        for sym, taddr in VALUE_TOKENS.get(cid, []):
            try:
                b = _erc20_balance(addr, taddr, chain, rpc)
            except Exception:
                b = None
            if b is None:
                failed.append(sym)
            elif b > 0:
                held.append((sym, taddr, b, token_meta(taddr, rpc)[0], True))
        rows, _tsrc, twhy = token_transfers(addr, chain)
        found, gap = discover_holdings(addr, chain, rpc, rows, twhy)
        known = {h[1].lower() for h in held}
        for h in found:
            if h[1].lower() not in known:
                (held if h[4] else spam).append(h)
        scan_gap = "; ".join(filter(None, [gap, ("major-token balanceOf unanswered for " + ", ".join(failed))
                                           if failed else None])) or None
        scan_note = ("INCOMPLETE -- " + scan_gap) if scan_gap else \
            "complete (major tokens + every ERC20 moved in the last 100 transfers)"

    last_days, rec_src, rec_why = last_activity(addr, chain)
    dep_days = deploy_age_days(addr, chain)
    has_code = code_len > 0

    level, urgency = assess(has_code, supply, eth_wei, token_bals, txcount, last_days, holds_erc20=bool(held),
                            scan_gap=scan_gap, recency_why=rec_why)

    print("== THREAT ASSESSMENT: %s  (chain %s) ==" % (addr, chain))
    print("  deployed:      %s%s" % (
        ("yes (code %dB)" % code_len) if has_code else "NO CODE (decoy/EOA/self-destructed)",
        ("  |  first-seen ~%.0fd ago" % dep_days) if dep_days is not None else ""))
    act_str = ("ACTIVE" if (last_days is not None and last_days <= _ACTIVE_D) else
               "DORMANT" if (last_days is not None and last_days <= _DORMANT_D) else
               "ABANDONED?" if last_days is not None else "unknown")
    print("  activity:      %s  (%s recent txns%s)" % (
        act_str, txcount if txcount is not None else "?",
        (", last tx %.1fd ago via %s" % (last_days, rec_src)) if last_days is not None else ", " + (rec_why or "?")))
    val = ["eth %.4f" % (eth_wei / 1e18)]
    if supply is not None:
        val.append("totalSupply %s" % (("%.2f" % (supply / (10 ** (decimals or 0)))) if decimals else str(supply)))
    for t, b in token_bals:
        dec, sym = token_meta(t, rpc) if b else (None, None)
        val.append("token %s%s: %s" % (t[:10], (" (%s)" % _ascii(sym)) if sym else "", fmt_units(b, dec) if b else
                                        ("0" if b == 0 else "unknown")))
    print("  value-bearing: %s" % " | ".join(val))
    if held:
        print("  holds ERC20:   %s" % " | ".join("%s %s" % (fmt_units(h[2], h[3]), h[0]) for h in held))
    if spam:
        print("  not counted:   %s  (one sender + never sent out, or a spam-shaped symbol)"
              % " | ".join("%s %s" % (fmt_units(h[2], h[3]), h[0]) for h in spam))
    print("  value scan:    %s" % scan_note)
    if args.count:
        print("  scope:         %s = %s  (blast radius: N instances -> sample their funding)" % (args.count, counter_val))
    print("  " + "-" * 60)
    print("  THREAT: %s" % level)
    print("          -> %s" % urgency)
    print("  (coarse: confirm the exact bug-PATH is reachable/used; on a factory, a small funded sample can still "
          "grow -- exposure tracks future deposits.)")


if __name__ == "__main__":
    main()
