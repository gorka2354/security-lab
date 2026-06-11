#!/usr/bin/env python3
"""activity.py - LIVE-FIRST Phase-0/1 gate: is this DEPLOYED contract ACTIVE + does VALUE flow?

The heavy-helms lesson: a bug in deployed-but-DORMANT code is EV ~0. Its GauntletGame read
nextGauntletId==0 (the vulnerable reveal path NEVER executed), queueForGauntlet is free, and the
contract holds no funds -> nothing to grind, nothing to steal. Check activity BEFORE the deep read,
not after. Green (ACTIVE/value) -> dig; red (DORMANT) -> park (watch.py) or skip.

    python activity.py <addr>[,<addr>...] --chain <id|name> [--blocks N] [--token <erc20>] [--counter "sig()"|0xSELECTOR]

Keyless (public RPC, stdlib + optional web3 for selectors): per address it reports
  code?  -> recent events (eth_getLogs over the last N blocks)  -> ETH held (+ optional ERC20 balance)
  -> optional path-counter (e.g. nextGauntletId() == 0 means that path has never run).
Reuses fetch_source._rpc / DEFAULT_RPC. A COARSE contract-liveness gate, not a per-function oracle:
contract-level activity (people touched it) != your bug-path being exercised -- use --counter for that.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fetch_source as fs  # reuse _rpc / DEFAULT_RPC  # noqa: E402

CHAIN_ALIAS = {"eth": "1", "ethereum": "1", "mainnet": "1", "base": "8453", "arb": "42161",
               "arbitrum": "42161", "op": "10", "optimism": "10", "linea": "59144",
               "polygon": "137", "matic": "137", "bsc": "56"}

BAL_OF = "0x70a08231"  # balanceOf(address)


def resolve_chain(c):
    """Map a chain alias/name to its id string (passes ids through)."""
    return CHAIN_ALIAS.get(str(c).lower(), str(c))


def classify(code_len, events, balance_wei, token_bal=None):
    """PURE: map probe results -> (verdict, recommendation, note). events<0 = query failed."""
    if code_len == 0:
        return ("NO-CODE", "SKIP", "no bytecode (not deployed / EOA / wrong chain)")
    if events < 0:
        return ("UNKNOWN", "RETRY", "event query failed (RPC log-range limit) -> lower --blocks and retry")
    has_value = balance_wei > 0 or (token_bal or 0) > 0
    if events > 0:
        return ("ACTIVE", "DIG", f"{events} event(s) in window" + (" + holds value" if has_value else ""))
    if has_value:
        return ("QUIET-VALUE", "DIG-CAREFUL", "no recent events BUT holds value -> widen window / see who funds it")
    return ("DORMANT", "PARK/SKIP", "no recent events + 0 ETH/token -> likely unused (EV ~0)")


def _to_int(h):
    try:
        return int(h, 16)
    except Exception:
        return 0


def _selector(sig):
    """4-byte selector from a 'name(types)' signature (or pass through a 0x........ literal)."""
    s = sig.strip()
    if s.startswith("0x") and len(s) == 10:
        return s
    try:
        from web3 import Web3
        h = Web3.keccak(text=s)[:4].hex()
        return h if h.startswith("0x") else "0x" + h  # web3 v6 .hex() drops the 0x prefix
    except Exception:
        raise SystemExit(f"[!] cannot hash '{sig}' (web3 not available) -> pass the 4-byte 0xSELECTOR instead")


def probe(addr, chain, blocks, rpc=None, token=None, counter=None):
    """Returns (code_len, events, balance_wei, token_bal, counter_val). I/O. events<0 on log-range failure."""
    rpc = rpc or fs.DEFAULT_RPC.get(str(chain))
    code = fs._rpc(rpc, "eth_getCode", [addr, "latest"]) or "0x"
    code_len = max(0, len(code) // 2 - 1)
    bal = _to_int(fs._rpc(rpc, "eth_getBalance", [addr, "latest"]) or "0x0")

    latest = _to_int(fs._rpc(rpc, "eth_blockNumber", []) or "0x0")
    events = -1
    for span in (blocks, blocks // 5, blocks // 25):  # shrink-retry around RPC log-range caps
        if span < 1:
            continue
        try:
            logs = fs._rpc(rpc, "eth_getLogs",
                           [{"address": addr, "fromBlock": hex(max(0, latest - span)), "toBlock": "latest"}])
            events = len(logs or [])
            break
        except Exception:
            continue

    tok = None
    if token:
        data = BAL_OF + addr.lower().replace("0x", "").rjust(64, "0")
        tok = _to_int(fs._rpc(rpc, "eth_call", [{"to": token, "data": data}, "latest"]) or "0x0")

    cval = None
    if counter:
        try:
            cval = _to_int(fs._rpc(rpc, "eth_call", [{"to": addr, "data": _selector(counter)}, "latest"]) or "0x0")
        except SystemExit:
            raise
        except Exception:
            cval = None
    return code_len, events, bal, tok, cval


def main():
    ap = argparse.ArgumentParser(description="LIVE-FIRST activity gate (is deployed code ACTIVE + value-bearing?)")
    ap.add_argument("addresses", help="contract address(es), comma-separated")
    ap.add_argument("--chain", default="1", help="chain id or name (eth/base/arb/op/linea/polygon)")
    ap.add_argument("--blocks", type=int, default=5000, help="event lookback window (blocks; shrink-retried)")
    ap.add_argument("--token", help="optional ERC20 to also report the contract's balance of (value proxy)")
    ap.add_argument("--counter", help="optional no-arg view to read a path counter, e.g. \"nextGauntletId()\" or 0xSELECTOR")
    ap.add_argument("--rpc", help="override RPC url")
    args = ap.parse_args()

    chain = resolve_chain(args.chain)
    rpc = args.rpc or fs.DEFAULT_RPC.get(chain)
    if not rpc:
        print(f"[!] no RPC for chain {args.chain} (have: {', '.join(sorted(fs.DEFAULT_RPC))} + names) -> pass --rpc")
        return 1

    addrs = [a.strip() for a in args.addresses.split(",") if a.strip()]
    print(f"# activity gate  chain={chain}  window={args.blocks} blocks\n")
    digs = 0
    for addr in addrs:
        try:
            code_len, events, bal, tok, cval = probe(addr, chain, args.blocks, rpc, args.token, args.counter)
        except SystemExit:
            raise
        except Exception as e:
            print(f"[ERROR     ] {addr}  -- {str(e)[:60]}")
            continue
        verdict, rec, note = classify(code_len, events, bal, tok)
        if rec in ("DIG", "DIG-CAREFUL"):
            digs += 1
        ev = "?" if events < 0 else events
        extra = ""
        if tok is not None:
            extra += f" token={tok / 1e18:.4f}"
        if cval is not None:
            extra += f" counter={cval}" + ("  <- path NEVER run (==0)" if cval == 0 else "")
        print(f"[{verdict:11}] {addr}  ({rec})")
        print(f"             code={code_len}B  events(last {args.blocks})={ev}  eth={bal / 1e18:.4f}{extra}")
        print(f"             {note}")
    print(f"\n-> {digs}/{len(addrs)} worth a deep dive. DORMANT/NO-CODE -> park (watch.py) or skip, don't deep-read.")
    print("   NOTE: ETH-only value is a weak proxy (most TVL is ERC20 -> pass --token); events = contract-level,")
    print("   not your exact bug-path (use --counter for that, e.g. nextGauntletId()==0 => path never executed).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
