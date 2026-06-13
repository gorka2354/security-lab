#!/usr/bin/env python3
"""activity.py - LIVE-FIRST Phase-0/1 gate: is this DEPLOYED contract ACTIVE + does VALUE flow?

The heavy-helms lesson: a bug in deployed-but-DORMANT code is EV ~0. Its GauntletGame read
nextGauntletId==0 (the vulnerable reveal path NEVER executed), queueForGauntlet is free, and the
contract holds no funds -> nothing to grind, nothing to steal. Check activity BEFORE the deep read,
not after. Green (ACTIVE/value) -> dig; red (DORMANT) -> park (watch.py) or skip.

    python activity.py <addr>[,<addr>...] --chain <id|name> [--blocks N] [--token <erc20>] [--counter "sig()"|0xSELECTOR]

Keyless (public RPC, stdlib + optional web3 for selectors): per address it reports
  code?  -> own totalSupply() (0 = EMPTY: deployed but no positions -> NOT a live finding; the ledgity lesson)
  -> recent events (eth_getLogs over the last N blocks)  -> ETH held (+ optional ERC20 balance)
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
TOTAL_SUPPLY = "0x18160ddd"  # totalSupply() -- the contract's OWN positions/shares (0 = empty -> not live)
ERC20_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"  # Transfer(addr,addr,uint)


def parse_logs(res):
    """(events, transfer_events) from an eth_getLogs result. CRITICAL: a `None` result means the RPC
    REFUSED the query (range too big / unsupported) -> return (-1, 0) = UNKNOWN, NEVER 0. Treating a
    null response as '0 events' is a false-DORMANT bug (caught re-verifying Mantle Index). PURE."""
    if res is None:
        return (-1, 0)
    xfer = sum(1 for L in res if (L.get("topics") or [""])[0].lower() == ERC20_TRANSFER)
    return (len(res), xfer)


def token_hint(events, xfer):
    """If recent activity is ~all ERC20 Transfers, it's likely a TOKEN -- and DefiLlama routinely lists a
    protocol's GOV TOKEN, not its core. Resolve the real contract before digging (the venus-flux/XVS trap). PURE."""
    if events > 0 and xfer >= 0.8 * events:
        return "looks like an ERC20 TOKEN (>=80% Transfer events) -- DefiLlama often lists the gov token, not the core -> resolve the real contract"
    return ""


def resolve_chain(c):
    """Map a chain alias/name to its id string (passes ids through)."""
    return CHAIN_ALIAS.get(str(c).lower(), str(c))


def classify(code_len, events, balance_wei, token_bal=None, supply=None):
    """PURE: map probe results -> (verdict, recommendation, note). events<0 = query failed; supply is the
    contract's OWN totalSupply (None = absent / not an ERC-share contract). Deployment-gate addition: a
    deployed share/balance contract with totalSupply==0 holds NO user positions, so a share/redemption-math
    bug has nothing to act on -- the ledgity WrappedLTokenSonic lesson (deployed, inherited the bug, EMPTY)."""
    if code_len < 0:
        return ("UNKNOWN", "RETRY", "eth_getCode returned null (RPC issue) -> retry / check the RPC, NOT 'no code'")
    if code_len == 0:
        return ("NO-CODE", "SKIP", "no bytecode (not deployed / EOA / wrong chain) -> NOT a live finding")
    if supply == 0:
        return ("EMPTY", "PARK (not live)",
                "deployed but totalSupply==0 -> no shares/positions exist; a share/balance/redemption-math bug "
                "has nothing to act on (re-evaluate IF it gets funded) -- the ledgity lesson")
    if events < 0:
        return ("UNKNOWN", "RETRY", "event query failed (RPC log-range limit) -> lower --blocks and retry")
    has_value = balance_wei > 0 or (token_bal or 0) > 0
    if events > 0:
        return ("ACTIVE", "DIG", f"{events} event(s) in window" + (" + holds value" if has_value else ""))
    if has_value:
        return ("QUIET-VALUE", "DIG-CAREFUL", "no recent events BUT holds value -> widen window / see who funds it")
    return ("DORMANT", "PARK/SKIP",
            "no events in window + 0 ETH/token -> likely unused (widen --blocks for a low-frequency contract,"
            " and confirm getLogs isn't being range-refused, before trusting a DORMANT)")


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
    """Returns (code_len, events, xfer, balance_wei, token_bal, supply, counter_val). I/O. events<0 on
    log-range failure. supply = the contract's own totalSupply() (None if it has none / call reverts)."""
    rpc = rpc or fs.DEFAULT_RPC.get(str(chain))
    # None = RPC returned null (error/unsupported) -> UNKNOWN; "0x" = a real EOA -> 0. Don't conflate them.
    code = fs._rpc(rpc, "eth_getCode", [addr, "latest"])
    code_len = -1 if code is None else max(0, len(code) // 2 - 1)
    braw = fs._rpc(rpc, "eth_getBalance", [addr, "latest"])
    bal = _to_int(braw) if braw is not None else 0

    # the contract's OWN positions: totalSupply()==0 on a deployed share/vault/wrapper = empty -> not live.
    # "0x"/null = no such function (not an ERC-share contract) -> None, leave the verdict to events/value.
    sraw = fs._rpc(rpc, "eth_call", [{"to": addr, "data": TOTAL_SUPPLY}, "latest"])
    supply = _to_int(sraw) if (sraw is not None and sraw != "0x") else None

    bn = fs._rpc(rpc, "eth_blockNumber", [])
    if bn is None:
        raise RuntimeError("eth_blockNumber returned null (RPC down/unsupported) -- cannot gate this address")
    latest = _to_int(bn)
    events, xfer = -1, 0
    for span in (blocks, blocks // 5, blocks // 25):  # shrink-retry around RPC log-range caps
        if span < 1:
            continue
        try:
            res = fs._rpc(rpc, "eth_getLogs",
                          [{"address": addr, "fromBlock": hex(max(0, latest - span)), "toBlock": "latest"}])
        except Exception:
            continue
        ev, xf = parse_logs(res)
        if ev < 0:           # null = RPC refused this range -> try a SMALLER window, don't call it 0
            continue
        events, xfer = ev, xf
        break

    tok = None
    if token:
        data = BAL_OF + addr.lower().replace("0x", "").rjust(64, "0")
        traw = fs._rpc(rpc, "eth_call", [{"to": token, "data": data}, "latest"])
        tok = _to_int(traw) if traw is not None else None  # None -> unknown, NOT 0

    cval = None
    if counter:
        try:
            craw = fs._rpc(rpc, "eth_call", [{"to": addr, "data": _selector(counter)}, "latest"])
            cval = _to_int(craw) if craw is not None else None  # None -> unknown, NOT a false "==0 / never run"
        except SystemExit:
            raise
        except Exception:
            cval = None
    return code_len, events, xfer, bal, tok, supply, cval


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
            code_len, events, xfer, bal, tok, supply, cval = probe(addr, chain, args.blocks, rpc, args.token, args.counter)
        except SystemExit:
            raise
        except Exception as e:
            print(f"[ERROR     ] {addr}  -- {str(e)[:60]}")
            continue
        verdict, rec, note = classify(code_len, events, bal, tok, supply)
        thint = token_hint(events, xfer)
        if rec in ("DIG", "DIG-CAREFUL") and not thint:
            digs += 1
        ev = "?" if events < 0 else events
        extra = ""
        if supply is not None:
            extra += f" totalSupply={supply / 1e18:.4f}"
        if tok is not None:
            extra += f" token={tok / 1e18:.4f}"
        if cval is not None:
            extra += f" counter={cval}" + ("  <- path NEVER run (==0)" if cval == 0 else "")
        print(f"[{verdict:11}] {addr}  ({'RESOLVE-CORE' if thint else rec})")
        print(f"             code={code_len}B  events(last {args.blocks})={ev}  eth={bal / 1e18:.4f}{extra}")
        print(f"             {thint or note}")
    print(f"\n-> {digs}/{len(addrs)} worth a deep dive. NO-CODE/EMPTY/DORMANT -> park (watch.py) or skip, don't deep-read.")
    print("   NOTE: ETH-only value is a weak proxy (most TVL is ERC20 -> pass --token); events = contract-level,")
    print("   not your exact bug-path (use --counter for that, e.g. nextGauntletId()==0 => path never executed).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
