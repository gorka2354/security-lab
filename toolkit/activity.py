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
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fetch_source as fs  # reuse _rpc / DEFAULT_RPC  # noqa: E402
import explorer  # noqa: E402  (txlist port: Etherscan-v2 -> a current Blockscout)
import tlsfix  # noqa: F401,E402  -- current CA bundle on stale-CA Windows hosts (see tlsfix.py)

CHAIN_ALIAS = {"eth": "1", "ethereum": "1", "mainnet": "1", "base": "8453", "arb": "42161",
               "arbitrum": "42161", "op": "10", "optimism": "10", "linea": "59144",
               "polygon": "137", "matic": "137", "bsc": "56", "mantle": "5000",
               "hyperevm": "999", "hyperliquid": "999", "mezo": "31612", "sonic": "146",
               "abstract": "2741", "abs": "2741", "xlayer": "196", "robinhood": "4663", "apechain": "33139",
               "opbnb": "204", "amoy": "80002", "monad": "143", "monad-testnet": "10143", "gnosis": "100",
               "citrea": "4114", "flare": "14", "kaia": "8217"}

BAL_OF = "0x70a08231"  # balanceOf(address)
TOTAL_SUPPLY = "0x18160ddd"  # totalSupply() -- the contract's OWN positions/shares (0 = empty -> not live)
DECIMALS = "0x313ce567"  # decimals() -- so we render supply/token in token units, not hardcoded 1e18
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


def etherscan_txcount(addr, chain, key=None, days=30, now=None):
    """Recent on-chain tx activity from the account txlist (explorer.py: Etherscan-v2, else a current Blockscout)
    -- a liveness signal that does NOT rely on eth_getLogs (which range-limits / quirk-returns a FALSE 0).
    Returns how many of the latest 20 txns fall within `days` (0..20), or None when no explorer answers.
    The death.fun lesson: 0 getLogs events but ~100 txns / 20 min -> txns are authoritative. The age cut matters:
    counting the latest page regardless of age called any contract with a tx history ACTIVE, however long idle."""
    rows, _src, _why = explorer.query(chain, {"module": "account", "action": "txlist", "address": addr,
                                             "page": 1, "offset": 20, "sort": "desc"}, key=key)
    if rows is None:
        return None
    cutoff = (now or time.time()) - days * 86400
    return sum(1 for r in rows if explorer.row_ts(r) >= cutoff)


def classify(code_len, events, balance_wei, token_bal=None, supply=None, txcount=None):
    """PURE: map probe results -> (verdict, recommendation, note). events<0 = query failed; supply is the
    contract's OWN totalSupply (None = absent / not an ERC-share contract); txcount = recent txns from the
    Etherscan-v2 txlist (None if unavailable). Deployment-gate: a deployed share contract with totalSupply==0
    holds NO positions (ledgity EMPTY lesson); recent TXNS are an authoritative liveness signal that overrides
    an event-based false-DORMANT (the death.fun lesson: 0 getLogs events but the contract is busy on-chain)."""
    if code_len < 0:
        return ("UNKNOWN", "RETRY", "eth_getCode returned null (RPC issue) -> retry / check the RPC, NOT 'no code'")
    if code_len == 0:
        return ("NO-CODE", "SKIP", "no bytecode (not deployed / EOA / wrong chain) -> NOT a live finding")
    if supply == 0:
        return ("EMPTY", "PARK (not live)",
                "deployed but totalSupply==0 -> no shares/positions exist; a share/balance/redemption-math bug "
                "has nothing to act on (re-evaluate IF it gets funded) -- the ledgity lesson")
    if (txcount or 0) > 0:
        return ("ACTIVE", "DIG",
                "%d+ recent txns (Etherscan-v2 txlist) -> live, even if getLogs is quiet; events can false-0 on "
                "range limits, txns are authoritative (the death.fun lesson). Verify the BUG-path is among them." % txcount)
    if events < 0:
        return ("UNKNOWN", "RETRY", "event query failed (RPC log-range limit) -> lower --blocks and retry")
    has_value = balance_wei > 0 or (token_bal or 0) > 0
    if events > 0:
        return ("ACTIVE", "DIG", f"{events} event(s) in window" + (" + holds value" if has_value else ""))
    if has_value:
        return ("QUIET-VALUE", "DIG-CAREFUL", "no recent events BUT holds value -> widen window / see who funds it")
    if (supply or 0) > 0:
        return ("QUIET-VALUE", "DIG-CAREFUL",
                "no recent events / 0 ETH-or-token held BUT totalSupply>0 -> outstanding shares/positions exist "
                "(low-frequency, or a funds-forwarded vault like lazy) -> NOT dormant; widen --blocks to see flow")
    return ("DORMANT", "PARK/SKIP",
            "no events in window + 0 ETH/token -> likely unused (widen --blocks for a low-frequency contract,"
            " and confirm getLogs isn't being range-refused, before trusting a DORMANT)")


def _to_int(h):
    try:
        return int(h, 16)
    except Exception:
        return 0


def _keccak256(msg):
    """Pure-stdlib keccak-256 (Ethereum variant; NOT NIST SHA3 - different padding). No web3 dependency,
    so selector hashing works in any env incl. CI. Verified vs keccak256("")=c5d24601.. and transfer()=a9059cbb."""
    RC = [0x1, 0x8082, 0x800000000000808A, 0x8000000080008000, 0x808B, 0x80000001, 0x8000000080008081,
          0x8000000000008009, 0x8A, 0x88, 0x80008009, 0x8000000A, 0x8000808B, 0x800000000000008B,
          0x8000000000008089, 0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x800A,
          0x800000008000000A, 0x8000000080008081, 0x8000000000008080, 0x80000001, 0x8000000080008008]
    R = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
    M = 0xFFFFFFFFFFFFFFFF

    def rol(x, n):
        n %= 64
        return ((x << n) | (x >> (64 - n))) & M

    A = [[0] * 5 for _ in range(5)]
    rate = 136
    m = bytearray(msg)
    m.append(0x01)
    while len(m) % rate:
        m.append(0)
    m[-1] ^= 0x80
    for off in range(0, len(m), rate):
        blk = m[off:off + rate]
        for i in range(rate // 8):
            A[i % 5][i // 5] ^= int.from_bytes(blk[i * 8:i * 8 + 8], "little")
        for rnd in range(24):
            C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
            D = [C[(x - 1) % 5] ^ rol(C[(x + 1) % 5], 1) for x in range(5)]
            for x in range(5):
                for y in range(5):
                    A[x][y] ^= D[x]
            B = [[0] * 5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    B[y][(2 * x + 3 * y) % 5] = rol(A[x][y], R[x][y])
            for x in range(5):
                for y in range(5):
                    A[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y])
            A[0][0] ^= RC[rnd]
    out = bytearray()
    for i in range(4):
        out += A[i % 5][i // 5].to_bytes(8, "little")
    return bytes(out[:32])


def _selector(sig):
    """4-byte selector from a 'name(types)' signature (or pass through a 0x........ literal). Pure-stdlib."""
    s = sig.strip()
    if s.startswith("0x") and len(s) == 10:
        return s
    return "0x" + _keccak256(s.encode()).hex()[:8]


def probe(addr, chain, blocks, rpc=None, token=None, counter=None):
    """Returns (code_len, events, xfer, balance_wei, token_bal, supply, decimals, counter_val). I/O.
    events<0 on log-range failure. supply = the contract's own totalSupply() (None if absent/reverts);
    decimals = its decimals() (default 18) so we render supply in token units, not hardcoded 1e18."""
    rpc = rpc or fs.DEFAULT_RPC.get(str(chain))
    if not rpc:
        # urllib would raise ValueError("unknown url type: None") three frames deep; say what to do instead
        raise SystemExit("[activity] no RPC configured for chain %s -- pass --rpc <url> "
                         "(or add it to fetch_source.DEFAULT_RPC)" % chain)
    # None = RPC returned null (error/unsupported) -> UNKNOWN; "0x" = a real EOA -> 0. Don't conflate them.
    code = fs._rpc(rpc, "eth_getCode", [addr, "latest"])
    code_len = -1 if code is None else max(0, len(code) // 2 - 1)
    braw = fs._rpc(rpc, "eth_getBalance", [addr, "latest"])
    bal = _to_int(braw) if braw is not None else 0

    # the contract's OWN positions: totalSupply()==0 on a deployed share/vault/wrapper = empty -> not live.
    # "0x"/null = no such function (not an ERC-share contract) -> None, leave the verdict to events/value.
    sraw = fs._rpc(rpc, "eth_call", [{"to": addr, "data": TOTAL_SUPPLY}, "latest"])
    supply = _to_int(sraw) if (sraw is not None and sraw != "0x") else None
    # decimals() so the printout shows real token units (eva is 6-dec -> /1e18 mis-rendered $2.7M as 0.0000)
    draw = fs._rpc(rpc, "eth_call", [{"to": addr, "data": DECIMALS}, "latest"])
    dec = _to_int(draw) if (draw is not None and draw != "0x") else 18
    if not (0 < dec <= 36):
        dec = 18

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
    txc = etherscan_txcount(addr, chain)  # authoritative liveness (txns) when getLogs false-0s
    return code_len, events, xfer, bal, tok, supply, dec, txc, cval


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
            code_len, events, xfer, bal, tok, supply, dec, txc, cval = probe(addr, chain, args.blocks, rpc, args.token, args.counter)
        except SystemExit:
            raise
        except Exception as e:
            print(f"[ERROR     ] {addr}  -- {str(e)[:60]}")
            continue
        verdict, rec, note = classify(code_len, events, bal, tok, supply, txc)
        thint = token_hint(events, xfer)
        if rec in ("DIG", "DIG-CAREFUL") and not thint:
            digs += 1
        ev = "?" if events < 0 else events
        unit = 10 ** dec
        extra = ""
        if supply is not None:
            extra += f" totalSupply={supply / unit:,.2f}({dec}dec)"
        if tok is not None:
            extra += f" token={tok / unit:.4f}"
        if txc is not None:
            extra += f" txns(recent)={txc}"
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
