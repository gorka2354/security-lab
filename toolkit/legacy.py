#!/usr/bin/env python3
"""legacy.py - the DEPRECATED-FUNDED sourcing lane: find OLD contracts that still hold value.

The Thetanuts lesson (2026-06, ~$2.1M): a vault the protocol "deprecated years ago, no relation to current
products" was still on-chain, still funded, still callable -> drained. DefiLlama de-lists dead protocols and
bug-bounties don't cover them, so scout/contest_monitor STRUCTURALLY miss this class. legacy.py is the inverse
of activity.py: activity PARKS dormant code (EV~0); legacy SEEKS dormant code that is STILL FUNDED (EV high --
forgotten, un-monitored, classic bug shapes like det_vault_share_math / det_erc4626).

    python toolkit/legacy.py check <addr>[,<addr>...] --chain <id|name>     # classify candidates
    python toolkit/legacy.py from-deployer <deployerAddr> --chain <id|name> # enumerate a deployer's contracts (needs ETHERSCAN_API_KEY)

Keyless `check` works on any public RPC (code+ETH+token+totalSupply+recent events). An ETHERSCAN_API_KEY
sharpens the dormancy signal (recent txns, authoritative) and enables `from-deployer` discovery. Discovery
only; verify value-at-stake + responsible disclosure by hand. ASCII output.
"""
import argparse
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import activity  # reuse probe / classify helpers / CHAIN_ALIAS  # noqa: E402
import fetch_source as fs  # noqa: E402


def classify_legacy(code_len, events, balance_wei, token_bal=None, supply=None, txcount=None):
    """PURE inverse of activity.classify: the target class is DEPRECATED (no recent activity) yet still
    FUNDED (residual ETH/token, or outstanding shares = backing). events<0 = the log query failed; txcount =
    recent Etherscan txns (None if no key -> dormancy rests on events alone, weaker). Returns (verdict, rec, note)."""
    if code_len < 0:
        return ("UNKNOWN", "RETRY", "eth_getCode returned null (RPC issue) -> retry, NOT 'no code'")
    if code_len == 0:
        return ("NO-CODE", "SKIP", "no bytecode (EOA / not deployed / wrong chain)")
    has_value = balance_wei > 0 or (token_bal or 0) > 0 or (supply or 0) > 0
    active = (txcount or 0) > 0 or (events or 0) > 0
    if not has_value:
        return ("EMPTY", "SKIP",
                "deployed but 0 ETH / 0 token / totalSupply==0 -> nothing at stake (drained or never funded)")
    if active:
        return ("ACTIVE-FUNDED", "normal-hunt",
                "holds value AND has recent activity -> a LIVE target, not the legacy class; hunt via the normal lane")
    return ("LEGACY-FUNDED", "READ IT",
            "residual value + NO recent activity -> a DEPRECATED-but-funded contract (Thetanuts class): forgotten, "
            "un-monitored, classic bug shapes. fetch_source -> recon (det_vault_share_math/det_erc4626) -> confirm value at stake.")


def deployer_contracts(deployer, chain, key=None, cap=200):
    """Contract addresses CREATED by `deployer` (Etherscan-v2 txlist: creation txns have empty `to` +
    a `contractAddress`). Needs a key. Returns a list (possibly empty) or None when unavailable."""
    key = key or os.environ.get("ETHERSCAN_API_KEY")
    if not key:
        return None
    url = ("https://api.etherscan.io/v2/api?chainid=%s&module=account&action=txlist&address=%s"
           "&startblock=0&endblock=99999999&page=1&offset=%d&sort=asc&apikey=%s" % (chain, deployer, cap, key))
    try:
        d = json.load(urllib.request.urlopen(
            urllib.request.Request(url, headers={"User-Agent": "security-lab"}), timeout=30))
    except Exception:
        return None
    rows = d.get("result")
    if not isinstance(rows, list):
        return None
    seen, out = set(), []
    for tx in rows:
        ca = (tx.get("contractAddress") or "").strip()
        if (not (tx.get("to") or "").strip()) and ca and ca.lower() not in seen:
            seen.add(ca.lower())
            out.append(ca)
    return out


def is_7702(code_raw):
    """An EIP-7702 delegated EOA carries exactly 23 bytes of code: 0xef0100 + a 20-byte address. It is a
    WALLET, not a deployed contract -> never a legacy-contract target (caught on the first live run: a
    7702 EOA with ETH + no events mis-read as LEGACY-FUNDED). PURE."""
    c = (code_raw or "").lower()
    return c.startswith("0xef0100") and len(c) == 2 + 23 * 2


def assess(addr, chain, blocks, rpc):
    """Probe one address (reusing activity.probe) and apply the legacy classifier. Returns a dict row."""
    code_raw = fs._rpc(rpc, "eth_getCode", [addr, "latest"])
    if is_7702(code_raw):
        return {"addr": addr, "verdict": "EOA-7702", "rec": "SKIP", "code": 23, "events": 0,
                "eth": 0.0, "supply": None, "dec": 18, "txc": None,
                "note": "EIP-7702 delegated EOA (0xef0100 prefix) -> a wallet, not a deployed contract"}
    code_len, events, xfer, bal, tok, supply, dec, txc, _cval = activity.probe(addr, chain, blocks, rpc, None, None)
    verdict, rec, note = classify_legacy(code_len, events, bal, tok, supply, txc)
    return {"addr": addr, "verdict": verdict, "rec": rec, "note": note, "code": code_len,
            "events": events, "eth": bal / 1e18, "supply": supply, "dec": dec, "txc": txc}


def _print_row(r):
    ev = "?" if r["events"] < 0 else r["events"]
    extra = ""
    if r["supply"] is not None:
        extra += f" totalSupply={r['supply'] / 10 ** r['dec']:,.2f}"
    if r["txc"] is not None:
        extra += f" txns(recent)={r['txc']}"
    print(f"[{r['verdict']:13}] {r['addr']}  ({r['rec']})")
    print(f"               code={r['code']}B  events={ev}  eth={r['eth']:.4f}{extra}")
    print(f"               {r['note']}")


def main():
    ap = argparse.ArgumentParser(description="Deprecated-but-funded sourcing lane (the Thetanuts class)")
    ap.add_argument("mode", choices=["check", "from-deployer"], help="check addresses, or enumerate a deployer's contracts")
    ap.add_argument("target", help="address(es) (comma-sep) for `check`, or a deployer address for `from-deployer`")
    ap.add_argument("--chain", default="1", help="chain id or name (eth/base/arb/op/linea/polygon/...)")
    ap.add_argument("--blocks", type=int, default=20000, help="event lookback window (wider than activity: legacy = low-frequency)")
    ap.add_argument("--rpc", help="override RPC url")
    args = ap.parse_args()

    chain = activity.resolve_chain(args.chain)
    rpc = args.rpc or fs.DEFAULT_RPC.get(chain)
    if not rpc:
        print(f"[!] no RPC for chain {args.chain} -> pass --rpc")
        return 1

    if args.mode == "from-deployer":
        addrs = deployer_contracts(args.target, chain)
        if addrs is None:
            print("[!] from-deployer needs ETHERSCAN_API_KEY (export it) for the txlist creation-scan.")
            print("    Workaround: paste the legacy addresses you already have into `check` (keyless).")
            return 1
        print(f"# legacy scan: {len(addrs)} contract(s) created by {args.target}  chain={chain}\n")
    else:
        addrs = [a.strip() for a in args.target.split(",") if a.strip()]
        print(f"# legacy check  chain={chain}  window={args.blocks} blocks\n")

    hits = 0
    for a in addrs:
        try:
            r = assess(a, chain, args.blocks, rpc)
        except Exception as e:
            print(f"[ERROR        ] {a}  -- {str(e)[:60]}")
            continue
        if r["verdict"] == "LEGACY-FUNDED":
            hits += 1
        _print_row(r)
    print(f"\n-> {hits} LEGACY-FUNDED (deprecated + still holds value) = the Thetanuts class -> fetch_source + recon."
          "\n   No ETHERSCAN_API_KEY => dormancy rests on the event window only (weaker); a key adds authoritative txns.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
