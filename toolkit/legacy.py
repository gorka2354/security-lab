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
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import activity  # reuse probe / classify helpers / CHAIN_ALIAS  # noqa: E402
import fetch_source as fs  # noqa: E402


def classify_legacy(code_len, events, balance_wei, token_bal=None, supply=None, age_days=None, dormant_days=90):
    """PURE inverse of activity.classify: the target class is DEPRECATED (no RECENT activity) yet still FUNDED
    (residual ETH/token, or outstanding shares = backing). Dormancy is the AGE of the last tx, NOT a tx COUNT
    -- an abandoned contract with 20 lifetime txns from 2021 still has count>0 (the live-run lesson). age_days
    = days since the most recent tx (None if no key -> fall back to the event window, weaker). Returns (verdict, rec, note)."""
    if code_len < 0:
        return ("UNKNOWN", "RETRY", "eth_getCode returned null (RPC issue) -> retry, NOT 'no code'")
    if code_len == 0:
        return ("NO-CODE", "SKIP", "no bytecode (EOA / not deployed / wrong chain)")
    has_value = balance_wei > 0 or (token_bal or 0) > 0 or (supply or 0) > 0
    if not has_value:
        return ("EMPTY", "SKIP",
                "deployed but 0 ETH / 0 token / totalSupply==0 -> nothing at stake (drained or never funded)")
    if age_days is not None:
        dormant = age_days >= dormant_days                  # authoritative: time since the last tx
    elif (events or 0) > 0:
        dormant = False                                     # recent events -> active (no key for age)
    elif events == 0:
        dormant = True                                      # no events in window, no key -> tentative (weaker)
    else:
        return ("UNKNOWN", "RETRY", "no last-tx age (no key) AND the event query failed -> can't gate dormancy; set ETHERSCAN_API_KEY")
    if not dormant:
        age_str = f"last tx {age_days:.0f}d ago" if age_days is not None else "recent events"
        return ("ACTIVE-FUNDED", "normal-hunt",
                f"holds value AND active ({age_str}) -> a LIVE target, not the legacy class; hunt via the normal lane")
    age_str = f"last tx {age_days:.0f}d ago" if age_days is not None else "no recent events (no key -> weak signal)"
    return ("LEGACY-FUNDED", "READ IT",
            f"residual value + DORMANT ({age_str}) -> a DEPRECATED-but-funded contract (Thetanuts class): forgotten, "
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


def _creations_from_internal(rows, creator):
    """PURE: the contractAddresses CREATED BY `creator` in a txlistinternal result -- internal txns of
    type create/create2 whose `from` is the creator. This is how vault protocols spawn clones (factory
    pattern), which the deployer-EOA txlist NEVER shows. Unit-testable."""
    seen, out, cl = set(), [], (creator or "").lower()
    for tx in rows or []:
        ca = (tx.get("contractAddress") or "").strip()
        if (tx.get("type") in ("create", "create2") and (tx.get("from") or "").lower() == cl
                and ca and ca.lower() not in seen):
            seen.add(ca.lower())
            out.append(ca)
    return out


def factory_spawned(factory, chain, key=None, cap=10000):
    """Contracts a FACTORY created (Etherscan-v2 txlistinternal, type create/create2). Closes the
    from-deployer blind spot: most vaults are factory-clones, invisible to the EOA txlist. Needs a key."""
    key = key or os.environ.get("ETHERSCAN_API_KEY")
    if not key:
        return None
    url = ("https://api.etherscan.io/v2/api?chainid=%s&module=account&action=txlistinternal&address=%s"
           "&startblock=0&endblock=99999999&page=1&offset=%d&sort=asc&apikey=%s" % (chain, factory, cap, key))
    try:
        d = json.load(urllib.request.urlopen(
            urllib.request.Request(url, headers={"User-Agent": "security-lab"}), timeout=30))
    except Exception:
        return None
    rows = d.get("result")
    if not isinstance(rows, list):
        return None
    return _creations_from_internal(rows, factory)


def is_7702(code_raw):
    """An EIP-7702 delegated EOA carries exactly 23 bytes of code: 0xef0100 + a 20-byte address. It is a
    WALLET, not a deployed contract -> never a legacy-contract target (caught on the first live run: a
    7702 EOA with ETH + no events mis-read as LEGACY-FUNDED). PURE."""
    c = (code_raw or "").lower()
    return c.startswith("0xef0100") and len(c) == 2 + 23 * 2


def last_tx_age_days(addr, chain, key=None):
    """Days since the address's MOST RECENT tx (Etherscan-v2 txlist, sort=desc, the [0] timeStamp). The
    authoritative dormancy signal -- a tx COUNT can't tell 'busy' from '20 txns, last one in 2021'. Returns
    a float (days) or None (no key / no txns / call failed). Caveat: normal txlist; router/internal-only
    activity isn't counted -> a legacy lead, confirm by hand."""
    key = key or os.environ.get("ETHERSCAN_API_KEY")
    if not key:
        return None
    url = ("https://api.etherscan.io/v2/api?chainid=%s&module=account&action=txlist&address=%s"
           "&page=1&offset=1&sort=desc&apikey=%s" % (chain, addr, key))
    try:
        d = json.load(urllib.request.urlopen(
            urllib.request.Request(url, headers={"User-Agent": "security-lab"}), timeout=25))
        r = d.get("result")
        if isinstance(r, list) and r:
            return max(0.0, (time.time() - int(r[0]["timeStamp"])) / 86400.0)
    except Exception:
        return None
    return None


def assess(addr, chain, blocks, rpc, dormant_days=90, token=None):
    """Probe one address (reusing activity.probe) and apply the legacy classifier. `token` = an ERC20 to also
    count as HELD value -> a bridge/escrow holds LOCKED TOKENS, not ETH (the Pepu-dig lesson: without this a
    token-holding bridge reads EMPTY = false-negative). Returns a dict row."""
    code_raw = fs._rpc(rpc, "eth_getCode", [addr, "latest"])
    if is_7702(code_raw):
        return {"addr": addr, "verdict": "EOA-7702", "rec": "SKIP", "code": 23, "events": 0,
                "eth": 0.0, "supply": None, "dec": 18, "age": None, "tok": None,
                "note": "EIP-7702 delegated EOA (0xef0100 prefix) -> a wallet, not a deployed contract"}
    code_len, events, xfer, bal, tok, supply, dec, txc, _cval = activity.probe(addr, chain, blocks, rpc, token, None)
    tokdec = 18
    if token and tok:                                # the HELD token's own decimals (USDC=6) so display isn't mis-scaled
        traw = fs._rpc(rpc, "eth_call", [{"to": token, "data": activity.DECIMALS}, "latest"])
        try:
            d2 = int(traw, 16)
            tokdec = d2 if 0 < d2 <= 36 else 18
        except Exception:
            pass
    age = last_tx_age_days(addr, chain)
    verdict, rec, note = classify_legacy(code_len, events, bal, tok, supply, age, dormant_days)
    return {"addr": addr, "verdict": verdict, "rec": rec, "note": note, "code": code_len, "events": events,
            "eth": bal / 1e18, "supply": supply, "dec": dec, "age": age, "tok": tok, "tokdec": tokdec}


def _print_row(r):
    ev = "?" if r["events"] < 0 else r["events"]
    extra = ""
    if r["supply"] is not None:
        extra += f" totalSupply={r['supply'] / 10 ** r['dec']:,.2f}"
    if r.get("tok"):
        extra += f" tokenHeld={r['tok'] / 10 ** r.get('tokdec', 18):,.2f}"
    if r.get("age") is not None:
        extra += f" lastTx={r['age']:.0f}d ago"
    print(f"[{r['verdict']:13}] {r['addr']}  ({r['rec']})")
    print(f"               code={r['code']}B  events={ev}  eth={r['eth']:.4f}{extra}")
    print(f"               {r['note']}")


def _load_addrs(path, target):
    """sweep/check input: addresses from a --file (one per line, '#' comments ok) + a comma list, de-duped."""
    src = []
    if path:
        try:
            src += open(path, encoding="utf-8", errors="ignore").read().splitlines()
        except Exception as e:
            raise SystemExit(f"[!] cannot read --file {path}: {e}")
    src += (target or "").split(",")
    out, seen = [], set()
    for line in src:
        a = line.split("#")[0].strip()
        if a and a.lower() not in seen:
            seen.add(a.lower())
            out.append(a)
    return out


def _value_key(r):
    """sweep ranking: LEGACY-FUNDED first, then by residual ETH, then supply (a ROUGH proxy -- no price feed)."""
    order = {"LEGACY-FUNDED": 0, "ACTIVE-FUNDED": 1}.get(r["verdict"], 2)
    return (order, -(r.get("eth") or 0.0), -((r.get("supply") or 0)))


def main():
    ap = argparse.ArgumentParser(description="Deprecated-but-funded sourcing lane (the Thetanuts class)")
    ap.add_argument("mode", choices=["check", "from-deployer", "from-factory", "sweep"],
                    help="check / enumerate a deployer EOA / a factory's clones / sweep+rank a big list")
    ap.add_argument("target", nargs="?", default="",
                    help="address(es) comma-sep; or a deployer/factory addr; omit for `sweep --file`")
    ap.add_argument("--file", help="sweep/check: a file of addresses, one per line ('#' comments ok)")
    ap.add_argument("--chain", default="1", help="chain id or name (eth/base/arb/op/linea/polygon/...)")
    ap.add_argument("--blocks", type=int, default=20000, help="event lookback window (wider than activity: legacy = low-frequency)")
    ap.add_argument("--dormant-days", type=int, default=90, help="last-tx age (days) at/above which a funded contract is DORMANT")
    ap.add_argument("--token", help="an ERC20 to also count as HELD value (a bridge/escrow locks tokens, not ETH)")
    ap.add_argument("--rpc", help="override RPC url")
    args = ap.parse_args()

    chain = activity.resolve_chain(args.chain)
    rpc = args.rpc or fs.DEFAULT_RPC.get(chain)
    if not rpc:
        print(f"[!] no RPC for chain {args.chain} -> pass --rpc")
        return 1

    if args.mode in ("from-deployer", "from-factory"):
        enum, kind = ((deployer_contracts, "created by deployer EOA") if args.mode == "from-deployer"
                      else (factory_spawned, "spawned by factory"))
        addrs = enum(args.target, chain)
        if addrs is None:
            print(f"[!] {args.mode} needs ETHERSCAN_API_KEY (export it) for the creation-scan.")
            print("    Workaround: paste the legacy addresses you already have into `check` (keyless).")
            return 1
        print(f"# legacy scan: {len(addrs)} contract(s) {kind} {args.target}  chain={chain}\n")
    else:
        addrs = _load_addrs(args.file, args.target)
        if not addrs:
            print("[!] no addresses -> pass them comma-sep, or --file <path>")
            return 1
        print(f"# legacy {args.mode}  chain={chain}  {len(addrs)} address(es)  window={args.blocks} blocks\n")

    rows = []
    for a in addrs:
        try:
            rows.append(assess(a, chain, args.blocks, rpc, args.dormant_days, args.token))
        except Exception as e:
            print(f"[ERROR        ] {a}  -- {str(e)[:60]}")

    if args.mode == "sweep":
        rows.sort(key=_value_key)
        targets = [r for r in rows if r["verdict"] == "LEGACY-FUNDED"]
        print(f"## TOP TARGETS -- {len(targets)} LEGACY-FUNDED (ranked by residual value)\n")
        for r in targets:
            _print_row(r)
        tally = {}
        for r in rows:
            tally[r["verdict"]] = tally.get(r["verdict"], 0) + 1
        print("\n## rest (tally): " + ", ".join(f"{v}x{k}" for k, v in sorted(tally.items())))
        print(f"\n-> {len(targets)}/{len(rows)} LEGACY-FUNDED -> fetch_source + recon (det_vault_share_math/det_erc4626)."
              "\n   Value rank is a ROUGH proxy (no price feed); verify backing + scope by hand.")
    else:
        hits = 0
        for r in rows:
            if r["verdict"] == "LEGACY-FUNDED":
                hits += 1
            _print_row(r)
        print(f"\n-> {hits} LEGACY-FUNDED (deprecated + still holds value) = the Thetanuts class -> fetch_source + recon."
              "\n   No ETHERSCAN_API_KEY => dormancy rests on the event window only (weaker); a key adds authoritative txns.")
    return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
