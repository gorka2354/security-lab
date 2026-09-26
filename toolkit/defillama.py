"""Resolve a protocol's REAL deployed contract addresses from its DefiLlama TVL-adapter config
(github.com/DefiLlama/DefiLlama-Adapters projects/<slug>/index.js), grouped by chain.

WHY: DefiLlama's `protocol.address` field is frequently a DECOY -- no code, a token, or a thin wrapper --
which this arc hit repeatedly (Morpho Midnight singleton, NUVA, Saffron, Lista RWA). The TVL-adapter
config, by contrast, names the actual contracts the protocol's TVL is read from. Reach the real code
first, then fetch_source / threat.py / recon on it.

Usage: python toolkit/defillama.py addrs <slug>          # slug = the DefiLlama-Adapters project dir name
"""

from __future__ import annotations

import argparse
import re
import urllib.request
import tlsfix  # noqa: F401,E402  -- current CA bundle on stale-CA Windows hosts (see tlsfix.py)

CHAINS = (r"ethereum|arbitrum|base|bsc|binance|polygon|optimism|avax|avalanche|fantom|linea|scroll|"
          r"gnosis|celo|sonic|mantle|blast|mode|zksync|era|metis|kava|core|manta|fraxtal|unichain|"
          r"berachain|hyperliquid|hyperevm|katana|monad|xdai|op|arb")

# chain-name -> chain id (for fetch_source.py / threat.py --chain)
CHAIN_ID = {
    "ethereum": 1, "op": 10, "optimism": 10, "bsc": 56, "binance": 56, "gnosis": 100, "xdai": 100,
    "polygon": 137, "fantom": 250, "zksync": 324, "era": 324, "metis": 1088, "base": 8453,
    "mode": 34443, "arbitrum": 42161, "arb": 42161, "celo": 42220, "avax": 43114, "avalanche": 43114,
    "linea": 59144, "blast": 81457, "scroll": 534352, "sonic": 146, "mantle": 5000, "berachain": 80094,
    "unichain": 130, "hyperliquid": 999, "hyperevm": 999, "core": 1116, "manta": 169, "fraxtal": 252,
    "kava": 2222, "katana": 747474, "monad": 143,
}
_TOKEN = re.compile(r"\b(" + CHAINS + r")\b|0x[a-fA-F0-9]{40}(?![a-fA-F0-9])", re.I)


def adapter_url(slug):
    return "https://raw.githubusercontent.com/DefiLlama/DefiLlama-Adapters/main/projects/%s/index.js" % slug


def addrs(slug):
    """-> {chain: [addr,...]} of the REAL contracts named in the TVL adapter. Empty on no-adapter."""
    req = urllib.request.Request(adapter_url(slug), headers={"User-Agent": "curl/8.0"})
    txt = urllib.request.urlopen(req, timeout=20).read().decode("utf-8", "ignore")
    out, cur = {}, "?"
    for m in _TOKEN.finditer(txt):
        tok = m.group(0)
        if tok.lower().startswith("0x"):
            out.setdefault(cur, [])
            if tok not in out[cur]:
                out[cur].append(tok)
        else:
            cur = tok.lower()
    return out


def main():
    ap = argparse.ArgumentParser(description="Resolve REAL contract addresses from a DefiLlama TVL adapter")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("addrs")
    a.add_argument("slug")
    args = ap.parse_args()
    if args.cmd == "addrs":
        try:
            res = addrs(args.slug)
        except Exception as e:
            print("no adapter / fetch failed for '%s': %s" % (args.slug, str(e)[:80]))
            print("  (try the exact DefiLlama-Adapters projects/<dir> name; some protocols have no adapter)")
            return
        if not res:
            print("== '%s': adapter found but 0 addresses (config may be programmatic/imported) ==" % args.slug)
            return
        total = sum(len(v) for v in res.values())
        print("== '%s': %d real contract address(es) from the TVL adapter (NOT the decoy protocol.address) ==" % (
            args.slug, total))
        for chain, al in res.items():
            cid = CHAIN_ID.get(chain)
            print("  [%s%s] %s" % (chain, ("/%d" % cid) if cid else "", ""))
            for a2 in al:
                print("     %s   ->  fetch_source.py %s --chain %s ; threat.py %s --chain %s" % (
                    a2, a2, cid or chain, a2, cid or chain))


if __name__ == "__main__":
    main()
