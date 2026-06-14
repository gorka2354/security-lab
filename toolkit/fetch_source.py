#!/usr/bin/env python3
"""fetch_source.py - LIVE-FIRST: fetch a DEPLOYED contract's verified source by address.

A repo mixes deployed AND not-deployed code (Malda's LZ bridge was in the repo but not
live -> low EV). The verified source ON-CHAIN *is* the deployed code. Fetch that and run
recon/scope/hypothesize on it -> you hunt only LIVE, in-scope code. (See method note "LIVE-FIRST".)

    python toolkit/fetch_source.py <address> [--chain 1] [--out <dir>]
    # then:  python toolkit/recon.py <dir>   /   scope.py <dir>   /   hypothesize.py <dir>

Sources (in order):
  1. Etherscan v2 API  - env ETHERSCAN_API_KEY, near-full coverage, all chains via chainid
  2. Sourcify          - no key, partial coverage (fallback)
ASCII output. Stdlib only (urllib). Chain ids: 1 eth, 8453 base, 42161 arb, 59144 linea, 10 op.
"""

import argparse
import json
import os
import re
import urllib.request

# EIP-1967 implementation slot = keccak256("eip1967.proxy.implementation") - 1
EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
DEFAULT_RPC = {
    "1": "https://ethereum-rpc.publicnode.com", "8453": "https://base-rpc.publicnode.com",
    "42161": "https://arbitrum-one-rpc.publicnode.com", "10": "https://optimism-rpc.publicnode.com",
    "59144": "https://linea-rpc.publicnode.com", "137": "https://polygon-bor-rpc.publicnode.com",
    "56": "https://bsc-rpc.publicnode.com",          # BSC (posi-vaults lived here)
    "5000": "https://rpc.mantle.xyz",                # Mantle (mantle-index false-DORMANT fix)
    "999": "https://rpc.hyperliquid.xyz/evm",        # HyperEVM (hyperbeat)
    "31612": "https://mezo.drpc.org",                # Mezo (mezo-borrow)
    "146": "https://sonic.drpc.org",                 # Sonic (ledgity WrappedLTokenSonic)
    "2741": "https://api.mainnet.abs.xyz",            # Abstract (ZK Stack / Pudgy; gaming + native AA)
}


def _get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "security-lab/1.0"})
    with urllib.request.urlopen(req, timeout=40) as r:
        return r.read().decode("utf-8", "replace")


def _rpc(rpc, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(rpc, data=body,
                                 headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read()).get("result")


def impl_from_eip1167(code):
    """Extract the implementation address embedded in EIP-1167 minimal-proxy bytecode. Pure (testable)."""
    m = re.search(r"363d3d373d3d3d363d73([0-9a-fA-F]{40})5af4", code or "")
    return "0x" + m.group(1) if m else None


def resolve_impl(address, chain, rpc=None):
    """Follow an EIP-1967 (storage slot) or EIP-1167 (minimal-proxy bytecode) proxy to its
    implementation address. Returns None for an EOA / non-proxy / unknown chain. Needs an RPC."""
    rpc = rpc or DEFAULT_RPC.get(str(chain))
    if not rpc:
        return None
    try:
        raw = _rpc(rpc, "eth_getStorageAt", [address, EIP1967_IMPL_SLOT, "latest"]) or ""
        if raw and set(raw[2:]) != {"0"}:
            return "0x" + raw[-40:]
        return impl_from_eip1167(_rpc(rpc, "eth_getCode", [address, "latest"]) or "")
    except Exception:
        return None


def parse_etherscan_source(src, name="Contract"):
    """Etherscan getsourcecode 'SourceCode' field -> {path: content}.

    Handles both shapes: a flat single-file string, and a standard-json-input that
    Etherscan double-wraps in {{ ... }}. Pure (no network) -> unit-testable.
    """
    s = (src or "").strip()
    if not s:
        return {}
    if s.startswith("{{") and s.endswith("}}"):   # Etherscan double-wraps standard-json
        s = s[1:-1]
    if s.startswith("{"):
        try:
            obj = json.loads(s)
            sources = obj.get("sources", obj)
            files = {}
            for path, v in sources.items():
                files[path] = v.get("content", "") if isinstance(v, dict) else str(v)
            if files:
                return files
        except Exception:
            pass
    return {name + ".sol": s}   # flat single-file source


def from_etherscan(address, chain, key):
    url = (f"https://api.etherscan.io/v2/api?chainid={chain}&module=contract"
           f"&action=getsourcecode&address={address}&apikey={key}")
    try:
        data = json.loads(_get(url))
    except Exception:
        return None
    if str(data.get("status")) != "1" or not data.get("result"):
        return None
    res = data["result"][0]
    return parse_etherscan_source(res.get("SourceCode", ""), res.get("ContractName") or "Contract") or None


def from_sourcify(address, chain):
    # Sourcify v2 (the old /files/{chain}/{address} endpoint is deprecated -> 404)
    url = f"https://sourcify.dev/server/v2/contract/{chain}/{address}?fields=sources"
    try:
        obj = json.loads(_get(url))
    except Exception:
        return None
    sources = obj.get("sources") or {}
    files = {}
    for path, v in sources.items():
        files[path] = v.get("content", "") if isinstance(v, dict) else str(v)
    return files or None


def main():
    ap = argparse.ArgumentParser(description="Fetch a deployed contract's verified source (live-first)")
    ap.add_argument("address")
    ap.add_argument("--chain", default="1", help="chain id (1 eth, 8453 base, 42161 arb, 59144 linea)")
    ap.add_argument("--out", help="output dir (default: fetched/<chain>_<address>)")
    ap.add_argument("--proxy", action="store_true",
                    help="follow EIP-1967/1167 proxy to its impl and fetch THAT (live drift-hunting)")
    ap.add_argument("--rpc", help="RPC url for --proxy (default: a public node for the chain)")
    a = ap.parse_args()
    address = a.address
    if a.proxy:
        impl = resolve_impl(a.address, a.chain, a.rpc)
        if impl and impl.lower() != a.address.lower():
            print(f"[proxy] {a.address} -> implementation {impl} (fetching the live logic, not the stub)")
            address = impl
        else:
            print(f"[proxy] no proxy impl resolved for {a.address} (EOA / non-proxy / no RPC) - fetching as-is")
    out = a.out or os.path.join("fetched", f"{a.chain}_{address}")

    key = os.environ.get("ETHERSCAN_API_KEY")
    files, backend = None, None
    if key:
        files = from_etherscan(address, a.chain, key)
        backend = "Etherscan v2"
    if not files:
        files = from_sourcify(address, a.chain)
        backend = "Sourcify"
    if not files:
        print(f"[!] no verified source for {address} on chain {a.chain} "
              f"({'set ETHERSCAN_API_KEY for full coverage' if not key else 'unverified / not on Sourcify'})")
        return

    nsol = 0
    for path, content in files.items():
        safe = path.replace("\\", "/").lstrip("/").replace("..", "_")
        dest = os.path.join(out, safe)
        os.makedirs(os.path.dirname(os.path.abspath(dest)), exist_ok=True)
        open(dest, "w", encoding="utf-8").write(content)
        nsol += 1
    print(f"[{backend}] wrote {nsol} verified source files -> {out}")
    print(f"  this is the DEPLOYED (live) code. Next: recon.py / scope.py / hypothesize.py {out}")


if __name__ == "__main__":
    main()
