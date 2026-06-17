#!/usr/bin/env python3
"""reach_bytecode.py -- extend reach to UNVERIFIED-but-live contracts (the ThetaNuts lesson).

When fetch_source.py returns "no verified source", the source-based pipeline stops at the door --
which is exactly how the ThetaNuts legacy Index Vault ($2.1M, unverified) slipped past. But the
deployed BYTECODE is readable for ANY address (eth_getCode). This tool recovers what it can WITHOUT
source: the function-dispatcher SELECTORS -> resolved to human signatures (openchain.xyz, with an
offline fallback map for the standard ERC20/4626 ones) -> a surface triage (vault? mint/redeem?
owner-drain?). Selector recovery alone is a real triage win: it tells you an unverified live
contract HAS a deposit/redeem/mint surface worth a manual (or decompiled) share-inflation review.

Honest ceiling: this recovers the SURFACE (which functions exist), not the share MATH. Confirming
the round-to-zero/inflation bug still needs decompilation (heimdall/Dedaub) or the verified source.
Usage: python toolkit/reach_bytecode.py <address> [chainid]
"""
import os
import re
import sys
import json
import urllib.request

ETHERSCAN = "https://api.etherscan.io/v2/api"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) reach_bytecode/1.0"


def _get(url, timeout=15):
    """urllib GET with a real User-Agent (the default Python-urllib UA is WAF/Cloudflare-blocked)."""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)

# Standard selectors that resolve OFFLINE (no network) -- enough to confirm an ERC20/vault token.
KNOWN = {
    "18160ddd": "totalSupply()",
    "70a08231": "balanceOf(address)",
    "a9059cbb": "transfer(address,uint256)",
    "23b872dd": "transferFrom(address,address,uint256)",
    "095ea7b3": "approve(address,uint256)",
    "dd62ed3e": "allowance(address,address)",
    "313ce567": "decimals()",
    "06fdde03": "name()",
    "95d89b41": "symbol()",
    "b6b55f25": "deposit(uint256)",
    "6e553f65": "deposit(uint256,address)",
    "db006a75": "redeem(uint256)",
    "ba087652": "redeem(uint256,address,address)",
    "2e1a7d4d": "withdraw(uint256)",
    "b460af94": "withdraw(uint256,address,address)",
    "1249c58b": "mint()",
    "a0712d68": "mint(uint256)",
    "94bf804d": "mint(uint256,address)",
    "c6e6f592": "convertToShares(uint256)",
    "07a2d13a": "convertToAssets(uint256)",
    "01e1d114": "totalAssets()",
    "8da5cb5b": "owner()",
    "f2fde38b": "transferOwnership(address)",
}

# STRONG share-accounting entry points (the share-conversion surface) -- these make it a VAULT.
STRONG_VAULT = re.compile(
    r"\b(deposit|redeem|withdraw|convertToShares|convertToAssets|previewDeposit|previewRedeem)\w*\s*\(", re.I)
# WEAK supporting signals -- present on plain tokens too, so not sufficient alone.
WEAK_VAULT = re.compile(r"\b(mint|claim|stake|unstake)\w*\s*\(", re.I)
SUPPLY_SURFACE = re.compile(r"\b(totalSupply|totalAssets|balanceOf)\s*\(", re.I)


def is_eravm(code):
    """zkSync EraVM bytecode (Abstract 2741, zkSync Era 324, Sophon...) starts with a 0x00 version
    word; EVM runtime starts with the Solidity preamble 0x6080.. -> a 0x00 first byte = non-EVM."""
    return bool(code) and code.startswith("0x") and len(code) > 4 and code[2:4] == "00"


def get_code(addr, chain="1"):
    key = os.environ.get("ETHERSCAN_API_KEY", "")
    url = f"{ETHERSCAN}?chainid={chain}&module=proxy&action=eth_getCode&address={addr}&apikey={key}"
    return _get(url, timeout=30).get("result", "") or ""


def extract_selectors(code_hex):
    """Walk the bytecode opcode-aware (so PUSH immediates aren't mis-scanned) and collect every
    PUSH4 immediate -- the function dispatcher compares msg.sig against each selector with PUSH4."""
    b = bytes.fromhex(code_hex[2:] if code_hex.startswith("0x") else code_hex)
    sels, seen, i, n = [], set(), 0, len(b)
    while i < n:
        op = b[i]
        if 0x60 <= op <= 0x7f:                 # PUSH1..PUSH32
            width = op - 0x5f
            if op == 0x63 and i + 5 <= n:      # PUSH4 -> candidate selector
                s = b[i + 1:i + 5].hex()
                if s not in seen and s not in ("00000000", "ffffffff"):
                    seen.add(s)
                    sels.append(s)
            i += 1 + width
        else:
            i += 1
    return sels


def resolve_openchain(selectors):
    """Batch-resolve selectors -> signatures via the free openchain.xyz signature DB."""
    res = {}
    for j in range(0, len(selectors), 50):
        chunk = selectors[j:j + 50]
        q = "&".join("function=0x" + s for s in chunk)
        url = f"https://api.openchain.xyz/signature-database/v1/lookup?{q}&filter=true"
        try:
            fns = _get(url, timeout=30).get("result", {}).get("function", {})
            for s in chunk:
                hits = fns.get("0x" + s) or []
                if hits:
                    res[s] = hits[0]["name"]
        except Exception:
            pass
    return res


def resolve_4byte(selectors):
    """Per-selector fallback via 4byte.directory (reachable when openchain isn't). Picks the
    earliest-id signature (the canonical one; later collisions are usually spam)."""
    res = {}
    for s in selectors:
        try:
            url = f"https://www.4byte.directory/api/v1/signatures/?hex_signature=0x{s}"
            results = _get(url, timeout=10).get("results", [])
            if results:
                results.sort(key=lambda x: x.get("id", 1 << 62))
                res[s] = results[0]["text_signature"]
        except Exception:
            pass
    return res


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    addr, chain = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else "1")
    code = get_code(addr, chain)
    if not code or code == "0x":
        print(f"[!] {addr}: no bytecode (EOA / self-destructed)")
        return
    # EVM runtime starts with the Solidity preamble (PUSH1 0x80 -> 0x6080...); zkSync EraVM bytecode
    # (Abstract chain 2741, zkSync Era 324, Sophon, Sonic-zk...) starts with 0x00.. version words and
    # is NOT EVM -> the PUSH4 selector scan AND the EVM decompilers (heimdall/panoramix) do NOT apply.
    if is_eravm(code):
        print(f"[reach_bytecode] {addr} chain {chain}: {(len(code) - 2) // 2} bytes -- NON-EVM bytecode "
              f"(zkSync EraVM? e.g. Abstract/zkSync-Era/Sophon). The EVM selector scan + EVM decompilers "
              f"(heimdall/panoramix) do NOT apply here; an UNVERIFIED contract on a zk-chain can't be reached "
              f"this way -> need verified source or a dedicated EraVM/zkEVM tool.")
        return
    print(f"[reach_bytecode] {addr} chain {chain}: {(len(code) - 2) // 2} bytes")
    sels = extract_selectors(code)
    online = resolve_openchain(sels)
    names = {s: (KNOWN.get(s) or online.get(s)) for s in sels}
    gaps = [s for s in sels if not names.get(s)]
    fourbyte = resolve_4byte(gaps) if gaps else {}
    names = {s: (KNOWN.get(s) or online.get(s) or fourbyte.get(s)) for s in sels}
    resolved = {s: nm for s, nm in names.items() if nm}
    src = "openchain" if online else ("4byte" if fourbyte else "offline-map-only")
    print(f"  selectors: {len(sels)} recovered, {len(resolved)} resolved (resolver: {src})")
    strong, weak, supply = [], [], []
    for s in sels:
        nm = names.get(s)
        if not nm:
            continue
        tag = ""
        if STRONG_VAULT.search(nm):
            tag = "   <-- SHARE-CONVERSION surface"
            strong.append(nm)
        elif WEAK_VAULT.search(nm):
            tag = "   (mint/claim -- supporting)"
            weak.append(nm)
        elif SUPPLY_SURFACE.search(nm):
            supply.append(nm)
        print(f"    0x{s}  {nm}{tag}")
    print()
    fns = lambda lst: ", ".join(sorted(set(f.split("(")[0] for f in lst)))
    if strong and supply:
        print(f"  [!] UNVERIFIED but VAULT-SHAPED: share-token (totalSupply/balanceOf) + share-conversion "
              f"({fns(strong)}{', +' + fns(weak) if weak else ''}) -> manual/decompiled share-inflation "
              f"review warranted (the det_erc4626 class can't see the round-to-zero math without source)")
    elif strong:
        print(f"  [.] share-conversion surface ({fns(strong)}) but no clear share-token -> verify")
    elif weak and supply:
        print(f"  [ ] mintable/claimable token ({fns(weak)}) -- NOT a share vault (no deposit/redeem/convert)")
    else:
        print("  [ ] no obvious vault/share-conversion surface in the resolved selectors")


if __name__ == "__main__":
    main()
