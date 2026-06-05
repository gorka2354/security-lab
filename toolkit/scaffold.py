#!/usr/bin/env python3
"""scaffold.py - generate a Foundry invariant-test scaffold for a contract.

    python scaffold.py <path/to/Contract.sol> [ContractName] [--out file.t.sol]

The L3 force-multiplier: writing an invariant handler by hand (a bounded wrapper
for every state-changing function, with actors/prank/bound) takes hours on a big
contract. This auto-generates that tedious 80% - the Handler + targetSelector
wiring + the universal-invariant stubs. You fill the 20%: deploy the target in
setUp and complete the protocol-specific invariants.

Heuristic parser (regex, like recon.py) - expect to refine the output. ASCII.
"""

import argparse
import os
import re

# universal invariants worth checking on almost any protocol (stubs to fill)
UNIVERSAL = [
    ("invariant_solvency",
     "contract can always cover what it owes (balance >= obligations)",
     "// assertGe(token.balanceOf(address(target)), _totalOwed(), \"INSOLVENT\");"),
    ("invariant_supply_conservation",
     "no tokens minted from nothing (totalSupply backed)",
     "// assertLe(target.totalSupply(), _backing(), \"SUPPLY > BACKING\");"),
    ("invariant_no_free_value",
     "no actor can withdraw/redeem more value than they put in",
     "// for each actor: assertLe(valueOut[a], valueIn[a]);  // track in handler"),
    ("invariant_share_price_sane",
     "share price never jumps without a backing change / never zero",
     "// uint256 pps = target.convertToAssets(1e18); assertGt(pps, 0);"),
    ("invariant_accounting_consistent",
     "sum of balances == totalSupply; per-user accounting matches globals",
     "// assertEq(_sumBalances(), target.totalSupply());"),
]


def split_top_level(s, sep=","):
    """Split by sep, ignoring separators inside (), [], <>."""
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch in "([<":
            depth += 1
        elif ch in ")]>":
            depth -= 1
        if ch == sep and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return [p.strip() for p in out if p.strip()]


def categorize(param):
    """Return (kind, base_type, name) for a single param declaration."""
    toks = param.replace("\n", " ").split()
    if len(toks) < 2:
        return ("skip", param, "")
    name = toks[-1]
    base = toks[0]
    arr = base.endswith("[]") or "[]" in param
    core = base.rstrip("[]")
    if arr:
        return ("array", base, name)
    if re.match(r"u?int\d*$", core):
        return ("num", core, name)
    if core == "address":
        return ("addr", core, name)
    if core == "bool":
        return ("bool", core, name)
    if core == "string" or core == "bytes":
        return ("dynbytes", core, name)
    if re.match(r"bytes\d+$", core):
        return ("fixed", core, name)  # bytes32 etc -> fuzzable value
    return ("other", core, name)


def find_contract_body(text, name=None):
    """Return (contract_name, body_text). If name given, find it; else first contract."""
    decls = list(re.finditer(r"\b(contract|interface|library|abstract\s+contract)\s+(\w+)", text))
    targets = [d for d in decls if d.group(0).split()[0] != "interface"
               and "library" not in d.group(0)]
    if name:
        targets = [d for d in decls if d.group(2) == name]
    elif targets:
        targets = [targets[0]]
    if not targets:
        return None, ""
    d = targets[0]
    start = d.start()
    after = [x.start() for x in decls if x.start() > start]
    end = min(after) if after else len(text)
    return d.group(2), text[start:end]


def parse_functions(body):
    """Yield (name, params_str, is_payable) for external/public state-changing fns."""
    for m in re.finditer(r"function\s+(\w+)\s*\(([^{};]*?)\)([^{};]*?)\{", body, re.S):
        name, params, attrs = m.group(1), m.group(2), m.group(3)
        if not re.search(r"\b(external|public)\b", attrs):
            continue
        if re.search(r"\b(view|pure)\b", attrs):
            continue
        yield name, params, bool(re.search(r"\bpayable\b", attrs))


def gen_handler_fn(name, params, payable):
    """Generate one handler wrapper method."""
    parsed = [categorize(p) for p in split_top_level(params)]
    sig_params = ["uint256 _actorSeed"]
    if payable:
        sig_params.append("uint256 _value")
    body, args, todos = [], [], []
    n = 0
    for kind, base, pname in parsed:
        if kind == "num":
            n += 1
            v = f"a{n}"
            sig_params.append(f"{base} {v}")
            body.append(f"        {v} = {base}(bound(uint256({v}), 0, 1e30));")
            args.append(v)
        elif kind == "fixed":
            n += 1
            v = f"a{n}"
            sig_params.append(f"{base} {v}")
            args.append(v)
        elif kind == "bool":
            n += 1
            v = f"a{n}"
            sig_params.append(f"bool {v}")
            args.append(v)
        elif kind == "addr":
            args.append("_actor(_actorSeed)")
        elif kind == "dynbytes":
            args.append('""' if base == "bytes" else '""')
        elif kind == "array":
            args.append(f"new {base.rstrip('[]')}[](0)")
            todos.append(f"refine array arg ({base} {pname})")
        else:
            args.append("/*TODO*/ 0")
            todos.append(f"refine arg ({base} {pname})")
    call_val = "{value: _value}" if payable else ""
    lines = [f"    function h_{name}({', '.join(sig_params)}) public {{"]
    lines.append("        address a = _actor(_actorSeed);")
    lines += body
    if payable:
        lines.append("        _value = bound(_value, 0, 100 ether);")
        lines.append("        vm.deal(address(this), _value);")
    if todos:
        lines.append("        // TODO: " + "; ".join(todos))
    lines.append("        vm.prank(a);")
    lines.append(f"        try target.{name}{call_val}({', '.join(args)}) {{}} catch {{}}")
    lines.append("    }")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Foundry invariant-test scaffolder")
    ap.add_argument("file")
    ap.add_argument("contract", nargs="?", default=None)
    ap.add_argument("--out")
    args = ap.parse_args()

    text = open(args.file, encoding="utf-8", errors="ignore").read()
    cname, body = find_contract_body(text, args.contract)
    if not cname:
        print("no contract found")
        return 1
    fns = list(parse_functions(body))
    if not fns:
        print(f"no external/public state-changing functions in {cname}")
        return 1

    handlers = [gen_handler_fn(n, p, pay) for n, p, pay in fns]
    selectors = "\n".join(
        f"        sel[{i}] = {cname}Handler.h_{n}.selector;" for i, (n, _, _) in enumerate(fns))
    invs = "\n\n".join(
        f"    /// @dev {desc}\n    function {fn}() public view {{\n        {stub}\n    }}"
        for fn, desc, stub in UNIVERSAL)

    out = f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {{Test}} from "forge-std/Test.sol";
// import {{{cname}}} from "../src/{os.path.basename(args.file)}";   // TODO: fix path

// AUTO-GENERATED invariant scaffold for {cname} (toolkit/scaffold.py).
// TODO: (1) deploy {cname} in setUp  (2) fund/approve actors  (3) fill invariants.

contract {cname}Handler is Test {{
    {cname} internal target;
    address[] internal _actors;

    constructor({cname} _t) {{
        target = _t;
        _actors.push(address(0xA11));
        _actors.push(address(0xB22));
        _actors.push(address(0xC33));
        // TODO: mint/approve tokens for each actor as the target requires
    }}

    function _actor(uint256 s) internal view returns (address) {{
        return _actors[s % _actors.length];
    }}

{chr(10).join(handlers)}
}}

contract {cname}Invariants is Test {{
    {cname} internal target;
    {cname}Handler internal handler;

    function setUp() public {{
        vm.warp(1_700_000_000);
        // target = new {cname}(/* TODO constructor args */);
        // TODO: initialize the target (proxy init, config, etc.)
        handler = new {cname}Handler(target);

        bytes4[] memory sel = new bytes4[]({len(fns)});
{selectors}
        targetContract(address(handler));
        targetSelector(FuzzSelector({{addr: address(handler), selectors: sel}}));
    }}

    // ===== universal invariants - FILL THESE for {cname} =====

{invs}
}}
'''
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        open(args.out, "w", encoding="utf-8").write(out)
        print(f"[scaffold written to {args.out}]  ({len(fns)} handlers, {len(UNIVERSAL)} invariants)")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
