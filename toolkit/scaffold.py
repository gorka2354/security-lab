#!/usr/bin/env python3
"""scaffold.py - generate an invariant/fuzz harness for a contract.

    python scaffold.py <path/to/Contract.sol> [ContractName] [--engine ENGINE] [--out PATH]

ENGINE (default `foundry`):
  foundry   one .t.sol  : Foundry invariant handler + targetSelector + universal-invariant stubs.
  chimera   a Recon-Fuzz "chimera" harness (Setup/Properties/TargetFunctions/CryticTester/
            CryticToFoundry + echidna.yaml + medusa.json). ONE harness runs under Foundry,
            Echidna AND Medusa - the cross-engine upgrade (Recon-Fuzz: protected $1B+ TVL).
  halmos    a `check_*` symbolic-execution suite (Halmos) - PROVE an invariant on ALL inputs,
            not sample them. For math cores where fuzzing may not hit the edge.
  all       chimera + halmos.

The L3 force-multiplier: writing the handler wiring by hand (a bounded wrapper for every
state-changing function, with actors/clamping) takes hours on a big contract. This auto-generates
that tedious 80%. You fill the 20%: deploy the target in setUp/setup and complete the invariants.

For chimera/halmos: with --out DIR the files are written there; without --out they are printed to
stdout with `// ==== FILE: name ====` banners (inspect first, write nothing by surprise).

Heuristic parser (regex, like recon.py) - expect to refine the output. ASCII.
"""

import argparse
import os
import re

# universal invariants worth checking on almost any protocol (stubs to fill).
# (name, human description, foundry-stub, bool-property-body for chimera/halmos)
UNIVERSAL = [
    ("solvency",
     "contract can always cover what it owes (balance >= obligations)",
     "// assertGe(token.balanceOf(address(target)), _totalOwed(), \"INSOLVENT\");",
     "// return token.balanceOf(address(target)) >= _totalOwed();"),
    ("supply_conservation",
     "no tokens minted from nothing (totalSupply backed)",
     "// assertLe(target.totalSupply(), _backing(), \"SUPPLY > BACKING\");",
     "// return target.totalSupply() <= _backing();"),
    ("no_free_value",
     "no actor can withdraw/redeem more value than they put in",
     "// for each actor: assertLe(valueOut[a], valueIn[a]);  // track in handler",
     "// for each actor: if (valueOut[a] > valueIn[a]) return false; (track in handlers)"),
    ("share_price_sane",
     "share price never jumps without a backing change / never zero",
     "// uint256 pps = target.convertToAssets(1e18); assertGt(pps, 0);",
     "// return target.convertToAssets(1e18) > 0;"),
    ("accounting_consistent",
     "sum of balances == totalSupply; per-user accounting matches globals",
     "// assertEq(_sumBalances(), target.totalSupply());",
     "// return _sumBalances() == target.totalSupply();"),
]

# three fuzzer-sender actors, shared by every engine (echidna.yaml `sender` + medusa senderAddresses
# use the SAME addresses, so msg.sender in a handler is always one of these).
ACTORS = ["0x0000000000000000000000000000000000010000",
          "0x0000000000000000000000000000000000020000",
          "0x0000000000000000000000000000000000030000"]


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


# ----------------------------------------------------------------------------- foundry engine
def gen_handler_fn(name, params, payable):
    """Generate one Foundry handler wrapper method (uses forge-std bound/prank/deal)."""
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


def emit_foundry(cname, file_base, fns):
    """Single-file Foundry invariant scaffold (original behavior). Returns {filename: content}."""
    handlers = [gen_handler_fn(n, p, pay) for n, p, pay in fns]
    selectors = "\n".join(
        f"        sel[{i}] = {cname}Handler.h_{n}.selector;" for i, (n, _, _) in enumerate(fns))
    invs = "\n\n".join(
        f"    /// @dev {desc}\n    function invariant_{fn}() public view {{\n        {stub}\n    }}"
        for fn, desc, stub, _ in UNIVERSAL)
    out = f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {{Test}} from "forge-std/Test.sol";
// import {{{cname}}} from "../src/{file_base}";   // TODO: fix path

// AUTO-GENERATED invariant scaffold for {cname} (toolkit/scaffold.py, engine=foundry).
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
    return {f"{cname}Invariants.t.sol": out}


# ----------------------------------------------------------------------------- chimera engine
def _clampable(base):
    """Full-width int we can clamp with `% 1e30` without a literal-type compile error."""
    return base in ("uint", "uint256", "int", "int256")


def gen_chimera_handler(name, params, payable):
    """One engine-PORTABLE handler: no vm/bound, msg.sender IS a fuzzer actor.

    Address params resolve to one of the configured actors so the harness compiles + runs
    identically under Foundry, Echidna and Medusa.
    """
    parsed = [categorize(p) for p in split_top_level(params)]
    has_addr = any(k == "addr" for k, _, _ in parsed)
    sig_params = []
    if has_addr:
        sig_params.append("uint256 _actorSeed")
    clamp, args, todos = [], [], []
    n = 0
    for kind, base, pname in parsed:
        if kind == "num":
            n += 1
            v = f"a{n}"
            sig_params.append(f"{base} {v}")
            if _clampable(base):
                clamp.append(f"        {v} = {v} % 1e30;")
            args.append(v)
        elif kind in ("fixed", "bool"):
            n += 1
            v = f"a{n}"
            sig_params.append(f"{base} {v}")
            args.append(v)
        elif kind == "addr":
            args.append("_actors[_actorSeed % _actors.length]")
        elif kind == "dynbytes":
            args.append('""')
        elif kind == "array":
            args.append(f"new {base.rstrip('[]')}[](0)")
            todos.append(f"refine array arg ({base} {pname})")
        else:
            args.append("/*TODO*/ 0")
            todos.append(f"refine arg ({base} {pname})")
    val = "{value: msg.value}" if payable else ""
    pay = " payable" if payable else ""
    lines = [f"    function h_{name}({', '.join(sig_params)}) public{pay} {{"]
    lines += clamp
    if todos:
        lines.append("        // TODO: " + "; ".join(todos))
    lines.append(f"        try target.{name}{val}({', '.join(args)}) {{}} catch {{}}")
    lines.append("    }")
    return "\n".join(lines)


def emit_chimera(cname, file_base, fns):
    """Recon-Fuzz chimera harness: ONE harness, three engines. Returns {filename: content}."""
    actors_push = "\n".join(f"        _actors.push(address({a}));" for a in ACTORS)
    handlers = "\n\n".join(gen_chimera_handler(n, p, pay) for n, p, pay in fns)
    props = "\n\n".join(
        f"    /// @dev {desc}\n    function property_{fn}() public view returns (bool) {{\n"
        f"        {body}\n        return true;\n    }}"
        for fn, desc, _, body in UNIVERSAL)
    selectors = "\n".join(
        f"        sel[{i}] = this.h_{n}.selector;" for i, (n, _, _) in enumerate(fns))
    invariants = "\n\n".join(
        f"    function invariant_{fn}() public {{\n        assertTrue(property_{fn}());\n    }}"
        for fn, _, _, _ in UNIVERSAL)
    sender_yaml = "\n".join(f'  - "{a}"' for a in ACTORS)
    sender_json = ", ".join(f'"{a}"' for a in ACTORS)

    setup = f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

// import {{{cname}}} from "../../src/{file_base}";   // TODO: fix path

// AUTO-GENERATED chimera harness for {cname} (toolkit/scaffold.py, engine=chimera).
// Shared deploy + actor set. setup() runs in BOTH the Foundry harness (CryticToFoundry.setUp)
// and the Echidna/Medusa harness (CryticTester ctor). The actors are also the fuzzer senders,
// so msg.sender in any handler is always one of them.
abstract contract Setup {{
    {cname} internal target;
    address[] internal _actors;

    function setup() internal virtual {{
{actors_push}
        // TODO: deploy the target  ->  target = new {cname}(/* ctor args */);
        // TODO: fund + approve each actor for the tokens {cname} needs.
    }}
}}
'''

    properties = f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {{Setup}} from "./Setup.sol";

// Universal invariants as bool-returning `property_*` (Echidna/Medusa property mode) - FILL THESE.
// CryticToFoundry wraps each one in an `invariant_*` for the Foundry fuzzer too.
abstract contract Properties is Setup {{
{props}
}}
'''

    target_functions = f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {{Properties}} from "./Properties.sol";

// Clamped, engine-portable handlers (no forge-std vm/bound -> compiles under all three engines).
abstract contract TargetFunctions is Properties {{
{handlers}
}}
'''

    crytic_tester = f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {{TargetFunctions}} from "./TargetFunctions.sol";

// Echidna / Medusa entrypoint.
//   echidna . --contract CryticTester --config echidna.yaml
//   medusa fuzz
contract CryticTester is TargetFunctions {{
    constructor() payable {{
        setup();
    }}
}}
'''

    crytic_to_foundry = f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {{Test}} from "forge-std/Test.sol";
import {{TargetFunctions}} from "./TargetFunctions.sol";

// Foundry entrypoint - runs the SAME setup/handlers/properties under `forge test`.
// Drop a found counterexample into test_repro() to debug it with -vvvv.
contract CryticToFoundry is Test, TargetFunctions {{
    function setUp() public {{
        setup();

        bytes4[] memory sel = new bytes4[]({len(fns)});
{selectors}
        targetContract(address(this));
        targetSelector(FuzzSelector({{addr: address(this), selectors: sel}}));
    }}

{invariants}

    // function test_repro() public {{ /* paste a CryticTester call-sequence here */ }}
}}
'''

    echidna_yaml = f'''# Echidna config for the {cname} chimera harness (toolkit/scaffold.py).
testMode: property
prefix: "property_"   # our invariants are property_* (not echidna's default echidna_ prefix)
testLimit: 50000
seqLen: 100
corpusDir: "echidna-corpus"
# the handlers' msg.sender is one of these (mirrors Setup._actors / medusa senderAddresses)
sender:
{sender_yaml}
# psender: the property-check sender. balanceContract: fund the tester if the target needs ETH.
# balanceContract: 1000000000000000000000
'''

    medusa_json = f'''{{
  "fuzzing": {{
    "testLimit": 50000,
    "callSequenceLength": 100,
    "deployerAddress": "{ACTORS[0]}",
    "senderAddresses": [{sender_json}],
    "targetContracts": ["CryticTester"],
    "corpusDirectory": "medusa-corpus"
  }},
  "testing": {{
    "propertyTesting": {{ "enabled": true, "testPrefixes": ["property_"] }},
    "assertionTesting": {{ "enabled": false }},
    "stopOnFailedTest": false
  }},
  "compilation": {{ "platform": "crytic-compile" }}
}}
'''

    return {
        "Setup.sol": setup,
        "Properties.sol": properties,
        "TargetFunctions.sol": target_functions,
        "CryticTester.sol": crytic_tester,
        "CryticToFoundry.sol": crytic_to_foundry,
        "echidna.yaml": echidna_yaml,
        "medusa.json": medusa_json,
    }


# ----------------------------------------------------------------------------- halmos engine
def gen_halmos_check(name, params):
    """One `check_*` symbolic test: args are symbolic, assert a universal property holds for ALL."""
    parsed = [categorize(p) for p in split_top_level(params)]
    sig, args, n = [], [], 0
    for kind, base, pname in parsed:
        if kind in ("num", "fixed", "bool"):
            n += 1
            v = f"a{n}"
            sig.append(f"{base} {v}")
            args.append(v)
        elif kind == "addr":
            n += 1
            v = f"a{n}"
            sig.append(f"address {v}")
            args.append(v)
        else:
            args.append("/*TODO sym*/ 0")
    lines = [f"    /// @custom:halmos prove a universal property holds after {name}() for ALL inputs",
             f"    function check_{name}({', '.join(sig)}) public {{"]
    lines.append(f"        try target.{name}({', '.join(args)}) {{}} catch {{ return; }}")
    lines.append("        // TODO: assert(token.balanceOf(address(target)) >= _totalOwed());")
    lines.append("    }")
    return "\n".join(lines)


def emit_halmos(cname, file_base, fns):
    """Symbolic-execution suite (Halmos). Returns {filename: content}."""
    checks = "\n\n".join(gen_halmos_check(n, p) for n, p, _ in fns)
    out = f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {{Test}} from "forge-std/Test.sol";
// import {{{cname}}} from "../src/{file_base}";   // TODO: fix path

// AUTO-GENERATED Halmos symbolic suite for {cname} (toolkit/scaffold.py, engine=halmos).
// Halmos makes every function argument SYMBOLIC and PROVES the assert for ALL inputs (not samples).
// Keep the constructor + setUp CONCRETE; only the check_ args are symbolic.
//   run:  halmos --contract {cname}Symbolic --function check_
contract {cname}Symbolic is Test {{
    {cname} internal target;

    function setUp() public {{
        // target = new {cname}(/* concrete ctor args */);
        // TODO: a concrete, minimal initial state (symbolic state explodes the solver).
    }}

{checks}
}}
'''
    return {f"{cname}Symbolic.t.sol": out}


# ----------------------------------------------------------------------------- driver
ENGINES = {"foundry": emit_foundry, "chimera": emit_chimera, "halmos": emit_halmos}


def build(engine, cname, file_base, fns):
    """Return {filename: content} for the requested engine ('all' merges chimera+halmos)."""
    if engine == "all":
        files = {}
        files.update(emit_chimera(cname, file_base, fns))
        files.update(emit_halmos(cname, file_base, fns))
        return files
    return ENGINES[engine](cname, file_base, fns)


def main():
    ap = argparse.ArgumentParser(description="Invariant/fuzz harness scaffolder (Foundry/Echidna/Medusa/Halmos)")
    ap.add_argument("file")
    ap.add_argument("contract", nargs="?", default=None)
    ap.add_argument("--engine", choices=["foundry", "chimera", "halmos", "all"], default="foundry")
    ap.add_argument("--out", help="file (foundry) or directory (chimera/halmos/all)")
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

    file_base = os.path.basename(args.file)
    files = build(args.engine, cname, file_base, fns)

    # foundry single-file keeps the original default: print the body, or write to --out file.
    if args.engine == "foundry":
        (name, content), = files.items()
        if args.out:
            os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
            open(args.out, "w", encoding="utf-8").write(content)
            print(f"[scaffold written to {args.out}]  ({len(fns)} handlers, {len(UNIVERSAL)} invariants)")
        else:
            print(content)
        return 0

    # multi-file engines: write into --out DIR, else print with file banners (write nothing).
    if args.out:
        os.makedirs(os.path.abspath(args.out), exist_ok=True)
        for name, content in files.items():
            open(os.path.join(args.out, name), "w", encoding="utf-8").write(content)
        print(f"[{args.engine} scaffold: {len(files)} files -> {args.out}]  "
              f"({len(fns)} handlers, {len(UNIVERSAL)} invariants)")
    else:
        for name, content in files.items():
            print(f"\n// ==== FILE: {name} ====")
            print(content)
        print(f"\n[{args.engine}: {len(files)} files above - rerun with --out DIR to write them]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
