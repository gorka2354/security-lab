#!/usr/bin/env python3
"""dispatch.py - autonomous DYNAMIC-FUZZ confirm-or-kill loop.

Turns the mini-PC dynamic layer (toolkit/MINIPC-LANE.md) from a manual SSH tool into a pipeline stage:
select live in-scope targets from the registry -> dispatch a STRUCTURAL fork-fuzz campaign to the stand
(ityfuzz_lane.py over SSH) -> parse the result -> write a triage row to monitor/dispatch-log.json and, on a
hit, a ledger `todo` (a LEAD for human Gate-0 verification -- never an auto-`real`; the researcher discloses).

    python toolkit/dispatch.py sweep --max 4 --timeout 240 [--dry-run] [--force] [--status DIG,REAL]
    python toolkit/dispatch.py one <target-key> --timeout 300
    python toolkit/dispatch.py log [--n 20]

White-hat: fork-only, read-only, in-scope, EVM-only (skips non-EVM chains e.g. Abstract/zkSync). Token-cheap:
the fuzz is the stand's compute; the LLM only triages the log. Pure core (SSH runner injectable) -> golden-tested.
Stdlib only. ASCII output.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ityfuzz_lane as L  # noqa: E402  (reuse CHAIN + the lane's JSON contract)
import ledger  # noqa: E402
import defillama as _dl  # noqa: E402  (reach-chaining: resolve real addrs from the TVL adapter)

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY = os.path.join(_ROOT, "monitor", "registry.json")
DISPATCH_LOG = os.path.join(_ROOT, "monitor", "dispatch-log.json")
SSH_HOST = os.environ.get("SECLAB_STAND", "egor@100.81.218.50")
EVM_FUZZ_CHAINS = set(L.CHAIN)  # chain NAMES ityfuzz supports (eth/bsc/polygon/arbitrum/base/optimism/...)
RECENT_DAYS = 14
_ADDR = re.compile(r"^0x[a-fA-F0-9]{40}$")
_ZERO = "0x" + "0" * 40


def _today(s=None):
    return s or datetime.date.today().isoformat()


def load_registry(path=REGISTRY):
    with open(path, encoding="utf-8") as f:
        return json.load(f).get("targets", {})


def load_log(path=DISPATCH_LOG):
    if not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def save_log(rows, path=DISPATCH_LOG):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=1)


def recently_fuzzed(log, key, today, days=RECENT_DAYS):
    """True if `key` has a dispatch-log row within `days` of `today` (skip -> don't re-fuzz)."""
    cut = datetime.date.fromisoformat(today) - datetime.timedelta(days=days)
    for r in log or []:
        if r.get("key") == key:
            try:
                if datetime.date.fromisoformat(r.get("ts", "")[:10]) >= cut:
                    return True
            except Exception:
                continue
    return False


def pick_address(t):
    """The core address to fuzz: a reviewed_impl impl if present, else addresses[0]. Skips the zero addr."""
    ri = t.get("reviewed_impl") or {}
    for v in ri.values():
        v = v.get("impl") if isinstance(v, dict) else v
        if isinstance(v, str) and _ADDR.match(v) and v.lower() != _ZERO:
            return v
    for a in (t.get("addresses") or []):
        if isinstance(a, str) and _ADDR.match(a) and a.lower() != _ZERO:
            return a
    return None


def pick_chain(t, allow=None):
    """First EVM-fuzzable chain of the target (intersected with `allow` if given)."""
    for c in (t.get("chains") or []):
        cl = str(c).lower()
        if cl in EVM_FUZZ_CHAINS and (allow is None or cl in allow):
            return cl
    return None


# --- REACH-CHAINING: resolve an address for address-less targets so the loop has more to fuzz ---
_KEY_ADDR = re.compile(r"0x[a-fA-F0-9]{40}")


def resolve_from_key(key):
    """Some target keys embed the address (e.g. 'krystal-community-vault-0xff63..'). Pure, high-precision."""
    m = _KEY_ADDR.search(key or "")
    a = m.group(0) if m else None
    return a if (a and a.lower() != _ZERO) else None


def resolve_from_defillama(key, _addrs=None):
    """(addr, chain) of the first EVM-fuzzable contract in the target's DefiLlama TVL adapter, else None.
    _addrs injectable (defillama.addrs) for tests."""
    fn = _addrs or _dl.addrs
    try:
        res = fn(key)
    except Exception:
        return None
    for chain, al in (res or {}).items():
        cl = str(chain).lower()
        if cl in EVM_FUZZ_CHAINS and al:
            return (al[0], cl)
    return None


def resolve_address(key, target, _addrs=None):
    """Best-effort (addr, chain) for an address-less target: address-in-key first, then the DefiLlama adapter.
    For address-in-key the chain is the target's first EVM chain (a guess; a wrong chain -> ityfuzz fails to
    fetch -> `error` via the execs guard, never a silent false-clean)."""
    a = resolve_from_key(key)
    if a:
        ch = pick_chain(target) or "eth"
        return (a, ch)
    return resolve_from_defillama(key, _addrs=_addrs)


def enrich(targets, reach=True, statuses=("DIG", "REAL"), _addrs=None):
    """Return a copy of `targets` with addresses filled in for address-less DIG/REAL targets (network). The
    registry itself is NOT mutated (labcore owns it); resolution is per-run + recorded via dispatch-log."""
    if not reach:
        return targets
    out = dict(targets)
    for k, t in targets.items():
        if t.get("status") in statuses and not t.get("addresses"):
            r = resolve_address(k, t, _addrs=_addrs)
            if r:
                addr, ch = r
                t2 = dict(t)
                t2["addresses"] = [addr]
                if ch not in [str(c).lower() for c in (t.get("chains") or [])]:
                    t2["chains"] = [ch] + list(t.get("chains") or [])
                out[k] = t2
    return out


def select_targets(targets, statuses=("DIG", "REAL"), chains=None, limit=None, log=None, force=False, today=None):
    """Pick actionable live EVM targets (status + address + EVM chain + not-recently-fuzzed). Pure."""
    today = _today(today)
    out = []
    for key in sorted(targets):
        t = targets[key]
        if t.get("status") not in statuses:
            continue
        addr = pick_address(t)
        if not addr:
            continue
        ch = pick_chain(t, allow=chains)
        if not ch:
            continue
        if log is not None and not force and recently_fuzzed(log, key, today):
            continue
        out.append({"key": key, "name": t.get("name", key), "status": t.get("status"),
                    "address": addr, "chain": ch})
        if limit and len(out) >= limit:
            break
    return out


def build_remote_cmd(address, chain, timeout, repo="~/security-lab"):
    """The bash the stand runs: PATH + env + the structural fork-fuzz lane. Pure -> testable."""
    return ('export PATH="$HOME/.ityfuzz/bin:$HOME/.foundry/bin:$HOME/.local/bin:$PATH"; '
            "source ~/.seclab_env; cd %s; "
            "python3 toolkit/ityfuzz_lane.py %s --chain %s --timeout %d" % (repo, address, chain, int(timeout)))


def build_ssh(remote_cmd, host=SSH_HOST):
    return ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", host, remote_cmd]


def parse_remote(stdout):
    """Extract the ityfuzz_lane JSON result block from the campaign stdout. Pure."""
    if not stdout:
        return None
    m = re.search(r"\{[\s\S]*\}", stdout)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        return None


MIN_EXECS = 500  # below this the "campaign" never really ran (early ityfuzz panic / unreachable / non-EVM addr)


def interpret(result):
    """result (ityfuzz_lane JSON) -> {state: lead|clean|error, n_signals, summary}. Pure.
    A found bug -> lead. ok + real execs + 0 signals -> clean. ok but ~0 execs -> error (a FALSE clean: the
    campaign didn't run -- a panicked/unreachable target must NOT read as 'fuzzed clean')."""
    if not result or not result.get("ok"):
        why = (result or {}).get("error") or "no/invalid campaign output"
        return {"state": "error", "n_signals": 0, "summary": why}
    if result.get("found"):
        return {"state": "lead", "n_signals": int(result.get("n_signals", 0) or 0),
                "summary": "; ".join((result.get("markers") or [])[:3]) or "signal"}
    execs = int(result.get("execs", 0) or 0)
    if execs < MIN_EXECS:
        return {"state": "error", "n_signals": 0,
                "summary": "campaign did not run (execs=%d; likely ityfuzz panic / unreachable / non-EVM)" % execs}
    return {"state": "clean", "n_signals": 0, "summary": "0 objectives in %d execs" % execs}


def run_one(tgt, timeout, host=SSH_HOST, _runner=subprocess.run):
    """Dispatch one target to the stand, return the interpreted row. _runner injectable for tests."""
    cmd = build_ssh(build_remote_cmd(tgt["address"], tgt["chain"], timeout), host=host)
    out = ""
    try:
        p = _runner(cmd, capture_output=True, text=True, timeout=timeout + 150)
        out = (p.stdout or "") + "\n" + (p.stderr or "")
    except subprocess.TimeoutExpired as e:
        so = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        se = e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
        out = so + "\n" + se
    except Exception as e:
        return {**tgt, "state": "error", "n_signals": 0, "summary": str(e)[:140], "raw": None}
    res = parse_remote(out)
    return {**tgt, **interpret(res), "raw": res}


def record(row, today=None, log_path=DISPATCH_LOG, ledger_path=None, write_ledger=True):
    """Append the row to the dispatch-log; on a LEAD also add a ledger `todo` (for human Gate-0 verify)."""
    today = _today(today)
    log = load_log(log_path)
    log.append({"key": row["key"], "name": row.get("name"), "address": row["address"], "chain": row["chain"],
                "ts": today, "state": row["state"], "n_signals": row.get("n_signals", 0),
                "summary": row.get("summary", "")[:200]})
    save_log(log, log_path)
    if write_ledger and row["state"] == "lead":
        kw = {"path": ledger_path} if ledger_path else {}
        ledger.add(row["key"], "ityfuzz-fork", 0, "dynfuzz", (row.get("summary") or "")[:80], "todo",
                   "[dynfuzz] ityfuzz surfaced %d signal(s): %s -> HUMAN Gate-0 verify (live+in-scope+callable) "
                   "before any claim; the researcher discloses" % (row.get("n_signals", 0), row.get("summary", "")),
                   today, **kw)
    return log


def sweep(args):
    targets = load_registry()
    if getattr(args, "reach", False):
        before = sum(1 for t in targets.values() if t.get("status") in ("DIG", "REAL") and t.get("addresses"))
        targets = enrich(targets, reach=True)
        after = sum(1 for t in targets.values() if t.get("status") in ("DIG", "REAL") and t.get("addresses"))
        print("[reach] resolved %d address-less target(s) via key/DefiLlama (addressed: %d -> %d)"
              % (after - before, before, after))
    log = load_log()
    statuses = tuple(s.strip().upper() for s in args.status.split(",")) if args.status else ("DIG", "REAL")
    chains = set(c.strip().lower() for c in args.chains.split(",")) if args.chains else None
    picks = select_targets(targets, statuses=statuses, chains=chains, limit=args.max, log=log, force=args.force)
    print("== dispatch sweep: %d target(s) [status=%s chains=%s max=%s] ==" % (
        len(picks), ",".join(statuses), ",".join(sorted(chains)) if chains else "EVM", args.max))
    for p in picks:
        print("  [%s] %-26s %s @ %s" % (p["status"], p["name"], p["address"], p["chain"]))
    if not picks:
        print("  (nothing to fuzz -- most DIG/REAL targets lack a resolved address; run reach first)")
        return
    if args.dry_run:
        print("\n-- DRY RUN: remote command for the first target --")
        print("  ssh %s '%s'" % (SSH_HOST, build_remote_cmd(picks[0]["address"], picks[0]["chain"], args.timeout)))
        return
    leads = 0
    for i, p in enumerate(picks, 1):
        print("\n[%d/%d] fuzzing %s (%s @ %s) for %ds ..." % (i, len(picks), p["name"], p["address"], p["chain"],
                                                             args.timeout))
        row = run_one(p, args.timeout)
        record(row)
        mark = {"lead": ">>> LEAD", "clean": "clean", "error": "ERR "}.get(row["state"], row["state"])
        print("   %s | %s" % (mark, row.get("summary", "")))
        leads += row["state"] == "lead"
    print("\n== done: %d target(s), %d lead(s) -> monitor/dispatch-log.json (leads also in ledger as `todo`) ==" % (
        len(picks), leads))


def cmd_one(args):
    targets = load_registry()
    if args.target not in targets:
        print("no such target key: %s" % args.target)
        return
    t = targets[args.target]
    addr = pick_address(t)
    ch = pick_chain(t)
    if not addr or not ch:
        print("target %s not fuzzable (addr=%s chain=%s -- need a resolved EVM address)" % (args.target, addr, ch))
        return
    p = {"key": args.target, "name": t.get("name", args.target), "status": t.get("status"), "address": addr, "chain": ch}
    print("== dispatch one: %s (%s @ %s) for %ds ==" % (p["name"], addr, ch, args.timeout))
    row = run_one(p, args.timeout)
    record(row)
    print(json.dumps({k: row[k] for k in ("state", "n_signals", "summary")}, indent=1))


def cmd_resolve(args):
    """Preview reach-chaining: which address-less DIG/REAL targets get a resolved address (no fuzz)."""
    targets = load_registry()
    rows = []
    for k in sorted(targets):
        t = targets[k]
        if t.get("status") in ("DIG", "REAL") and not t.get("addresses"):
            r = resolve_address(k, t)
            if r:
                rows.append((k, r[0], r[1]))
    print("== reach-chaining preview: %d address-less target(s) now resolvable ==" % len(rows))
    for k, a, ch in rows:
        print("  %-40s -> %s @ %s%s" % (k[:40], a, ch, "" if ch in EVM_FUZZ_CHAINS else "  (non-EVM, skipped)"))


def cmd_log(args):
    log = load_log()
    for r in log[-args.n:]:
        print("  %s [%s] %-24s %s @ %s | %s" % (r.get("ts"), r.get("state"), r.get("name"), r.get("address"),
                                                r.get("chain"), r.get("summary", "")[:80]))
    if not log:
        print("  (dispatch-log empty)")


def main():
    ap = argparse.ArgumentParser(description="Autonomous dynamic-fuzz confirm-or-kill loop (dispatch to the stand)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sw = sub.add_parser("sweep")
    sw.add_argument("--status", default="DIG,REAL")
    sw.add_argument("--chains", default=None, help="restrict to e.g. eth,bsc (default: all EVM ityfuzz chains)")
    sw.add_argument("--timeout", type=int, default=240)
    sw.add_argument("--max", type=int, default=8)
    sw.add_argument("--dry-run", action="store_true")
    sw.add_argument("--force", action="store_true", help="re-fuzz even if fuzzed within %d days" % RECENT_DAYS)
    sw.add_argument("--reach", action="store_true",
                    help="reach-chaining: resolve addresses (key/DefiLlama) for address-less targets first")
    sw.set_defaults(func=sweep)
    rs = sub.add_parser("resolve")
    rs.set_defaults(func=cmd_resolve)
    on = sub.add_parser("one")
    on.add_argument("target")
    on.add_argument("--timeout", type=int, default=300)
    on.set_defaults(func=cmd_one)
    lg = sub.add_parser("log")
    lg.add_argument("--n", type=int, default=20)
    lg.set_defaults(func=cmd_log)
    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
