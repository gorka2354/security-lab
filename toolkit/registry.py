#!/usr/bin/env python3
"""registry.py - auto-derived categorized inventory of every triaged target (Inc 1 of registry+radar).

PURE PROJECTION over what we already record:
  - toolkit/triage-ledger.json   (verdicts: target/file/detector/verdict/reason/date)
  - hunts/_fanout/*.md           (typed tables: target | type | chain | gate | fork/audit | rec | leads)
  - hunts/<target>/HUNT.md       (free-text deep logs -> live addresses, best-effort)

Data-model = cartography reconciliation: re-derive EVERY run, MERGE on a stable normalized key,
stamp firstseen / lastupdated / run_tag so the registry can never rot from hand-edits. One row per
protocol with category tags (zone / chains / fork-base), unified status, OWASP-SC vuln-class tags,
recorded addresses, and a reviewed-impl slot for radar.py to fill later.

    python toolkit/registry.py [--root .] [--date YYYY-MM-DD]

Outputs monitor/registry.json (machine) + monitor/REGISTRY.md (dashboard). Stdlib only.
"""

import argparse
import datetime
import glob
import json
import os
import re

# ---- category vocab ------------------------------------------------------------------------------
CHAINS = {  # token in free text -> canonical chain tag
    "ethereum": "eth", "eth": "eth", "mainnet": "eth", "base": "base", "arbitrum": "arb", "arb": "arb",
    "optimism": "op", "op": "op", "polygon": "polygon", "bsc": "bsc", "binance": "bsc", "linea": "linea",
    "fluent": "fluent", "monad": "monad", "abstract": "abstract", "sonic": "sonic", "mantle": "mantle",
    "zksync": "zksync", "katana": "katana", "sei": "sei", "hyperevm": "hyperevm", "hyperliquid": "hyperliquid",
    "blast": "blast", "scroll": "scroll", "avalanche": "avax", "fantom": "fantom", "fraxtal": "fraxtal",
    "bitcoin": "btc", "plasma": "plasma", "pharos": "pharos", "rise": "rise", "stellar": "stellar",
}
ZONES = ["lending", "lend", "borrow", "dex", "amm", "perp", "perps", "derivatives", "bridge", "crosschain",
         "vault", "rwa", "yield", "stablecoin", "stable", "cdp", "restaking", "staking", "stake", "oracle",
         "lottery", "gamefi", "gambling", "prediction", "nft", "index", "money market", "savings", "credit"]
ZONE_CANON = {"lend": "lending", "borrow": "lending", "perps": "perp", "derivatives": "perp", "stable": "stablecoin",
              "crosschain": "bridge", "amm": "dex", "stake": "staking", "money market": "lending"}
# fork bases we name in our notes (forkdrift / fanout / ledger reasons)
FORK_BASES = ["velodrome", "aave", "compound", "uniswap", "morpho", "euler", "lagoon", "usdt0", "hyperlane",
              "m^0", "balancer", "curve", "solidly", "liquity", "yearn", "venus", "slipstream", "comet"]

# detector key substring -> OWASP Smart Contract Top 10 (2025) class. Best-effort; multiple may apply.
OWASP = [
    (("init", "access", "auth", "owner", "trust_anchor", "caller", "sibling", "controller"), "SC01-AccessControl"),
    (("oracle", "spot", "price", "share_math", "pair_reserve", "vault_share"), "SC02-OracleManipulation"),
    (("supply", "math", "reward", "decimal", "scale", "rounding", "liq", "rebalance", "self_transfer", "mint"), "SC03-LogicError"),
    (("input", "validation"), "SC04-InputValidation"),
    (("reentr", "cei"), "SC05-Reentrancy"),
    (("lowlevel", "low-level", "unchecked-call", "external-call"), "SC06-UncheckedCall"),
    (("flashloan", "flash-loan"), "SC07-FlashLoan"),
    (("overflow", "underflow", "unchecked"), "SC08-IntegerOverflow"),
    (("random",), "SC09-BadRandomness"),
    (("dos", "freeze", "gas"), "SC10-DoS"),
]
# verdict/recommendation -> unified status + priority (higher wins when a target has many)
STATUS = {"real": ("REAL", 6), "dig": ("DIG", 5), "dig-careful": ("DIG", 5), "todo": ("DIG", 5),
          "park": ("PARK", 4), "known": ("CLEAN", 2), "wontfix": ("CLEAN", 2), "fp": ("CLEAN", 2),
          "skip": ("SKIP", 1)}


def norm_key(name):
    """Stable merge key: text before the first '(' or ' - ' separator, slugified. Merges the
    parenthetical-annotated duplicates ('Twyne (twyne-contracts-v1)') with their bare key ('twyne')."""
    s = str(name or "").split("(")[0].split(" - ")[0].split(" — ")[0]
    s = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
    return s or "unknown"


def display_name(name):
    return str(name or "").split("(")[0].split(" — ")[0].strip() or name


def _hits(text, vocab):
    t = (text or "").lower()
    out = []
    for w in vocab:
        if re.search(r"\b" + re.escape(w) + r"\b", t):
            out.append(w)
    return out


# chain tokens that are common English words -> only trust them from a structured chain column, not prose
AMBIGUOUS_CHAIN_WORDS = {"base", "op", "rise", "sonic"}


def extract_chains(text, structured=False):
    toks = _hits(text, list(CHAINS))
    if not structured:
        toks = [w for w in toks if w not in AMBIGUOUS_CHAIN_WORDS]
    return sorted({CHAINS[w] for w in toks if w in CHAINS})


def extract_zones(text):
    z = {ZONE_CANON.get(w, w) for w in _hits(text, ZONES)}
    return sorted(z)


def extract_fork(text):
    for b in FORK_BASES:
        if re.search(r"\b" + re.escape(b) + r"\b", (text or "").lower()):
            return b
    return None


def owasp_for(detector):
    d = (detector or "").lower()
    out = []
    for keys, code in OWASP:
        if any(k in d for k in keys):
            out.append(code)
    return out


# ---- source parsers ------------------------------------------------------------------------------
def parse_ledger(path):
    """Aggregate ledger entries per normalized target key."""
    agg = {}
    if not os.path.exists(path):
        return agg
    data = json.load(open(path, encoding="utf-8"))
    entries = data.get("entries", data) if isinstance(data, dict) else data
    for e in entries if isinstance(entries, list) else []:
        if not isinstance(e, dict):
            continue
        key = norm_key(e.get("target"))
        r = agg.setdefault(key, {"name": display_name(e.get("target")), "sources": set(), "zones": set(),
                                 "chains": set(), "fork": None, "owasp": set(), "status": ("?", 0),
                                 "n": 0, "reason": "", "dates": []})
        r["sources"].add("ledger")
        r["n"] += 1
        reason = e.get("reason", "") or ""
        blob = reason + " " + (e.get("snippet", "") or "") + " " + str(e.get("target", ""))
        r["zones"].update(extract_zones(blob))
        r["chains"].update(extract_chains(blob))
        r["fork"] = r["fork"] or extract_fork(blob)
        r["owasp"].update(owasp_for(e.get("detector")))
        st = STATUS.get((e.get("verdict") or "").lower())
        if st and st[1] > r["status"][1]:
            r["status"] = st
        if len(reason) > len(r["reason"]):
            r["reason"] = reason
        if e.get("date"):
            r["dates"].append(e["date"][:10])
        # source hints from the reason text
        for s in ("immunefi", "defillama", "fanout", "legacy", "contest", "abstract"):
            if s in blob.lower():
                r["sources"].add(s if s != "abstract" else "defillama")
    return agg


FANOUT_REC = {"dig": ("DIG", 5), "dig-careful": ("DIG", 5), "park": ("PARK", 4), "skip": ("SKIP", 1)}


def parse_fanout(glob_pat):
    """Parse the typed fan-out tables: | target | type | chain | gate | fork/audit | rec | leads |."""
    agg = {}
    for fp in sorted(glob.glob(glob_pat)):
        for line in open(fp, encoding="utf-8"):
            if not line.lstrip().startswith("|"):
                continue
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cells) < 6 or cells[0].lower() in ("target", "") or set(cells[0]) <= {"-", ":"}:
                continue
            name, typ, chain, gate, forka, rec = cells[0], cells[1], cells[2], cells[3], cells[4], cells[5]
            if rec.upper() not in ("DIG", "PARK", "SKIP", "DIG-CAREFUL"):
                continue
            key = norm_key(name)
            r = agg.setdefault(key, {"name": display_name(name), "sources": set(), "zones": set(),
                                     "chains": set(), "fork": None, "owasp": set(), "status": ("?", 0),
                                     "n": 0, "reason": "", "dates": []})
            r["sources"].add("fanout")
            r["zones"].update(extract_zones(typ + " " + name))
            r["chains"].update(extract_chains(chain, structured=True))
            r["fork"] = r["fork"] or extract_fork(forka + " " + name)
            st = FANOUT_REC.get(rec.lower())
            if st and st[1] > r["status"][1]:
                r["status"] = st
            # date from the filename (YYYY-MM-DD-...)
            m = re.search(r"(\d{4}-\d{2}-\d{2})", os.path.basename(fp))
            if m:
                r["dates"].append(m.group(1))
    return agg


def collect_addresses(hunts_dir):
    """Best-effort: live addresses per target from hunts/<target>/HUNT.md."""
    out = {}
    for md in glob.glob(os.path.join(hunts_dir, "*", "HUNT.md")):
        key = norm_key(os.path.basename(os.path.dirname(md)))
        addrs = set(re.findall(r"0x[a-fA-F0-9]{40}", open(md, encoding="utf-8", errors="replace").read()))
        if addrs:
            out[key] = sorted(addrs)[:12]
    return out


# ---- merge + emit --------------------------------------------------------------------------------
def merge(*aggs):
    keys = set().union(*[set(a) for a in aggs]) if aggs else set()
    merged = {}
    for k in keys:
        m = {"name": k, "sources": set(), "zones": set(), "chains": set(), "fork": None,
             "owasp": set(), "status": ("?", 0), "n": 0, "reason": "", "dates": []}
        for a in aggs:
            r = a.get(k)
            if not r:
                continue
            if len(display_name(r["name"])) >= len(display_name(m["name"])):
                m["name"] = r["name"]
            m["sources"] |= r["sources"]
            m["zones"] |= r["zones"]
            m["chains"] |= r["chains"]
            m["fork"] = m["fork"] or r["fork"]
            m["owasp"] |= r["owasp"]
            m["n"] += r["n"]
            if r["status"][1] > m["status"][1]:
                m["status"] = r["status"]
            if len(r["reason"]) > len(m["reason"]):
                m["reason"] = r["reason"]
            m["dates"] += r["dates"]
        merged[k] = m
    return merged


def query(root, text, status, zone, fork, chain, owasp):
    """Instant memory recall over monitor/registry.json — filter the triaged universe without re-deriving.
    All filters AND together; `text` is a free substring over name/zones/fork/last_reason. PURE-ish (reads json)."""
    reg = {}
    p = os.path.join(root, "monitor", "registry.json")
    if os.path.exists(p):
        reg = json.load(open(p, encoding="utf-8")).get("targets", {})
    if not reg:
        print("(no registry.json — run `python toolkit/registry.py` first)")
        return
    t = (text or "").lower()
    rows = []
    for v in reg.values():
        blob = (v["name"] + " " + " ".join(v.get("zones", [])) + " " + (v.get("fork_base") or "") + " "
                + (v.get("last_reason") or "")).lower()
        if t and t not in blob:
            continue
        if status and v.get("status", "").upper() != status.upper():
            continue
        if zone and zone.lower() not in [z.lower() for z in v.get("zones", [])]:
            continue
        if fork and (v.get("fork_base") or "").lower() != fork.lower():
            continue
        if chain and chain.lower() not in [c.lower() for c in v.get("chains", [])]:
            continue
        if owasp and not any(owasp.upper() in o.upper() for o in v.get("owasp_classes", [])):
            continue
        rows.append(v)
    rows.sort(key=lambda v: (STATUS_ORDER.get(v["status"], 9), v["key"]))
    print(f"# registry query -> {len(rows)} match(es)\n")
    for v in rows:
        z = ",".join(v.get("zones", [])[:3]) or "-"
        ch = ",".join(v.get("chains", [])[:2])
        fk = f" fork:{v['fork_base']}" if v.get("fork_base") else ""
        oc = " " + ",".join(x.split("-")[0] for x in v.get("owasp_classes", [])[:3]) if v.get("owasp_classes") else ""
        print(f"[{v['status']}] {v['name'][:36]:36} {z}{fk}{(' ('+ch+')') if ch else ''}{oc}")
        if v.get("last_reason"):
            print(f"      {v['last_reason'][:130]}")


def main():
    ap = argparse.ArgumentParser(description="Auto-derive (or --query) the categorized triaged-target registry")
    ap.add_argument("--root", default=os.path.join(os.path.dirname(__file__), ".."))
    ap.add_argument("--date", default=datetime.date.today().isoformat())
    ap.add_argument("--query", nargs="?", const="", metavar="TEXT",
                    help="recall mode: search the registry instead of rebuilding (free text + filters below)")
    ap.add_argument("--status"); ap.add_argument("--zone"); ap.add_argument("--fork")
    ap.add_argument("--chain"); ap.add_argument("--owasp")
    a = ap.parse_args()
    root = os.path.abspath(a.root)
    run_tag = a.date

    if a.query is not None or any([a.status, a.zone, a.fork, a.chain, a.owasp]):
        query(root, a.query, a.status, a.zone, a.fork, a.chain, a.owasp)
        return

    led = parse_ledger(os.path.join(root, "toolkit", "triage-ledger.json"))
    fan = parse_fanout(os.path.join(root, "hunts", "_fanout", "*.md"))
    addrs = collect_addresses(os.path.join(root, "hunts"))
    merged = merge(led, fan)

    # cartography reconciliation: preserve firstseen + reviewed_impl from a prior registry
    out_json = os.path.join(root, "monitor", "registry.json")
    prior = {}
    if os.path.exists(out_json):
        try:
            prior = json.load(open(out_json, encoding="utf-8")).get("targets", {})
        except Exception:
            prior = {}

    targets = {}
    for key, m in merged.items():
        dates = sorted(d for d in m["dates"] if d)
        p = prior.get(key, {})
        targets[key] = {
            "name": display_name(m["name"]),
            "key": key,
            "status": m["status"][0],
            "zones": sorted(m["zones"]),
            "chains": sorted(m["chains"]),
            "fork_base": m["fork"],
            "owasp_classes": sorted(m["owasp"]),
            "sources": sorted(m["sources"]),
            "addresses": addrs.get(key, p.get("addresses", [])),
            "reviewed_impl": p.get("reviewed_impl", {}),     # radar.py fills this
            "ledger_entries": m["n"],
            "last_reason": (m["reason"][:240]),
            "firstseen": p.get("firstseen") or (dates[0] if dates else run_tag),
            "lastupdated": dates[-1] if dates else run_tag,
            "run_tag": run_tag,
        }

    os.makedirs(os.path.dirname(out_json), exist_ok=True)
    json.dump({"generated": run_tag, "count": len(targets), "targets": targets},
              open(out_json, "w", encoding="utf-8"), indent=1, ensure_ascii=False, sort_keys=True)

    write_md(targets, run_tag, os.path.join(root, "monitor", "REGISTRY.md"))
    print(f"[registry] {len(targets)} targets -> {out_json} + monitor/REGISTRY.md")
    # quick console summary
    by_status = {}
    for t in targets.values():
        by_status[t["status"]] = by_status.get(t["status"], 0) + 1
    print("  by status:", ", ".join(f"{k}={v}" for k, v in sorted(by_status.items())))


STATUS_ORDER = {"REAL": 0, "DIG": 1, "PARK": 2, "CLEAN": 3, "SKIP": 4, "?": 5}


def write_md(targets, run_tag, path):
    rows = sorted(targets.values(), key=lambda t: (STATUS_ORDER.get(t["status"], 9), t["key"]))
    L = []
    L.append(f"# Target registry  ({len(targets)} triaged protocols)  -- generated {run_tag}")
    L.append("")
    L.append("> Auto-derived by `toolkit/registry.py` from the ledger + fan-out tables (+ HUNT addresses).")
    L.append("> Pure projection (re-derive every run; never hand-edit). `radar.py` watches the live + non-SKIP rows.")
    L.append("")
    by_status = {}
    for t in rows:
        by_status.setdefault(t["status"], []).append(t)
    L.append("## By status")
    for s in ("REAL", "DIG", "PARK", "CLEAN", "SKIP", "?"):
        if s in by_status:
            L.append(f"- **{s}**: {len(by_status[s])}")
    L.append("")
    # fork-base index (drives the batch fork-CVE re-scan)
    forks = {}
    for t in rows:
        if t["fork_base"]:
            forks.setdefault(t["fork_base"], []).append(t["name"])
    if forks:
        L.append("## Fork-base index  (one upstream CVE -> re-scan all of these)")
        for b, names in sorted(forks.items(), key=lambda kv: -len(kv[1])):
            L.append(f"- **{b}** ({len(names)}): {', '.join(sorted(set(names))[:14])}")
        L.append("")
    # radar shortlist
    live = [t for t in rows if t["status"] in ("DIG", "PARK", "REAL") or t["addresses"]]
    L.append(f"## Radar shortlist  (DIG/PARK/REAL or has live addresses): {len(live)}")
    L.append("")
    L.append("| status | target | zones | chains | fork-base | owasp | addrs | sources |")
    L.append("|---|---|---|---|---|---|---|---|")
    for t in live:
        L.append("| {s} | {n} | {z} | {c} | {f} | {o} | {a} | {src} |".format(
            s=t["status"], n=t["name"][:34], z=",".join(t["zones"][:3]) or "-", c=",".join(t["chains"][:3]) or "-",
            f=t["fork_base"] or "-", o=",".join(x.split("-")[0] for x in t["owasp_classes"][:3]) or "-",
            a=len(t["addresses"]) or "-", src=",".join(t["sources"][:3]) or "-"))
    L.append("")
    L.append("## Full inventory (by status)")
    L.append("")
    L.append("| status | target | zones | chains | fork-base | entries | first | last |")
    L.append("|---|---|---|---|---|---|---|---|")
    for t in rows:
        L.append("| {s} | {n} | {z} | {c} | {f} | {e} | {fs} | {ls} |".format(
            s=t["status"], n=t["name"][:34], z=",".join(t["zones"][:3]) or "-", c=",".join(t["chains"][:2]) or "-",
            f=t["fork_base"] or "-", e=t["ledger_entries"], fs=t["firstseen"], ls=t["lastupdated"]))
    open(path, "w", encoding="utf-8").write("\n".join(L) + "\n")


if __name__ == "__main__":
    main()
