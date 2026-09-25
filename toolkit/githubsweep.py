#!/usr/bin/env python3
"""githubsweep.py - automate the fresh-Solidity GitHub sweep (our #1 net-new SOURCE channel).

Our best findings (pmarket, pulso, Dealers.sh, heavy-helms) came from a MANUAL sweep of GitHub for
brand-new Solidity prediction-market / GameFi / vault repos - the ONLY channel that sees a two-person
team's contract repo on day 1, before it is on DefiLlama, in any audit-contest org, or on Immunefi.
This scripts it: union of repo-search + topic-search queries -> cheap metadata reject -> README/git-tree
substantiveness pass -> ledger-suppressed, ranked, scout-queue-style output.

    python toolkit/githubsweep.py                       # last 7d, top 25 -> hunts/_volume/scout-queue-github.md
    python toolkit/githubsweep.py --days 14 --top 40
    python toolkit/githubsweep.py --code-search         # opt-in source-grep layer (needs GITHUB_TOKEN)

Freshness IS the edge, so --days defaults small. Rank = freshness x our-zone keywords x deployed-signal
(a 0x address / a chain mention / broadcast+deployments artifacts). A repo that says "pre-audit /
pre-mainnet" with no address yet is routed to WATCH (radar), not hunted cold - catch its mainnet deploy
the week it happens (the highlow-contracts lesson).

GITHUB_TOKEN/GH_TOKEN (a free no-scope PAT) is optional but lifts search 10->30 req/min and unlocks the
code-search layer. Pure stdlib (urllib/json/re/datetime). ASCII output. White-hat: public data, read-only.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
import time
import urllib.parse
import tlsfix  # noqa: F401,E402  -- current CA bundle on stale-CA Windows hosts (see tlsfix.py)
import urllib.request

import ledger
import scout  # reuse: gh, WHEELHOUSE, SKIP_NAME, kw_hits, age_days, target_key, is_suppressed, LARGE_KB, lang_is_evm

# --- our finding classes, as GitHub topics (verified to return our exact class, e.g. topic:lmsr) ---
TOPICS = ["prediction-market", "lmsr", "gamefi", "onchain-game", "perpetuals", "perpetual",
          "amm", "vault", "defi", "options", "lending"]
# judged-hackathon submissions log real deployed addresses; rotate the year suffix over time.
HACK_TOPICS = ["ethglobal", "hackathon-2026", "devfolio", "keeperhub"]

# tutorials / boilerplate / toys that match a zone keyword but carry no huntable logic
TOY = re.compile(
    r"(?:tutorial|boilerplate|hardhat-|scaffold|course|learn(?:ing)?|hello-?world|todo|voting-?dapp|"
    r"nft-?mint|erc20-?token|starter|playground|whitepaper|awesome-|-bot\b|trading-?bot|arbitrage-?bot|"
    r"sample|demo-|-demo\b|cheatsheet|interview|roadmap|cookbook)", re.I)

ADDR_RE = re.compile(r"0x[0-9a-fA-F]{40}")
CHAIN_KW = re.compile(
    r"\b(mainnet|testnet|sepolia|base|arbitrum|optimism|polygon|bsc|bnb|blast|linea|scroll|abstract|"
    r"robinhood|mezo|rise|apechain|opbnb|monad|berachain|sonic|mantle|hyperevm|katana|amoy|arc)\b", re.I)
PREAUDIT = re.compile(
    r"(pre-?audit|un-?audited|not\s+\w{0,12}\s*audit|pre-?mainnet|audit\s+pending|no\s+audit|"
    r"audit-?ready|prior\s+to\s+mainnet)", re.I)
# wave-12 calibration: 4/7 top-scored candidates were testnet/faucet/hackathon (a deployed 0x != real value).
# A README that self-declares testnet/faucet/hackathon-only is $0-at-risk -> penalize so mainnet-funded ranks first.
TESTNET_ONLY = re.compile(
    r"\b(testnet|sepolia|amoy|holesky|goerli|faucet|devnet|hackathon|encode\s*club|ethglobal|"
    r"fresh-?uninitialized|not\s+\w{0,8}\s*activate|demo\s+only|mvp|proof[- ]of[- ]concept)\b", re.I)
# a real mainnet-value signal that outweighs a stray "testnet" mention in docs
MAINNET_VALUE = re.compile(r"\b(mainnet\s+deploy|deployed\s+to\s+mainnet|live\s+on\s+mainnet|production|TVL)\b", re.I)
ARTIFACT_RE = re.compile(r"(broadcast/.+/run-latest\.json|deployments/.+\.json|deployments\.json|\.s\.sol$)")
SOL_RE = re.compile(r"\.sol$")

# README chain word -> a chainid for the fetch_source hint (only the ones we can reach).
CHAIN_ID = {
    "base": 8453, "arbitrum": 42161, "optimism": 10, "polygon": 137, "bsc": 56, "bnb": 56,
    "blast": 81457, "linea": 59144, "scroll": 534352, "abstract": 2741, "monad": 143,
    "mezo": 31612, "sonic": 146, "mantle": 5000, "opbnb": 204, "amoy": 80002, "sepolia": 11155111,
    "hyperevm": 999, "apechain": 33139,
}
# non-EVM top language on a topic hit -> drop (topic queries can pull in Rust/Move/Cairo repos)
NON_EVM_LANGS = {"rust", "move", "cairo", "go", "c++", "python", "ruby", "haskell", "solidity-by-example"}
KEEP_LANGS = {"solidity", "vyper", "yul", "typescript", "javascript", None, ""}  # Foundry/Hardhat monorepos


# ----------------------------- pure logic (unit-tested, no network) -----------------------------

def is_toy(name, description):
    """A tutorial/boilerplate/bot repo that matches a zone keyword but has no huntable logic."""
    return bool(TOY.search((name or "") + " " + (description or "")))


def lang_ok(lang):
    """Keep Solidity/Vyper/Yul + JS/TS monorepos (Foundry/Hardhat); drop non-EVM engines."""
    l = (lang or "").lower()
    if l in NON_EVM_LANGS:
        return False
    return l in {x.lower() if isinstance(x, str) else x for x in KEEP_LANGS} or l in ("solidity", "vyper", "yul")


def readme_signals(text):
    """Extract deployed-signal facts from a README body. Pure -> testable."""
    text = text or ""
    m = ADDR_RE.search(text)
    ch = CHAIN_KW.search(text)
    return {
        "has_address": bool(m),
        "address": m.group(0) if m else "",
        "has_chain": bool(ch),
        "chain": (ch.group(1).lower() if ch else ""),
        "preaudit": bool(PREAUDIT.search(text)),
        # $0-at-risk unless a real mainnet-value signal overrides the testnet/faucet/hackathon self-label
        "testnet_only": bool(TESTNET_ONLY.search(text)) and not MAINNET_VALUE.search(text),
    }


def tree_signals(paths):
    """From a git-tree path list: deploy artifacts present + number of .sol contract files."""
    has_artifact = any(ARTIFACT_RE.search(p) for p in paths)
    sol_files = sum(1 for p in paths if SOL_RE.search(p))
    return {"has_artifact": has_artifact, "sol_files": sol_files}


def score_candidate(created, today, kw, sig, tree, size, source, is_toy_hit, min_size_kb):
    """Additive scout-style score. Freshness is the edge; a deployed 0x is the strongest substance signal."""
    s = max(0, 400 - scout.age_days(created, today))
    s += 60 * len(kw)
    s += 120 if sig.get("has_address") else 0
    s += 40 if sig.get("has_chain") else 0
    s += 30 if tree.get("has_artifact") else 0
    s += 4 * min(tree.get("sol_files", 0), 20)
    if source == "hackathon" and sig.get("has_address"):
        s += 80
    if is_toy_hit:
        s -= 200
    if size < min_size_kb:
        s -= 60
    # wave-12 calibration: a testnet/faucet/hackathon-only repo is $0-at-risk even with a deployed 0x.
    # Cancel the deployed-address bonus and push it below any real mainnet-funded candidate.
    if sig.get("testnet_only"):
        s -= 160
    return s


def route(sig):
    """Route by real-world value: testnet/faucet/pre-mainnet -> WATCH (radar, catch the mainnet deploy);
    a deployed+substantive repo on a value-bearing chain -> DIG."""
    if sig.get("testnet_only"):
        return "WATCH"
    if sig.get("preaudit") and not sig.get("has_address"):
        return "WATCH"
    return "DIG"


# ----------------------------- network layer -----------------------------

def _throttle():
    """Search is a single 10/min (unauth) or 30/min (token) bucket -> mirror fetch_source's Etherscan throttle."""
    time.sleep(2.5 if os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") else 7.0)


SEARCH_FAILED = []  # queries lost even after scout's rate-limit retry -> the queue is marked PARTIAL


def search_repos(q, per_page=50, sort="updated"):
    """One /search/repositories call -> (items, total). A failed call returns ([], None) AND is recorded in
    SEARCH_FAILED, so a lost query is reported as a coverage gap instead of passing for 'no results'."""
    url = ("https://api.github.com/search/repositories?q="
           + urllib.parse.quote(q) + f"&sort={sort}&order=desc&per_page={per_page}")
    d = scout.gh(url)  # attaches GITHUB_TOKEN/GH_TOKEN; waits out a per-minute search rate-limit once
    if not isinstance(d, dict):
        SEARCH_FAILED.append(q)
        return [], None
    return d.get("items", []) or [], d.get("total_count")


def raw_readme(full_name, branch):
    """README via the CDN (raw.githubusercontent.com) - separate from the search bucket, ~unlimited."""
    for fn in ("README.md", "readme.md", "README.MD", "Readme.md"):
        for br in ([branch] if branch else []) + ["main", "master"]:
            try:
                url = f"https://raw.githubusercontent.com/{full_name}/{br}/{fn}"
                req = urllib.request.Request(url, headers={"User-Agent": "security-lab-sweep"})
                with urllib.request.urlopen(req, timeout=20) as r:
                    if r.status == 200:
                        return r.read().decode("utf-8", "replace")
            except Exception:
                continue
    return ""


def git_tree(full_name, branch):
    """One core-REST git/trees call (separate 60/hr-unauth bucket). Returns path list (possibly truncated)."""
    d = scout.gh(f"https://api.github.com/repos/{full_name}/git/trees/{branch or 'main'}?recursive=1")
    if not isinstance(d, dict):
        return []
    return [t.get("path", "") for t in d.get("tree", []) if t.get("type") == "blob"]


def collect(days, topics, hack_topics, today, want_pushed=True):
    """Union of the query set -> deduped raw candidates (metadata only, no per-repo fetch yet)."""
    since = _since(today, days)
    seen, cands = set(), []

    def add(items, source):
        for r in items or []:
            fn = (r.get("full_name") or "").lower()
            if not fn or fn in seen:
                continue
            seen.add(fn)
            r["_source"] = source
            cands.append(r)

    # 1) organic fresh (created in window)
    items, tot = search_repos(f"language:Solidity created:>{since} fork:false", per_page=50)
    add(items, "organic")
    print(f"  [q1 organic] created:>{since} -> {tot} total, page {len(items)}", file=sys.stderr)
    _throttle()
    # 2) active-but-quiet (a stale repo that JUST got a deploy push; created: alone misses it)
    if want_pushed:
        items, tot = search_repos(f"language:Solidity pushed:>{since} stars:<3 fork:false", per_page=50)
        add(items, "pushed")
        print(f"  [q2 pushed]  pushed:>{since} stars:<3 -> {tot} total, page {len(items)}", file=sys.stderr)
        _throttle()
    # 3) topic precision (our finding classes)
    for t in topics:
        items, tot = search_repos(f"topic:{t} language:Solidity", per_page=30)
        add(items, f"topic:{t}")
        _throttle()
    # 4) hackathon tags (judged submissions log real addresses)
    for t in hack_topics:
        items, _ = search_repos(f"topic:{t} language:Solidity", per_page=30)
        add(items, "hackathon")
        _throttle()
    return cands


def _since(today, days):
    def ord_(s):
        return datetime.date(int(s[0:4]), int(s[5:7]), int(s[8:10]))
    return (ord_(today) - datetime.timedelta(days=days)).isoformat()


# ----------------------------- driver -----------------------------

def run(days, top, topics, hack_topics, max_fetch, min_size_kb, today, out, do_code_search):
    done = {e["target"].lower() for e in ledger.load().values()}
    seen_path = "monitor/githubsweep-seen.json"
    seen = _load(seen_path, {"full_names": []})
    seen_set = set(seen.get("full_names", []))
    first_run = not seen_set

    raw = collect(days, topics, hack_topics, today)
    print(f"  collected {len(raw)} unique repos across queries", file=sys.stderr)

    # cheap metadata pre-filter + pre-score (no extra HTTP)
    pre = []
    for r in raw:
        name = r.get("name", "")
        full = r.get("full_name", "")
        if r.get("fork") or r.get("archived"):
            continue
        if scout.SKIP_NAME.search(name):
            continue
        if not lang_ok(r.get("language")):
            continue
        key = scout.target_key(name)
        if scout.is_suppressed(key, done) or full.lower() in done:
            continue
        created = (r.get("created_at") or "")[:10]
        if not created:
            continue
        size = r.get("size", 0) or 0
        desc = r.get("description") or ""
        blob = (name + " " + desc + " " + " ".join(r.get("topics") or [])).lower()
        kw = scout.kw_hits(blob)
        toy = is_toy(name, desc)
        # pre-score without the fetched signals; used only to pick the top max_fetch to deep-check
        pre_s = max(0, 400 - scout.age_days(created, today)) + 60 * len(kw) - (200 if toy else 0) - (60 if size < min_size_kb else 0)
        pre.append({"r": r, "name": name, "full": full, "key": key, "created": created,
                    "size": size, "desc": desc, "kw": kw, "toy": toy, "pre_s": pre_s})

    pre.sort(key=lambda x: -x["pre_s"])
    print(f"  {len(pre)} survive cheap pre-filter; deep-checking top {min(max_fetch, len(pre))}", file=sys.stderr)

    # substantiveness pass (README + git-tree) only for the top max_fetch, to stay polite
    out_rows = []
    for c in pre[:max_fetch]:
        r = c["r"]
        branch = r.get("default_branch") or "main"
        readme = raw_readme(c["full"], branch)
        sig = readme_signals(readme)
        tree = tree_signals(git_tree(c["full"], branch)) if (sig["has_address"] or c["kw"]) else {"has_artifact": False, "sol_files": 0}
        kw2 = scout.kw_hits((c["name"] + " " + c["desc"] + " " + readme[:4000]).lower()) or c["kw"]
        s = score_candidate(c["created"], today, kw2, sig, tree, c["size"], r["_source"], c["toy"], min_size_kb)
        out_rows.append({**c, "sig": sig, "tree": tree, "kw": kw2, "score": s,
                         "route": route(sig), "source": r["_source"], "stars": r.get("stargazers_count", 0)})

    # the tail below max_fetch keeps its pre-score (metadata-only), so nothing is silently dropped
    for c in pre[max_fetch:]:
        out_rows.append({**c, "sig": {}, "tree": {}, "score": c["pre_s"],
                         "route": "DIG", "source": c["r"]["_source"], "stars": c["r"].get("stargazers_count", 0)})

    out_rows.sort(key=lambda x: -x["score"])
    new_rows = [x for x in out_rows if x["full"].lower() not in seen_set]

    if do_code_search:
        _code_search_note(out_rows[:top])

    if SEARCH_FAILED:
        print(f"  [PARTIAL] {len(SEARCH_FAILED)} search quer(ies) failed -> NOT covered this run: "
              + "; ".join(SEARCH_FAILED), file=sys.stderr)
    md = _render(out_rows[:top], today, len(done), days, failed=SEARCH_FAILED)
    with open(out, "w", encoding="utf-8") as f:
        f.write(md)
    print(_ascii(md))

    # advance the seen-set (novelty memory; the ledger stays the verdict memory)
    seen["full_names"] = sorted(seen_set | {x["full"].lower() for x in out_rows})
    _save(seen_path, seen)

    n_new = len(new_rows)
    print(f"\n[githubsweep] {len(out_rows)} candidates, {n_new} NEW since last run "
          f"({'first run - baseline seeded' if first_run else 'novelty vs seen-set'}). -> {out}", file=sys.stderr)
    return 10 if (n_new and not first_run) else 0


def _render(rows, today, n_done, days, failed=()):
    lines = ["# GitHub sweep queue",
             "",
             f"> Ref {today} (last {days}d). {len(rows)} candidates after ledger-suppression ({n_done} hunted).",
             "> Ranked by freshness x our-zone fit x deployed-signal (a 0x in the README/artifacts is the strongest).",
             "> Pick top -> clone -> recon+hypothesize (+ fetch_source <addr> if deployed). WATCH = pre-mainnet -> radar.",
             ""]
    if failed:
        lines[3:3] = [f"> **PARTIAL SWEEP: {len(failed)} search quer(ies) failed and were NOT covered** "
                      f"({'; '.join(failed)}) -- re-run; a GITHUB_TOKEN lifts search 10->30/min."]
    for x in rows:
        sig, tree = x.get("sig") or {}, x.get("tree") or {}
        large = "  [LARGE: verify fit]" if x["size"] > scout.LARGE_KB else ""
        zone = ",".join(x["kw"]) if x["kw"] else "-"
        lines.append(f"- **{x['full']}**  (github, created {x['created']}, {x['size']}KB, *{x['stars']}, "
                     f"src={x['source']}, score={x['score']}){large}  zone:{zone}")
        lines.append(f"    {x['desc'][:72]}")
        deployed = (f"deployed: {sig.get('address')} on {sig.get('chain') or '?'}" if sig.get("has_address")
                    else ("chain-mentioned" if sig.get("has_chain") else "no on-chain signal yet"))
        arts = "artifacts:" + (",".join(a for a, on in
                (("broadcast/deployments", tree.get("has_artifact")),) if on) or " -")
        lines.append(f"    {deployed}  |  {arts}  |  sol_files={tree.get('sol_files', '?')}  |  [{x['route']}]")
        lines.append(f"    `git clone --depth 1 https://github.com/{x['full']}.git hunts/_volume/{x['key']}`   # then recon+hypothesize")
        if sig.get("has_address"):
            cid = CHAIN_ID.get(sig.get("chain", ""), "")
            hint = f" --chain {cid}" if cid else ""
            lines.append(f"    `python toolkit/fetch_source.py {sig['address']}{hint} --proxy`   # live-first: fetch the deployed source")
        lines.append("")
    lines.append("---")
    lines.append("GitHub sweep = the day-1 net-new SOURCE channel (fresh 2-person repos before DefiLlama/Immunefi see them).")
    return "\n".join(lines)


def _code_search_note(rows):
    """Opt-in source-grep spot-check over the narrowed list (needs a token; separate 10/min bucket)."""
    if not (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")):
        print("  [code-search] skipped: needs GITHUB_TOKEN (code search has no unauth tier)", file=sys.stderr)
        return
    for c in rows[:8]:
        q = f'"totalSupply" extension:sol repo:{c["full"]}'
        d = scout.gh("https://api.github.com/search/code?q=" + urllib.parse.quote(q))
        n = d.get("total_count") if isinstance(d, dict) else "?"
        if n:
            print(f"  [code-search] {c['full']}: {n} totalSupply-in-.sol hits (share-math tell)", file=sys.stderr)
        time.sleep(6)


def _load(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _save(path, obj):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2)
    except Exception as e:
        print(f"  [warn] could not write {path}: {e}", file=sys.stderr)


def _ascii(s):
    """Console-safe rendering. The queue FILE stays UTF-8; stdout must be ASCII --
    GitHub descriptions carry em-dashes/emoji and a cp1251/cp866 console raises
    UnicodeEncodeError on print (repo convention: printed output is ASCII)."""
    return (s.replace("—", "--").replace("–", "-")
             .replace("‘", "'").replace("’", "'")
             .replace("“", '"').replace("”", '"')
             .replace("…", "...").replace(" ", " ")
             .encode("ascii", "replace").decode("ascii"))


def main():
    ap = argparse.ArgumentParser(description="Automate the fresh-Solidity GitHub sweep (day-1 SOURCE channel)")
    ap.add_argument("--days", type=int, default=7, help="freshness window (created/pushed within N days)")
    ap.add_argument("--top", type=int, default=25)
    ap.add_argument("--topics", default=",".join(TOPICS), help="comma-separated GitHub topics (our finding classes)")
    ap.add_argument("--hack-topics", default=",".join(HACK_TOPICS))
    ap.add_argument("--max-fetch", type=int, default=40, help="deep-check (README+tree) only the top N by pre-score")
    ap.add_argument("--min-size-kb", type=int, default=15)
    ap.add_argument("--code-search", action="store_true", help="opt-in source-grep spot-check (needs GITHUB_TOKEN)")
    ap.add_argument("--out", default="hunts/_volume/scout-queue-github.md")
    ap.add_argument("--today", default="")
    a = ap.parse_args()

    today = a.today or os.environ.get("SCOUT_TODAY") or datetime.date.today().isoformat()
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    rc = run(a.days, a.top, [t.strip() for t in a.topics.split(",") if t.strip()],
             [t.strip() for t in a.hack_topics.split(",") if t.strip()],
             a.max_fetch, a.min_size_kb, today, a.out, a.code_search)
    sys.exit(rc)


if __name__ == "__main__":
    main()
