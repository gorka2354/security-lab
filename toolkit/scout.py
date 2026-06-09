#!/usr/bin/env python3
"""scout.py - optimize Stage 0 (target sourcing), the hunter's bottleneck.

Two sources, one ranked queue (suppress already-hunted via the ledger, rank by our-fit):

  --source contests  : fresh PUBLIC audit-contest repos from GitHub orgs (sherlock-audit /
                       hats-finance). Reviewed-by-design -> good for learning/rep, low novel-bug odds.
  --source defillama : (scout v2) DEPLOYED-BUT-UNAUDITED protocols via DefiLlama /protocols --
                       low audit count x mid TVL x our-zone category. This is where novel bugs
                       actually live (the session-8-targets->0-findings lesson: contests are clean).
  --source both      : merge.

    python toolkit/scout.py --source defillama [--max-audits 1] [--tvl-min 1e6 --tvl-max 1.5e8]
    python toolkit/scout.py --source contests  [--orgs ...] [--days 150]

Output -> scout-queue.md. Discovery only. Contest hits get `git clone` lines; DefiLlama hits get
a `fetch_source.py <address>` starter (live-first: the deployed verified source by address) + the
project URL to locate the core contracts. Stdlib only (urllib + datetime; GITHUB_TOKEN env optional).
ASCII output.
"""

import argparse
import datetime
import json
import os
import re
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ledger  # same folder: skip already-hunted targets

# our zone -- a keyword in name/category/description bumps the fit score (where our detectors bite)
WHEELHOUSE = [
    "vault", "erc4626", "erc-4626", "stablecoin", "stable", "lend", "borrow", "oracle",
    "bridge", "cross-chain", "crosschain", "layerzero", "oft", "stake", "restake", "lrt",
    "lst", "perp", "dex", "amm", "yield", "collateral", "liquidat", "lending", "money-market",
    "game", "nft", "gamefi", "rwa", "savings", "redeem", "deposit", "queue",
]
# DefiLlama categories where our detectors/heuristics bite (bug-rich value logic)
DL_CATEGORIES = {
    "Lending", "CDP", "Yield", "Yield Aggregator", "Derivatives", "Liquid Staking",
    "Liquid Restaking", "RWA", "Algo-Stables", "Reserve Currency", "Gaming",
    "Prediction Market", "Leveraged Farming", "Options", "Insurance", "Synthetics",
}
# anti-fit: our regex engines are blind to heavily-assembly / huge codebases
LARGE_KB = 6000          # contest repo size over this -> flag "LARGE: verify fit (assembly/giant?)"
SKIP_NAME = re.compile(r"-judging$|template|example|test|report|docs?$|\.github$", re.I)


def gh(url):
    """GET the GitHub API; returns parsed JSON or None (graceful on rate-limit / network)."""
    req = urllib.request.Request(url, headers={
        "User-Agent": "security-lab-scout", "Accept": "application/vnd.github+json",
    })
    tok = os.environ.get("GITHUB_TOKEN")
    if tok:
        req.add_header("Authorization", f"Bearer {tok}")
    return _get(req)


def _get(req_or_url):
    req = req_or_url if isinstance(req_or_url, urllib.request.Request) else \
        urllib.request.Request(req_or_url, headers={"User-Agent": "security-lab-scout"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except Exception as e:
        print(f"  [warn] {getattr(req, 'full_url', req_or_url)}: {e}", file=sys.stderr)
        return None


def target_key(name):
    """Short target key: strip the trailing -0x.. hats hash and the sherlock `YYYY-MM-` date
    prefix. `2025-07-mellow-flexible-vaults` -> `mellow-flexible-vaults`; `dTRINITY-0x..` -> `dtrinity`."""
    k = re.sub(r"-0x[0-9a-fA-F]{6,}$", "", name)
    return re.sub(r"^\d{4}-\d{2}-", "", k).lower()


def org_repos(org, per_page=40):
    data = gh(f"https://api.github.com/orgs/{org}/repos?sort=created&direction=desc&per_page={per_page}")
    return data if isinstance(data, list) else []


def age_days(created_iso, now_iso):
    """Whole days between two ISO 'YYYY-MM-DD' strings (approximate day-ordinal; fine for thresholds)."""
    def ord_(s):
        y, m, d = int(s[0:4]), int(s[5:7]), int(s[8:10])
        return (y * 372) + (m * 31) + d
    return ord_(now_iso) - ord_(created_iso)


def unix_to_iso(unix):
    """Unix seconds -> 'YYYY-MM-DD' (UTC, deterministic). DefiLlama listedAt is unix."""
    try:
        return datetime.datetime.fromtimestamp(int(unix), datetime.timezone.utc).strftime("%Y-%m-%d")
    except Exception:
        return ""


# non-EVM chains -> our Solidity engines can't read them. Skip a protocol only if ALL its chains
# are non-EVM (a protocol on [Ethereum, Solana] is still huntable on the EVM side). Denylist (not
# allowlist) because new EVM L1/L2s appear constantly and are EVM by default.
NON_EVM = {c.lower() for c in [
    "Solana", "Sui", "Aptos", "Near", "Neutron", "Osmosis", "Cosmos", "Injective", "Sei",
    "Tron", "TON", "Stellar", "Cardano", "Bitcoin", "Stacks", "Starknet", "Algorand", "Hedera",
    "ICP", "Internet Computer", "Radix", "MultiversX", "Elrond", "Concordium", "Fuel", "Move",
    "Aptos", "Waves", "EOS", "Tezos", "Flow", "MASSA", "Fuel Ignition", "Cronos zkEVM",
    "Bittensor", "Polkadot", "Kava",
]}


def is_all_non_evm(chains):
    """True only if EVERY chain is known non-EVM -> not huntable by our tools."""
    cs = [str(c).lower() for c in (chains or [])]
    return bool(cs) and all(c in NON_EVM for c in cs)


def audits_int(audits):
    """DefiLlama `audits` is a stringy count ('0'/'1'/'2'); parse to int, default high (unknown=skip-ish)."""
    try:
        return int(str(audits).strip())
    except Exception:
        return 9


def is_suppressed(key, done):
    seg = key.split("-")[0]
    return key in done or (len(seg) > 2 and seg in done)   # >2 to avoid tiny-seg false hits


def kw_hits(blob):
    return sorted({k for k in WHEELHOUSE if k in blob})


# ── reachability (the post-scout-v2 bottleneck): a DefiLlama `address` is usually the GOV/UTILITY
# TOKEN, not the core mechanism (hit 3x: Usual ETH0, Lista RWA, Venus Flux all gave gov tokens).
# Fix: resolve the protocol's own GitHub CORE-contracts repo (clone the mechanism, not the token), and
# flag non-EVM langs early (Templar's `contracts` repo is Rust/NEAR -> our Solidity engines can't read it).
NON_EVM_LANGS = {"rust", "move", "cairo", "go", "c++", "python", "ruby", "haskell", "scala",
                 "clarity", "michelson", "motoko", "fc", "func", "teal"}
_CORE_POS = ("contract", "core", "protocol", "monorepo", "-v1", "-v2", "periphery", "vault", "lend",
             "perp", "pool", "engine", "money-market")
_CORE_NEG = ("frontend", "interface", " ui", "-ui", "ui-", "sdk", "docs", "doc-", "website", "webapp",
             "-site", "www", "indexer", "subgraph", "-bot", "-cli", "cli-", "-api", "backend", "server",
             "example", "template", "landing", "brand", "asset", "deploy", "script", "mock", "defillama",
             ".github", "audit", "whitepaper", "paper", "sdk-")


def lang_is_evm(lang):
    """A GitHub primary language compatible with our Solidity engines? Rust/Move/Cairo/... -> False
    (non-EVM, like Templar's NEAR contracts). TS/JS/None stay True (often a Foundry/Hardhat monorepo). PURE."""
    return (lang or "").strip().lower() not in NON_EVM_LANGS


def dl_github_orgs(p):
    """Extract GitHub org/user handles from a DefiLlama protocol record's `github` field
    (list | str | url | '@handle' | missing). Returns a clean list of handles. PURE."""
    g = p.get("github")
    if not g:
        return []
    items = g if isinstance(g, list) else [g]
    out = []
    for x in items:
        h = str(x).strip().rstrip("/").split("github.com/")[-1].lstrip("@").split("/")[0]
        if h:
            out.append(h)
    return out


def repo_core_score(repo, protocol_name):
    """Score a GitHub repo for 'is this the protocol's CORE contracts repo': + Solidity/contracts-y name,
    - frontend/sdk/docs/indexer noise, + name matches the protocol. archived -> rejected. PURE."""
    if repo.get("archived") or repo.get("fork"):
        return -999
    rn = (repo.get("name") or "").lower()
    desc = (repo.get("description") or "").lower()
    lang = (repo.get("language") or "")
    s = 0
    if lang == "Solidity":
        s += 50           # bonus breaks ties toward the EVM repo; non-EVM is FLAGGED in main, not penalized
    elif lang in ("Vyper", "Yul"):
        s += 40
    if any(k in rn for k in _CORE_NEG):
        s -= 40
    s += 12 * sum(1 for k in _CORE_POS if k in rn)
    if any(w in desc for w in ("smart contract", "contracts", "protocol", "money market", "lending", "vault")):
        s += 8
    slug = re.sub(r"[^a-z0-9]", "", (protocol_name or "").lower())
    if slug and (slug in re.sub(r"[^a-z0-9]", "", rn) or re.sub(r"[^a-z0-9]", "", rn) in slug):
        s += 10
    return s


def pick_core_repo(repos, protocol_name):
    """From a list of GitHub repo dicts, return the best CORE-contracts candidate (or None if none scores
    positive). PURE (no IO)."""
    best, bestsc = None, 0
    for r in (repos or []):
        sc = repo_core_score(r, protocol_name)
        if sc > bestsc:
            best, bestsc = r, sc
    return best


def resolve_core_repo(protocol_name, gh_orgs):
    """IO: across a protocol's GitHub org(s), find its core-contracts repo. Returns the repo dict or None.
    Bounded to the first 2 orgs (rate-limit friendly)."""
    pool = []
    for org in (gh_orgs or [])[:2]:
        pool += org_repos(org)
    return pick_core_repo(pool, protocol_name)


def defillama_protocols():
    d = _get("https://api.llama.fi/protocols")
    return d if isinstance(d, list) else []


def collect_defillama(done, tvl_min, tvl_max, max_audits, today):
    """scout v2: deployed-but-unaudited protocols. Low audit count x mid TVL x our-zone."""
    cands = []
    for p in defillama_protocols():
        cat = p.get("category") or ""
        if cat not in DL_CATEGORIES:
            continue
        tvl = p.get("tvl") or 0
        if tvl < tvl_min or tvl > tvl_max:
            continue
        aud = audits_int(p.get("audits"))
        if aud > max_audits:
            continue
        chains = p.get("chains") or []
        if is_all_non_evm(chains):              # Solidity engines can't read non-EVM
            continue
        name = p.get("name", "")
        key = (p.get("slug") or name).lower()
        if is_suppressed(key, done):
            continue
        listed = unix_to_iso(p.get("listedAt"))
        age = age_days(listed, today) if listed else 9999
        blob = (name + " " + cat + " " + (p.get("description") or "")).lower()
        kw = kw_hits(blob)
        addr = p.get("address") or ""
        # under-reviewed is the BIG signal; + freshness; + zone keywords; mid-TVL already filtered
        sc = (240 if aud == 0 else 90) + max(0, 365 - min(age, 365)) + 25 * len(kw)
        # fetch_source starter (live-first). address may be the token; the url -> docs -> core addrs.
        addr_clean = addr.split(":")[-1] if ":" in str(addr) else addr   # some are "chain:0x.."
        action = (f"`python toolkit/fetch_source.py {addr_clean} --proxy`   # then -> core contracts via {p.get('url','?')}"
                  if re.match(r"^0x[0-9a-fA-F]{40}$", str(addr_clean) or "")
                  else f"locate repo/addrs via {p.get('url','?')}  (DefiLlama has no github/address)")
        cands.append({
            "key": key, "name": name, "score": sc, "src": "defillama",
            "gh_orgs": dl_github_orgs(p),   # for core-repo resolution in main (reachability fix)
            "lines": [
                f"- **{name}**  (DefiLlama, {cat}, TVL ${tvl/1e6:.1f}M, audits={aud}, listed {listed or '?'})"
                + (f"  zone:{','.join(kw)}" if kw else "  zone:-"),
                f"    chains: {', '.join(chains[:5])}  | {(p.get('description') or '')[:70]}",
                f"    {action}",
            ],
        })
    return cands


# ── scout v3: Immunefi bug-bounty scope. Solves BOTH walls at once -- (1) reachability: a program's
# scope page lists the EXACT in-scope DEPLOYED addresses (not the gov token), and (2) scope/payout:
# in-scope + a real bounty is guaranteed (white-hat clean). The bounty LIST page embeds 210 program
# objects as escaped-JSON in the Next.js RSC stream -> parse name/slug/maxBounty/updated/tags. Filter to
# programType=Smart Contract + an EVM language (Solidity/Vyper) -> guaranteed-EVM contract scope.
IMMUNEFI_URL = "https://immunefi.com/bug-bounty/"
EVM_LANGS = {"solidity", "vyper", "yul"}


def _get_text(url):
    """GET raw text (the bounty list page is HTML, not JSON). Graceful on failure."""
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36"})
    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            return r.read().decode("utf-8", "replace")
    except Exception as e:
        print(f"  [warn] {url}: {e}", file=sys.stderr)
        return ""


def _imm_arr(tags_blob, key):
    """Extract an escaped-JSON string array (e.g. language/programType) from a program's tags blob. PURE."""
    m = re.search(r'\\"' + key + r'\\":\[([^\]]*)\]', tags_blob)
    return [s.lower() for s in re.findall(r'\\"([^"\\]+)\\"', m.group(1))] if m else []


def parse_immunefi_programs(html):
    """Parse the embedded program objects from the Immunefi bounty-list HTML (escaped-JSON in the RSC
    stream). Each object has exactly one of each field -> extract per field in document order and zip.
    Returns [{name, slug, maxBounty, updated, language[], programType[], projectType[], productType[]}]. PURE."""
    names = re.findall(r'\\"project\\":\\"((?:[^"\\]|\\.)*?)\\"', html)
    slugs = re.findall(r'\\"slug\\":\\"([^"\\]+)\\"', html)
    bounty = re.findall(r'\\"maxBounty\\":(\d+)', html)
    updated = re.findall(r'\\"updatedDate\\":\\"([^"\\]+)\\"', html)
    tags = re.findall(r'\\"tags\\":\{([^}]*)\}', html)
    launch = re.findall(r'\\"launchDate\\":\\"([^"\\]+)\\"', html)   # optional (freshness = under-hunted)
    n = min(len(names), len(slugs), len(bounty), len(updated), len(tags))
    out = []
    for i in range(n):
        out.append({
            "name": names[i], "slug": slugs[i], "maxBounty": int(bounty[i]), "updated": updated[i][:10],
            "launched": launch[i][:10] if i < len(launch) else "",
            "language": _imm_arr(tags[i], "language"), "programType": _imm_arr(tags[i], "programType"),
            "projectType": _imm_arr(tags[i], "projectType"), "productType": _imm_arr(tags[i], "productType"),
        })
    return out


def imm_is_evm_sc(prog):
    """Keep only programs we can actually hunt: a Smart-Contract program in an EVM language. PURE."""
    return ("smart contract" in prog.get("programType", [])
            and any(l in EVM_LANGS for l in prog.get("language", [])))


def collect_immunefi(done, today, min_bounty):
    """scout v3: Immunefi Smart-Contract bounties (EVM) -> exact in-scope addresses + guaranteed payout."""
    cands = []
    for p in parse_immunefi_programs(_get_text(IMMUNEFI_URL)):
        if not imm_is_evm_sc(p) or p["maxBounty"] < min_bounty:
            continue
        key = re.sub(r"[^a-z0-9]+", "-", p["name"].lower()).strip("-")
        if is_suppressed(key, done):
            continue
        zoneblob = (" ".join(p["projectType"] + p["productType"]) + " " + p["name"]).lower()
        kw = kw_hits(zoneblob)
        age = age_days(p["updated"], today) if p["updated"] else 9999
        launch_age = age_days(p["launched"], today) if p["launched"] else 9999
        lang = next((l for l in p["language"] if l in EVM_LANGS), "solidity")
        # EV != bounty size: huge bounties = the most-hunted/hardened giants (our wall). Rank by FRESHNESS
        # (recently launched/updated scope = under-hunted), modest bounty floor, our-zone fit. Big-name
        # giants (Aave/LayerZero) sink unless their scope was just refreshed.
        sc = (max(0, 220 - min(age, 220))                       # recently-UPDATED scope (new code in scope)
              + (120 if launch_age <= 150 else 0)               # NEWLY-LAUNCHED program = least-hunted
              + min(p["maxBounty"], 1_000_000) / 40_000          # bounty floor only (capped at 25 pts)
              + 25 * len(kw))
        fresh = "  [NEW PROGRAM]" if launch_age <= 150 else ""
        scope = f"https://immunefi.com/bug-bounty/{p['slug']}/scope/"
        cands.append({
            "key": key, "name": p["name"], "score": sc, "src": "immunefi",
            "lines": [
                f"- **{p['name']}**  (Immunefi, max ${p['maxBounty']/1e6:.2f}M, {lang}, "
                f"{'/'.join(p['productType'][:2]) or '-'}, launched {p['launched'] or '?'}, updated {p['updated'] or '?'}){fresh}"
                + (f"  zone:{','.join(kw)}" if kw else "  zone:-"),
                f"    IN-SCOPE addresses (exact, deployed) + rules at: {scope}",
                f"    # pull scope -> `fetch_source.py <in-scope addr> --proxy` -> forkdrift -> recon",
            ],
        })
    return cands


def collect_contests(orgs, days, done, today):
    """scout v1: fresh public audit-contest repos (reviewed-by-design)."""
    cands = []
    for org in orgs:
        for r in org_repos(org):
            name = r.get("name", "")
            if SKIP_NAME.search(name) or r.get("archived"):
                continue
            lang = r.get("language")
            if lang not in (None, "", "Solidity"):
                continue
            created = (r.get("created_at") or "")[:10]
            if not created or age_days(created, today) > days:
                continue
            key = target_key(name)
            if is_suppressed(key, done) or name.lower() in done:
                continue
            kw = kw_hits((name + " " + (r.get("description") or "")).lower())
            size = r.get("size", 0)
            sc = max(0, 400 - age_days(created, today)) + 60 * len(kw)
            big = "  [LARGE: verify fit - assembly/giant?]" if size > LARGE_KB else ""
            url = r.get("clone_url") or f"https://github.com/{org}/{name}.git"
            cands.append({
                "key": key, "name": name, "score": sc, "src": "contest",
                "lines": [
                    f"- **{name}**  ({org}, {created}, {lang or '?'}, {size}KB){big}"
                    + (f"  zone:{','.join(kw)}" if kw else "  zone:-"),
                    f"    {(r.get('description') or '')[:70]}",
                    f"    `git clone --depth 1 {url} hunts/_volume/{key}`",
                ],
            })
    return cands


def main():
    ap = argparse.ArgumentParser(description="Discover + rank Stage-0 targets (contests + deployed-but-unaudited)")
    ap.add_argument("--source", default="defillama", choices=["contests", "defillama", "immunefi", "both", "all"])
    ap.add_argument("--orgs", default="sherlock-audit,hats-finance")
    ap.add_argument("--min-bounty", type=float, default=50000, help="immunefi: skip programs with maxBounty < N USD")
    ap.add_argument("--days", type=int, default=150, help="contests: only repos created within N days")
    ap.add_argument("--tvl-min", type=float, default=1e6, help="defillama: min TVL (real protocol)")
    ap.add_argument("--tvl-max", type=float, default=1.5e8, help="defillama: max TVL (avoid over-combed giants)")
    ap.add_argument("--max-audits", type=int, default=1, help="defillama: keep protocols with <= N audits")
    ap.add_argument("--top", type=int, default=25)
    ap.add_argument("--resolve-top", type=int, default=12,
                    help="defillama: resolve the GitHub CORE-contracts repo for the top N candidates (reachability)")
    ap.add_argument("--today", default="")
    ap.add_argument("--out", default="hunts/_volume/scout-queue.md")
    a = ap.parse_args()

    today = a.today or os.environ.get("SCOUT_TODAY") or "2026-06-09"
    led = ledger.load()
    done = {e["target"].lower() for e in led.values()}

    cands = []
    if a.source in ("contests", "both", "all"):
        cands += collect_contests([o.strip() for o in a.orgs.split(",") if o.strip()], a.days, done, today)
    if a.source in ("defillama", "both", "all"):
        cands += collect_defillama(done, a.tvl_min, a.tvl_max, a.max_audits, today)
    if a.source in ("immunefi", "all"):
        cands += collect_immunefi(done, today, a.min_bounty)
    cands.sort(key=lambda c: -c["score"])

    # reachability: resolve the CORE-contracts GitHub repo for the top defillama candidates so we clone the
    # mechanism (not the gov token DefiLlama lists). Bounded to --resolve-top to respect GH rate limits.
    resolved = 0
    for c in cands[:a.top]:
        if c.get("src") != "defillama" or not c.get("gh_orgs") or resolved >= a.resolve_top:
            continue
        resolved += 1
        repo = resolve_core_repo(c["name"], c["gh_orgs"])
        if not repo:
            continue
        url = repo.get("clone_url") or f"https://github.com/{repo.get('full_name', '')}.git"
        lang = repo.get("language") or "?"
        flag = "" if lang_is_evm(lang) else f"  [!] {lang} = likely NON-EVM (our Solidity engines can't read it)"
        c["lines"][2] = (f"    `git clone --depth 1 {url} hunts/_volume/{c['key']}`"
                         f"  # CORE repo (DefiLlama github, {lang}){flag}")

    head = (f"# Scout queue (source={a.source})\n\nRef {today}. {len(cands)} candidates after "
            f"ledger-suppression ({len(done)} hunted).")
    if a.source in ("defillama", "both", "all"):
        head += (f" DefiLlama: audits<={a.max_audits}, TVL ${a.tvl_min/1e6:.0f}M-${a.tvl_max/1e6:.0f}M, "
                 f"our-zone categories.")
    if a.source in ("immunefi", "all"):
        head += f" Immunefi: Smart-Contract + EVM programs, maxBounty>=${a.min_bounty/1e3:.0f}k (exact in-scope addrs + payout)."
    out = [head, "Ranked by under-reviewed x freshness x our-fit. Pick top -> fetch_source/clone -> recon+hypothesize.\n"]
    if not cands:
        out.append("  (none -- relax --max-audits / TVL band, widen --days, or add a source)")
    for c in cands[:a.top]:
        out += c["lines"]
    out.append("\n---\nDefiLlama hits = DEPLOYED-BUT-UNAUDITED (where novel bugs live); verify in-scope/bounty "
               "+ that `address` is the CORE contract (often the token -> follow url/docs to the protocol). "
               "Contest hits = reviewed (learning/rep). LARGE may be assembly-heavy.")
    report = "\n".join(out)
    print(report)
    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        open(a.out, "w", encoding="utf-8").write(report)
        print(f"\n[written to {a.out}]")


if __name__ == "__main__":
    main()
