#!/usr/bin/env python3
"""forkdrift.py - is this deployed target a FORK of a known-audited base, and is it version-behind?

Lesson (RockSolid / Usual ETH0 sessions): scout v2's actionable (fetchable-source) candidates trend
toward FORKS of audited code (RockSolid = Lagoon v0.5.0; Usual ETH0 = audited USD0/DaoCollateral).
A fork's audited core is NOT where findings live - the win condition is **drift**:
  (a) CUSTOM modifications the fork made to the base   -> hunt these directly, and
  (b) a VERSION-LAG patch the fork is missing          -> check if it applies to the LIVE config.
So for a fork, drift-diff should be STEP 1, not step 5. This tool makes it step 1.

    python toolkit/forkdrift.py fingerprint <src_dir>          # which audited base? which version? plan.
    python toolkit/forkdrift.py diff <target_dir> <canon_dir>  # normalized SUBSTANTIVE diff (no cosmetics)

`diff` normalizes line endings + whitespace BEFORE comparing, so CRLF (Etherscan/Sourcify) vs LF and
pure-formatting reflows vanish -> what remains is real logic drift (the whitelist-hardening delta, etc.).
ASCII output. Stdlib only (difflib). Pure functions (fingerprint/detect_version/substantive_diff) are
unit-tested in tests/test_detectors.py.
"""

import argparse
import difflib
import os
import re

# ---------------------------------------------------------------------------
# Known-audited bases. A fork inherits the base's audit; findings live in DRIFT.
# `sigs` = distinctive substrings (case-insensitive) that fingerprint the base. CRITICAL: use
#   IMPLEMENTATION-INTERNAL markers (storage-namespace strings, internal library/function names),
#   NOT interface method names -- an integrator that merely CALLS Aave/Compound has the interface
#   names too, and would be mis-flagged as a fork (Ledgity FP). Internals exist only if you ARE the fork.
# `min` = sigs required to declare a fork (1 for a unique storage namespace; 2+ for broader bases).
# `repo` = canonical source to diff against (clone it, then `forkdrift.py diff`).
# ---------------------------------------------------------------------------
BASES = [
    {
        "name": "Lagoon / Hopper (ERC-7540 async vault)",
        "repo": "https://github.com/hopperlabsxyz/lagoon-v0",
        "min": 1,  # erc7201:hopper.storage is an impl-internal namespace -> 1 hit is conclusive
        "sigs": ["erc7201:hopper.storage", "hopper.storage.vault", "hopper.storage.erc7540",
                 "hopper.storage.feemanager", "hopperlabs.xyz"],
    },
    {
        "name": "M^0 MExtension (M token wrapper / yield-extension framework)",
        "repo": "https://github.com/m0-foundation/m-extensions",
        "min": 1,  # erc7201:M0.storage is the M^0 framework's impl-internal namespace
        "sigs": ["erc7201:m0.storage", "m0.storage.myieldtoone", "m0.storage.freezable",
                 "imtokenlike", "swapfacility"],
    },
    {
        "name": "Compound v2 / Venus (cToken money market)",
        "repo": "https://github.com/compound-finance/compound-protocol (or VenusProtocol/venus-protocol)",
        "min": 2,
        # impl internals (the *fresh helpers + accrual), not the IComptroller interface an integrator calls
        "sigs": ["redeemfresh", "mintfresh", "borrowfresh", "repayborrowfresh", "seizeinternal",
                 "exchangeratestoredinternal", "comptrollerinterface", "ctokenstorage"],
    },
    {
        "name": "Liquity (CDP / stablecoin trove)",
        "repo": "https://github.com/liquity/dev (or liquity/bold)",
        "min": 2,
        "sigs": ["trovemanager", "borroweroperations", "_redistributedebtandcoll", "sortedtroves",
                 "_movependingtrovereward", "getentiredebtandcoll", "l_eth", "l_lusddebt"],
    },
    {
        "name": "Aave v3 (pool / reserve money market)",
        "repo": "https://github.com/aave-dao/aave-v3-origin",
        "min": 2,
        # impl-internal logic libraries + execute* internals; an INTEGRATOR only has IPool/getReserveData
        "sigs": ["supplylogic", "borrowlogic", "liquidationlogic", "reservelogic.", "executesupply",
                 "executeborrow", "executeliquidationcall", "_reserves[", "validationlogic"],
    },
    {
        "name": "Morpho (Blue / MetaMorpho)",
        "repo": "https://github.com/morpho-org/morpho-blue",
        "min": 2,
        "sigs": ["_accrueinterest", "marketparams", "idtomarketparams", "_ishealthy", "supplyshares",
                 "borrowshares", "lastupdate", "metamorpho"],
    },
    {
        "name": "Solmate / Solady ERC4626 (lightweight vault)",
        "repo": "https://github.com/transmissions11/solmate (or Vectorized/solady)",
        "min": 1,
        "sigs": ["transmissions11/solmate", "vectorized/solady"],
    },
    {
        "name": "Lido wstETH-style rebasing wrapper",
        "repo": "https://github.com/lidofinance/lido-dao",
        "min": 2,
        "sigs": ["getpooledethbyshares", "getsharesbypooledeth", "_submit(", "depositbufferedether",
                 "transfershares", "_sharespersecond"],
    },
]

# A version string like v0.5.0 / 1.2.3 from the fork's own self-report.
_RE_VERSION_FN = re.compile(r'function\s+version\s*\([^)]*\)[^{]*\{[^}]*return\s*"v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)"',
                            re.IGNORECASE | re.DOTALL)
_RE_OZ_FROM = re.compile(r'oz-upgrades-from\s+\S*?v([0-9]+\.[0-9]+(?:\.[0-9]+)?)', re.IGNORECASE)
_RE_INTRODUCE = re.compile(r'introduce[d]?\s+(?:with\s+)?v([0-9]+\.[0-9]+(?:\.[0-9]+)?)', re.IGNORECASE)
_RE_SRC_VER = re.compile(r'src/v([0-9]+\.[0-9]+(?:\.[0-9]+)?)/', re.IGNORECASE)


def detect_base(text):
    """Score every known base by how many distinct IMPL-INTERNAL signatures appear in `text`.
    A base is reported only if its hit count meets that base's `min` threshold -> an integrator that
    merely calls a protocol's interface is NOT mis-flagged as a fork (the Ledgity-vs-Aave FP).
    Returns [(score, name, repo, [matched_sigs]), ...] sorted high-to-low. Pure."""
    low = (text or "").lower()
    out = []
    for b in BASES:
        hits = [s for s in b["sigs"] if s in low]
        if len(hits) >= b.get("min", 1):
            out.append((len(hits), b["name"], b["repo"], hits))
    out.sort(key=lambda r: -r[0])
    return out


def detect_version(text):
    """Best-effort: the fork's self-reported version + the evidence kind. Pure.
    Priority: version() return > oz-upgrades-from > 'introduce(d) with vX' comment > src/vX path."""
    t = text or ""
    m = _RE_VERSION_FN.search(t)
    if m:
        return m.group(1), "version() returns"
    m = _RE_OZ_FROM.search(t)
    if m:
        return m.group(1), "@custom:oz-upgrades-from (this is the PREVIOUS version; deployed is newer)"
    m = _RE_INTRODUCE.search(t)
    if m:
        return m.group(1), "'introduced with vX' comment"
    # collect all src/vX.Y.Z mentions; the HIGHEST is the deployed line
    vers = _RE_SRC_VER.findall(t)
    if vers:
        return max(vers, key=_ver_tuple), "src/vX path reference"
    return None, None


def _ver_tuple(v):
    parts = (v or "0").split(".")
    return tuple(int(p) for p in (parts + ["0", "0", "0"])[:3] if p.isdigit())


def norm_line(s):
    """Strip trailing CR + collapse all internal whitespace to single spaces + strip ends.
    Maps CRLF/LF and indentation change to the same string. Pure."""
    return re.sub(r"\s+", " ", (s or "").replace("\r", "")).strip()


# whitespace adjacent to structural punctuation / operators is formatting-only -> remove it.
# (the operator TOKEN itself is untouched, so '=' stays distinct from '==', '=>' etc.)
_PUNCT = re.compile(r"\s*([(){}\[\],;:?~^%|&!<>=*/+\-.])\s*")


def _canon_code(s):
    """Aggressively canonicalize Solidity formatting: CRLF + all whitespace collapsed, and spaces
    around punctuation/operators removed. Two sources that differ ONLY in formatting (incl. multi-line
    reflow of a signature) map to the SAME string; token/operator changes survive. Pure."""
    s = re.sub(r"\s+", " ", (s or "").replace("\r", ""))
    return _PUNCT.sub(r"\1", s)


def normalize(text):
    """Text -> list of canonicalized STATEMENTS (split on ; { }). Reflow/indent/CRLF/blank-line noise
    is gone; only real logic statements remain -> the unit of a 'substantive' diff. Pure."""
    parts = re.split(r"([;{}])", _canon_code(text))
    return [p.strip() for p in parts if p.strip()]


def substantive_diff(a_text, b_text):
    """Unified diff of two sources AFTER statement-level canonicalization (see normalize()).
    Returns the changed ('+'/'-') statements (no context). Empty list == cosmetically identical. Pure."""
    a, b = normalize(a_text), normalize(b_text)
    changes = []
    for line in difflib.unified_diff(a, b, lineterm="", n=0):
        if line[:3] in ("+++", "---") or line.startswith("@@"):
            continue
        if line and line[0] in "+-":
            changes.append(line)
    return changes


def list_sol(root):
    """All .sol files under root (skips OZ/lib/forge-std/solmate vendored trees). Returns [relpath...]."""
    out = []
    for dp, _, fns in os.walk(root):
        low = dp.replace("\\", "/").lower()
        if any(v in low for v in ("/openzeppelin", "/lib/", "/forge-std", "/solmate", "/solady", "/node_modules")):
            continue
        for fn in fns:
            if fn.endswith(".sol"):
                out.append(os.path.relpath(os.path.join(dp, fn), root))
    return sorted(out)


def pick_canonical(basename, target_ver, canon_files):
    """Among canonical files sharing `basename`, prefer the smallest version >= target_ver
    (the patch the fork SHOULD have taken); else the highest available. `canon_files` = [relpath...].
    Returns a relpath or None. Pure (no IO)."""
    cands = [f for f in canon_files if os.path.basename(f).lower() == basename.lower()]
    if not cands:
        return None
    tv = _ver_tuple(target_ver) if target_ver else None

    def fver(f):
        m = _RE_SRC_VER.search(f.replace("\\", "/") + "/")
        return _ver_tuple(m.group(1)) if m else None

    if tv:
        ge = sorted([f for f in cands if fver(f) and fver(f) >= tv], key=fver)
        if ge:
            return ge[0]
    # no version dirs or none >= target: take the highest-versioned, else the first
    withv = sorted([f for f in cands if fver(f)], key=fver)
    return withv[-1] if withv else cands[0]


def read(path):
    try:
        return open(path, encoding="utf-8", errors="replace").read()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Audit-awareness. "Audited" is NOT "skip" -- audited code still has bugs. It means: do not
# re-review the COVERED core blind (low EV vs the firms + any formal proof); ROUTE the hunt to the
# angles audits miss -> (1) post-audit DRIFT, (2) OUT-OF-SCOPE/integration code, (3) ECONOMIC invariants.
# Also fixes scout v2's mis-select: it trusts DefiLlama's `audits` field, which can be wrong (Royco
# Dawn showed audits=0 on DefiLlama yet ships 5 audit reports) -> a repo audit/ dir is ground truth.
# ---------------------------------------------------------------------------
AUDIT_FIRMS = [  # (display, [lowercase match substrings], is_formal_verification)
    ("Certora", ["certora"], True),
    ("Cantina/Spearbit", ["cantina", "spearbit"], False),
    ("Hexens", ["hexens"], False),
    ("Trail of Bits", ["trailofbits", "trail-of-bits", "trail of bits"], False),
    ("OpenZeppelin", ["openzeppelin-audit", "oz-audit", "openzeppelin security"], False),
    ("Sherlock", ["sherlock"], False),
    ("Code4rena", ["code4rena", "code-423n4"], False),
    ("Zellic", ["zellic"], False),
    ("Quantstamp", ["quantstamp"], False),
    ("Consensys Diligence", ["consensys diligence", "consensys-diligence"], False),  # not bare "consensys" (a chain/logo brand: Linea)
    ("Halborn", ["halborn"], False),
    ("ChainSecurity", ["chainsecurity"], False),
    ("WatchPug", ["watchpug"], False),
    ("PeckShield", ["peckshield"], False),
    ("Cyfrin", ["cyfrin"], False),
    ("Pashov", ["pashov"], False),
    ("0xMacro", ["0xmacro"], False),
]
# a repo file that looks like an audit report (path segment `audit(s)/` or an audit/review-named pdf/md)
_RE_AUDIT_FILE = re.compile(r"(^|/)audits?(/|$)|(audit|review|assessment)[^/]*\.(pdf|md|markdown)$", re.IGNORECASE)
# ...but automated-TOOL output is NOT a professional audit (Ledgity's only "report" was a slither dump)
_RE_TOOL_REPORT = re.compile(r"slither|mythril|mythx|4naly3er|aderyn|semgrep|solhint|coverage|lcov|\.sarif", re.IGNORECASE)
# README phrasing that ASSERTS a real audit (strong only -- "Security audit reports" as a folder label or a
# generic "security audit" heading must NOT count; rely on report-files + firm-names for those)
_RE_AUDIT_CLAIM = re.compile(r"audited by|audit by|has been audited|been audited by|audit(?:s)? (?:by|completed|performed|conducted)|formally verified|formal verification", re.IGNORECASE)
# README noise (badges/logos/images/links) where a firm-brand substring is NOT an audit claim (Linea's
# `logo=consensys` badge falsely matched Consensys Diligence) -> strip these lines before firm matching.
_RE_README_NOISE = re.compile(r"img\.shields\.io|<img|!\[|\]\(https?://|badge|logo=", re.IGNORECASE)
# path keywords for code an audit's core scope often EXCLUDES -> hunt these first on an audited target
OOS_HINTS = ("integration", "external", "adapter", "periphery", "wrapper", "bridge",
             "connector", "router", "zap", "migrat", "plugin", "strategy")


def _clean_readme(text):
    """Drop badge/logo/image/link lines from a README so a brand substring in a shield badge (Linea's
    `logo=consensys`) is not mistaken for an audit-firm claim. PURE."""
    return "\n".join(l for l in (text or "").splitlines() if not _RE_README_NOISE.search(l))


def detect_audit_evidence(file_list, readme_text=""):
    """Did this repo get a PROFESSIONAL audit? PURE (file_list = repo-relative paths; readme_text = README).
    Returns {audited, reports:[...], firms:[...], formal:bool, evidence:[...]}. Excludes automated-tool dumps
    (slither/mythril/...) from reports; strips README badges before firm matching; a real audit needs a
    report FILE, a named FIRM, or a STRONG claim ('audited by ...'/'formal verification') -- not a folder label."""
    low_files = [f.replace("\\", "/") for f in (file_list or [])]
    reports = [f for f in low_files if _RE_AUDIT_FILE.search(f) and not _RE_TOOL_REPORT.search(f)]
    clean = _clean_readme(readme_text)
    hay = (" ".join(low_files) + "\n" + clean).lower()
    firms, formal = [], False
    for disp, subs, is_formal in AUDIT_FIRMS:
        if any(s in hay for s in subs):
            firms.append(disp)
            formal = formal or is_formal
    if "formal verification" in hay or "formally verified" in hay:
        formal = True
    claim = bool(_RE_AUDIT_CLAIM.search(clean)) or bool(firms)
    audited = bool(reports) or claim
    evidence = []
    if reports:
        evidence.append(f"{len(reports)} report file(s): " + ", ".join(reports[:8]) + (" ..." if len(reports) > 8 else ""))
    if firms:
        evidence.append("firm(s) named: " + ", ".join(sorted(set(firms))))
    if _RE_AUDIT_CLAIM.search(readme_text or ""):
        evidence.append("README asserts an audit")
    return {"audited": audited, "reports": reports, "firms": sorted(set(firms)), "formal": formal, "evidence": evidence}


# non-logic / non-deployed code -> never an out-of-scope HUNT target (interfaces are ABIs; mocks/tests/scripts
# aren't deployed). Path-segment / suffix match.
_OOS_SKIP = ("/interfaces/", "interfaces/", "/interface/", "/mocks/", "/mock/", "/test/", "/tests/",
             "test/", "tests/", "/script/", "scripts/", "/lib/", "/examples/")


def likely_out_of_scope(sol_files):
    """Heuristic: IMPLEMENTATION .sol whose location suggests it sits OUTSIDE a core audit's scope
    (integrations / external adapters / periphery / wrappers). Excludes interfaces, mocks, tests, scripts
    (no exploitable/deployed logic). Hunt these first on an audited target. PURE."""
    out = []
    for f in (sol_files or []):
        p = f.replace("\\", "/").lower()
        if any(s in p for s in _OOS_SKIP) or p.endswith((".t.sol", ".test.sol", ".s.sol")):
            continue
        if any(k in p for k in OOS_HINTS):
            out.append(f)
    return sorted(out)


def _repo_root_of(src_dir):
    """Resolve the TARGET's own root from src_dir -- WITHOUT walking up into a parent monorepo. The root is
    src_dir itself, unless src_dir is a conventional source subdir (`src`/`contracts`/...), then it's the
    immediate parent (so an audit/ dir one level up from src/ is found). NEVER ascends 2+ levels -- a fetched
    target sits in a shared `hunts/_volume/` next to other clones, and ascending would scan ALL of them
    (the 88-PDFs-from-other-repos bug). PURE (path-string only)."""
    src_dir = os.path.abspath(src_dir).replace("\\", "/").rstrip("/")
    if os.path.basename(src_dir).lower() in ("src", "contracts", "source", "sources", "solidity"):
        return os.path.dirname(src_dir)
    return src_dir


def _scan_repo_files(root):
    """List root-relative file paths (skip vendored/sibling-clone trees) + read the README. Bounded to the
    target's own root. IO."""
    files, readme = [], ""
    for dp, dns, fns in os.walk(root):
        # skip vendored deps AND any nested clone volume (defensive: never wander into sibling targets)
        dns[:] = [d for d in dns if d.lower() not in
                  ("lib", "node_modules", ".git", "out", "cache", "_volume", "broadcast")]
        for fn in fns:
            rel = os.path.relpath(os.path.join(dp, fn), root)
            files.append(rel)
            if fn.lower() in ("readme.md", "readme") and not readme:
                readme = read(os.path.join(dp, fn))
    return files, readme


# Mezo MUSD lesson: a fork's own audit often lives in a SIBLING repo (mezo-org/audits holds the
# Cantina mUSD.pdf), so detect_audit_evidence -- which scans only THIS repo -- saw nothing and we
# nearly mis-routed an audited target as "greenfield". Derive the org from .git/config to point there.
_RE_GH_ORG = re.compile(r"github\.com[/:]([\w.-]+)/")


def parse_github_org(git_config_text):
    """Extract the GitHub org/owner from a .git/config blob (https or ssh remote). PURE."""
    m = _RE_GH_ORG.search(git_config_text or "")
    return m.group(1) if m else None


def github_org_of(repo_root):
    """Ascend from repo_root to the nearest enclosing .git/config and return its GitHub org.

    Source dirs are often nested (solidity/contracts, src), so walk up; STOP at the `_volume`
    clone boundary so we never read the parent security-lab repo's remote (same over-scan guard
    as _repo_root_of)."""
    d = os.path.abspath(repo_root)
    for _ in range(6):
        if os.path.basename(d) == "_volume":
            break
        cfg = os.path.join(d, ".git", "config")
        if os.path.exists(cfg):
            try:
                return parse_github_org(read(cfg))
            except Exception:
                return None
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return None


def _print_audit_route(src_dir, is_fork, ver):
    """Detect audit evidence near src_dir and print the AUDIT verdict + hunt router (or greenfield note)."""
    root = _repo_root_of(src_dir)
    repo_files, readme = _scan_repo_files(root)
    aud = detect_audit_evidence(repo_files, readme)
    oos = likely_out_of_scope([f for f in repo_files if f.endswith(".sol")])

    print("\n## AUDIT STATUS")
    if not aud["audited"]:
        org = github_org_of(root)
        audits_hint = f"github.com/{org}/audits" if org else "<org>/audits (the org's audit repo)"
        if is_fork:
            # a fork of an audited base is NOT greenfield: the core is audited-by-lineage.
            print("  NO LOCAL audit files -- BUT this is a FORK of an audited base: the CORE is audited-by-lineage.")
            print("  -> Route to the DRIFT (the HUNT PLAN above), NOT the whole surface.")
            print(f"  -> CHECK {audits_hint} : a fork's OWN audit often lives in a SIBLING repo, not this one")
            print("     (Mezo MUSD's Cantina mUSD.pdf was in mezo-org/audits, not the musd repo).")
        else:
            print("  NO audit evidence in THIS repo (consistent with UNDER-REVIEWED) -- the high-EV case.")
            print(f"  -> Greenfield: hunt the WHOLE surface (recon + hypothesize). But FIRST check {audits_hint}")
            print("     (audits often live in a sibling repo) + confirm DEPLOYED + in-scope bounty.")
        return
    tag = "AUDITED (audits != 0 -> NOT under-reviewed" + (", incl. FORMAL VERIFICATION" if aud["formal"] else "") + ")"
    print(f"  {tag}")
    for e in aud["evidence"]:
        print(f"    - {e}")
    print("  NOTE: audited != bug-free. But do NOT re-review the COVERED core blind (low EV vs the firms"
          + (" + formal proof" if aud["formal"] else "") + "). ROUTE the hunt to what audits miss:")
    print("  1. DRIFT (highest EV): diff DEPLOYED code vs the AUDITED commit -- audits cover commit X, deployed = X+N.")
    print("       Find the audited commit (audit/ filenames, README, or the report's first page), then:")
    print(f"         diffscan.py <repo> --since <audit-tag>   |   forkdrift.py diff <deployed-src> <audited-commit-src>")
    print("  2. OUT-OF-SCOPE (verify vs each report's scope section) -- code a core audit often skips:")
    if oos:
        for f in oos[:12]:
            print(f"         {f}")
        if len(oos) > 12:
            print(f"         ... (+{len(oos) - 12} more)")
    else:
        print("         (none flagged by path; read each report's scope section for the excluded list)")
    print("  3. ECONOMIC: hypothesize.py -> reasoning-tier invariants (cross-component / oracle-edge / MEV)")
    print("     that checklist audits under-cover. Prove with an invariant STRONGER than theirs, not by reading.")
    if is_fork:
        print("  (FORK + AUDITED: the fork inherits the base's audit, so DRIFT above is doubly the move.)")


def cmd_audit(repo_dir):
    """Standalone: just the audit verdict + hunt router for a cloned repo."""
    print(f"# forkdrift audit: {repo_dir}")
    _print_audit_route(repo_dir, is_fork=False, ver=None)


def cmd_fingerprint(src_dir):
    files = list_sol(src_dir)
    if not files:
        print(f"[!] no .sol under {src_dir}")
        return
    blob = "\n".join(read(os.path.join(src_dir, f)) for f in files)
    bases = detect_base(blob)
    ver, vhow = detect_version(blob)

    print(f"# forkdrift fingerprint: {src_dir}  ({len(files)} .sol)\n")
    if not bases:
        print("NO known-audited base matched.")
        print("  -> Treat as (likely) ORIGINAL code: hunt the WHOLE surface (recon + hypothesize), not a diff.")
        print("  -> (Or the base just isn't in BASES yet - eyeball storage-namespaces / unique names and add it.)")
        if ver:
            print(f"\n  self-reported version: v{ver}  (via {vhow})")
        _print_audit_route(src_dir, is_fork=False, ver=ver)
        return

    top = bases[0]
    print(f"LIKELY FORK of: {top[1]}   (confidence {top[0]} sig{'s' if top[0] != 1 else ''})")
    print(f"  canonical    : {top[2]}")
    print(f"  matched sigs : {', '.join(top[3])}")
    if len(bases) > 1:
        for sc, name, _, _ in bases[1:]:
            print(f"  (also: {name} x{sc})")
    if ver:
        print(f"\n  DEPLOYED version: v{ver}   (via {vhow})")
    else:
        print("\n  DEPLOYED version: unknown (no version()/oz-upgrades-from/comment) - check git tag of the base")

    print("\n## HUNT PLAN (fork -> drift is step 1)")
    print(f"  1. Clone canonical:  git clone --depth 1 {top[2].split(' ')[0]} <canon>")
    if ver:
        print(f"  2. The fork is on v{ver}. Diff it against the NEXT canonical version(s):")
        print(f"       python toolkit/forkdrift.py diff {src_dir} <canon>/src")
        print(f"     The substantive delta = (your CUSTOM drift) + (the vX.Y.Z+1 patch you are MISSING).")
    else:
        print(f"  2. Diff against canonical:  python toolkit/forkdrift.py diff {src_dir} <canon>/src")
    print("  3. CUSTOM drift  -> hunt it directly (recon/hypothesize on JUST those files).")
    print("  4. MISSING patch -> read WHY canonical changed it; then verify it APPLIES to the LIVE config")
    print("     (e.g. RockSolid was missing the v0.5.1 whitelist patch, but its vault is permissionless")
    print("      on-chain -> isWhitelisted()==true for all -> the patch was MOOT. Always check live config.)")
    print("  5. If the diff is cosmetic-only (no substantive lines) -> verbatim audited fork, no finding.")
    _print_audit_route(src_dir, is_fork=True, ver=ver)


def cmd_diff(target_dir, canon_dir):
    tfiles = list_sol(target_dir)
    cfiles = list_sol(canon_dir)
    if not tfiles:
        print(f"[!] no .sol under {target_dir}")
        return
    tblob = "\n".join(read(os.path.join(target_dir, f)) for f in tfiles)
    tver, _ = detect_version(tblob)

    print(f"# forkdrift diff: {target_dir}  vs  {canon_dir}")
    print(f"  target version v{tver or '?'}; {len(tfiles)} target .sol, {len(cfiles)} canonical .sol")
    print("  (whitespace/CRLF/blank-line normalized -> only SUBSTANTIVE logic drift is shown)\n")

    n_drift = n_clean = n_unpaired = 0
    for tf in tfiles:
        base = os.path.basename(tf)
        cf = pick_canonical(base, tver, cfiles)
        if not cf:
            n_unpaired += 1
            print(f"[NEW]   {tf}  -- no canonical counterpart (fork-only file -> hunt directly)")
            continue
        changes = substantive_diff(read(os.path.join(target_dir, tf)), read(os.path.join(canon_dir, cf)))
        if not changes:
            n_clean += 1
            continue
        n_drift += 1
        print(f"[DRIFT] {tf}  vs  {cf}   ({len(changes)} substantive lines)")
        for ln in changes[:40]:
            print(f"    {ln}")
        if len(changes) > 40:
            print(f"    ... (+{len(changes) - 40} more; open both files to read in full)")
        print()

    print(f"--- summary: {n_drift} files with SUBSTANTIVE drift, {n_clean} cosmetically identical, "
          f"{n_unpaired} fork-only ---")
    if n_drift == 0 and n_unpaired == 0:
        print("  => VERBATIM fork of canonical (no custom drift). Finding only if a version-lag patch APPLIES")
        print("     to the live config (diff target version vs the NEXT canonical version to see the patch).")
    else:
        print("  => Hunt the [DRIFT]/[NEW] files. For [DRIFT] that is a missing patch, verify live-config applicability.")


def main():
    ap = argparse.ArgumentParser(description="Detect a fork of a known-audited base + diff the drift")
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fingerprint", help="which audited base is this a fork of? version? audited? -> route")
    f.add_argument("src_dir")
    d = sub.add_parser("diff", help="normalized substantive diff of a fork vs its canonical base")
    d.add_argument("target_dir")
    d.add_argument("canon_dir")
    au = sub.add_parser("audit", help="audit verdict + hunt router for a cloned repo (drift/out-of-scope/economic)")
    au.add_argument("repo_dir")
    a = ap.parse_args()
    if a.cmd == "fingerprint":
        cmd_fingerprint(a.src_dir)
    elif a.cmd == "diff":
        cmd_diff(a.target_dir, a.canon_dir)
    elif a.cmd == "audit":
        cmd_audit(a.repo_dir)


if __name__ == "__main__":
    main()
