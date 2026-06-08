#!/usr/bin/env python3
"""recon.py - fast lead-surfacer for Solidity repos.

Encodes the heuristics from our vault (Крипто безопасность) as executable
detectors. Point it at a cloned repo and it greps for the patterns we keep
hunting by hand, then prints a PRIORITIZED markdown report you can paste into
a HUNT.md.

    python recon.py <path-to-repo> [--out report.md]

This is a TRIAGE tool, not a sound analyzer: it surfaces leads for a human to
review (expect false positives). For deep static analysis add Slither
(`pip install slither-analyzer`); this complements it by encoding OUR signals
(disabled invariants, sibling-modifier gaps, the oracle 3-guard checklist).
Output is ASCII for Windows consoles. Findings carry a priority (0=high).
"""

import argparse
import os
import re

SKIP_DIRS = {"lib", "node_modules", "out", "artifacts", "cache", ".git",
             "forge-std", "openzeppelin", "docs"}

# admin/privileged-looking verbs (tightened: dropped generic mint/burn/deposit/
# redeem/plain-withdraw which are usually legit user-facing).
PRIV = re.compile(
    r"(set[A-Z]|update[A-Z]|add[A-Z]|remove[A-Z]|grant|revoke|renounce|"
    r"transferOwnership|pause|unpause|upgrade|migrate|initialize|sweep|rescue|"
    r"recover|seize|skim|whitelist|blacklist|kill|drain|disable|enable|"
    r"harvest|notify|collect|distribute|claimFor|claimOn|claimExternal|claimReward|"
    r"withdrawAll|withdrawTo|withdrawFor|rescueTokens|setFee|setReward|forceWithdraw)")

# words that turn a TODO/comment into a security-relevant signal
RISK = re.compile(r"verif|verfi|check|sound|constraint|audit|unsafe|vuln|hack|"
                  r"\bbug\b|reentr|overflow|underflow|signature|access|auth", re.I)

# reentrancy primitives
CALL = re.compile(r"\.call\s*[\{(]|\.transfer\s*\(|\.send\s*\(|\.safeTransfer\w*\s*\(")
WRITE = re.compile(r"\b\w+(\[[^\]]*\])?\s*(=|\+=|-=)(?!=)|\bdelete\s+\w+")
GUARD = re.compile(r"nonreentrant|noreentr|reentrancyguard", re.I)

# test/mock/script files are noise when hunting production bugs -> deprioritize
_TESTRE = re.compile(r"(^|/)(tests?|mocks?|scripts?)/", re.I)

# arbitrary external call (bridge-aggregator approval-drain class)
ARBCALL = re.compile(r"\.call\s*[\({]|\.delegatecall\s*\(")

# inline authorization INSIDE a function body (no modifier, but gated in code):
# a msg.sender comparison, a require on msg.sender, a role/owner check, signature
# verification (keeper/oracle-quorum pattern), or upgrade auth. NOT bare msg.sender
# (that just means "uses the caller as an actor", e.g. _balances[msg.sender]).
INLINE_AUTH = re.compile(
    r"msg\.sender\s*[!=]=|_msgSender\(\)\s*[!=]=|require\s*\([^;{]*(msg\.sender|_msgSender)|"
    r"hasRole|_checkRole|_checkOwner|_authorizeUpgrade|enforceAccessControl|"
    r"_verifySignatures|verifySignature|_checkAccess|_checkSender|"
    r"_?require\w*Only\b|_?check\w*Only\b|"   # e.g. requireGovernanceOnly()
    r"_only\w+\s*\(")   # fix#14: inline auth-helper call, e.g. _onlyAdminOrRole(...)


def iter_sol(root):
    for cur, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]
        for f in files:
            if f.endswith(".sol"):
                yield os.path.join(cur, f)


def lineno(text, idx):
    return text.count("\n", 0, idx) + 1


# ── Detector 1: disabled signals (our strongest real lead, twice) ──
def det_disabled(text, rel):
    out = []
    prod = "/test" not in "/" + rel and not rel.startswith("test") and "script" not in rel
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if re.match(r"//\s*function\s+\w+", s):
            hot = bool(re.search(r"invariant|\btest", s, re.I))
            out.append((rel, i, s[:90], "commented-out function (disabled invariant/test?)",
                        0 if hot else 1))
        elif re.match(r"//\s*(assert|require)\w*\s*\(", s):
            out.append((rel, i, s[:90], "commented-out assertion/check", 0 if prod else 1))
        elif re.search(r"//.*\b(TODO|FIXME|HACK|XXX|BUG|AUDIT)\b", s, re.I):
            risky = bool(RISK.search(s))
            prio = 0 if (risky and prod) else (1 if risky else 2)
            out.append((rel, i, s[:90], "TODO/FIXME note - incomplete logic" +
                        (" (security-relevant)" if risky else ""), prio))
    return out


# ── Detector 2: access control (sibling/modifier gaps) ──
def det_access(text, rel):
    out = []
    for m in re.finditer(r"function\s+(\w+)\s*(\([^{};]*?)\{", text, re.S):
        name, blob = m.group(1), m.group(2)
        if not re.search(r"\b(external|public)\b", blob):
            continue
        if re.search(r"\b(view|pure)\b", blob):   # read-only -> access control N/A
            continue
        if re.search(r"\b(re)?initializer\b", blob):  # OZ initializer guards init
            continue
        # gated if: a modifier; OR strong inline auth anywhere (incl deep signature
        # gates, via INLINE_AUTH); OR msg.sender used as a mapping KEY near the top
        # (self-scoped: caller edits its OWN data, not an admin op). fix#13: a bare/
        # incidental msg.sender (e.g. emit Set(msg.sender,x)) must NOT mask a real
        # ungated setter. Bounded by the next function (no bleed).
        nxt = text.find("function ", m.end())
        end = nxt if nxt > 0 else m.end() + 1500
        top = text[m.end():min(m.end() + 280, end)]
        if ("only" in blob.lower() or INLINE_AUTH.search(text[m.end():end])
                or re.search(r"\[\s*(msg\.sender|_msgSender\(\))\s*\]", top)):
            continue
        if PRIV.search(name):
            out.append((rel, lineno(text, m.start()), f"function {name}(...)",
                        "external/public + privileged name, NO only* / inline auth", 0))
    return out


# ── Detector 2b: sibling inconsistency (the regression technique) ──
def det_sibling(text, rel):
    """Within one file: if some privileged fns are gated (only*) and a
    privileged sibling is NOT, flag it. This is how claimExternalVaultRewards
    (ungated) stood out next to claimBGTIncentives (onlyKeeper)."""
    funcs = []
    for m in re.finditer(r"function\s+(\w+)\s*(\([^{};]*?)\{", text, re.S):
        name, blob = m.group(1), m.group(2)
        if not re.search(r"\b(external|public)\b", blob) or re.search(r"\b(view|pure)\b", blob):
            continue
        gate = re.search(r"\bonly\w+", blob)
        gname = gate.group(0) if gate else None
        if not gname and re.search(r"\b(re)?initializer\b", blob):
            gname = "initializer"  # OZ initializer guards one-time init -> gated
        if not gname:  # no modifier -> inline auth (strong auth, full body) OR a
            nxt = text.find("function ", m.end())   # self-scoped mapping key near top
            end = nxt if nxt > 0 else m.end() + 1500
            if (INLINE_AUTH.search(text[m.end():end])
                    or re.search(r"\[\s*(msg\.sender|_msgSender\(\))\s*\]",
                                 text[m.end():min(m.end() + 280, end)])):
                gname = "inline-auth"
        funcs.append((name, lineno(text, m.start()), gname))
    gates = sorted({f[2] for f in funcs if f[2] and f[2] != "inline-auth"})
    ungated_priv = [f for f in funcs if not f[2] and PRIV.search(f[0])]
    if not gates or not ungated_priv:
        return []
    glist = ", ".join(gates)
    return [(rel, ln, f"function {name}(...)",
             f"UNGATED, but siblings here use [{glist}] -> inconsistent?", 0)
            for name, ln, _ in ungated_priv]


# ── Detector 2c: supply integrity (mint/burn entry points) ──
def det_mint(text, rel):
    """Surfaces every mint/burn entry function with its access-control status.
    The EVM cousin of the Zcash 'counterfeit from nothing' class: an unprotected
    or wrongly-bounded mint breaks total-supply integrity. Verify each with a
    supply invariant (totalSupply <= backing)."""
    out = []
    for m in re.finditer(r"function\s+(\w+)\s*(\([^{};]*?)\{", text, re.S):
        name, blob = m.group(1), m.group(2)
        if not re.search(r"\b(external|public)\b", blob) or re.search(r"\b(view|pure)\b", blob):
            continue
        if not re.search(r"mint|burn", name, re.I):
            continue
        nxt = text.find("function ", m.end())
        body = text[m.end():(m.end() + 280 if nxt < 0 else min(m.end() + 280, nxt))]
        gated = ("only" in blob.lower() or re.search(r"\b(re)?initializer\b", blob)
                 or INLINE_AUTH.search(body) or "msg.sender" in body)
        is_test = bool(re.search(r"(^|/)(test|tests|mock|mocks)", rel, re.I))
        if gated:
            out.append((rel, lineno(text, m.start()), f"function {name}(...)",
                        "mint/burn entry, GATED -> verify the gate + that supply stays bounded",
                        2 if is_test else 1))
        else:
            out.append((rel, lineno(text, m.start()), f"function {name}(...)",
                        "PUBLIC mint/burn, NO access control -> anyone can mint? (supply integrity)"
                        + (" [test/mock]" if is_test else ""), 1 if is_test else 0))
    return out


# ── Detector 3: oracle 3-guard checklist ──
def det_oracle(text, rel):
    out = []
    for m in re.finditer(r"\b(latestRoundData|latestAnswer|getRoundData)\b", text):
        miss = [n for n, ok in (
            ("staleness", bool(re.search(r"updatedAt|block\.timestamp\s*-|heartbeat", text))),
            ("price>0", bool(re.search(r"(<=\s*0|>\s*0|==\s*0|InvalidPrice|InvalidFeedPrice)", text))),
            ("decimals()", "decimals(" in text)) if not ok]
        note = "file has all 3 guards (likely OK)" if not miss else "MISSING in file: " + ", ".join(miss)
        out.append((rel, lineno(text, m.start()), m.group(0), note, 0 if miss else 2))
    return out


# ── Detector 4: dangerous primitives + unprotected initialize ──
def det_danger(text, rel):
    out = []
    for pat, note in [(r"\bdelegatecall\b", "delegatecall - storage/context risk"),
                      (r"\btx\.origin\b", "tx.origin - auth bypass / phishing"),
                      (r"\bselfdestruct\b", "selfdestruct"),
                      (r"\.call\{", "low-level call{...} - reentrancy/return check")]:
        for m in re.finditer(pat, text):
            out.append((rel, lineno(text, m.start()), m.group(0), note, 1))
    for m in re.finditer(r"function\s+(initialize\w*)\s*(\([^{};]*?)\{", text, re.S):
        if "initializer" not in m.group(2) and "only" not in m.group(2).lower():
            out.append((rel, lineno(text, m.start()), f"function {m.group(1)}(...)",
                        "initialize without initializer/onlyX -> front-run / re-init?", 0))
    return out


# ── Detector 5: reentrancy (CEI violation) ──
def det_reentrancy(text, rel):
    """External call followed by a state write, in a function with no
    nonReentrant guard -> classic checks-effects-interactions violation."""
    out = []
    for m in re.finditer(r"function\s+(\w+)\s*(\([^{};]*?)\{", text, re.S):
        name, blob = m.group(1), m.group(2)
        if not re.search(r"\b(external|public)\b", blob) or re.search(r"\b(view|pure)\b", blob):
            continue
        if GUARD.search(blob):
            continue
        nxt = text.find("function ", m.end())
        body = text[m.end():(nxt if nxt > 0 else m.end() + 1500)]
        cm = CALL.search(body)
        if not cm:
            continue
        if WRITE.search(body[cm.end():]):
            out.append((rel, lineno(text, m.start()), f"function {name}(...)",
                        "external call THEN state write, no nonReentrant -> reentrancy (CEI)?", 0))
        else:
            out.append((rel, lineno(text, m.start()), f"function {name}(...)",
                        "external call, no nonReentrant guard (FYI)", 2))
    return out


# ── Detector 6: arbitrary external call (aggregator approval-drain) ──
def det_arbcall(text, rel):
    """A function that takes an (address + bytes) and makes a low-level call is
    the classic bridge-aggregator arbitrary-call: an attacker routes the call to
    a token's transferFrom and drains approvals. (Socket, LiFi-class bugs.)"""
    out = []
    for m in re.finditer(r"function\s+(\w+)\s*(\([^{};]*?)\{", text, re.S):
        name, blob = m.group(1), m.group(2)
        if not re.search(r"\b(external|public)\b", blob):
            continue
        if not (re.search(r"\baddress\b", blob) and re.search(r"\bbytes\b", blob)):
            continue
        if "only" in blob.lower():  # access-controlled admin call -> not a drain risk
            continue
        nxt = text.find("function ", m.end())
        body = text[m.end():(nxt if nxt > 0 else m.end() + 1500)]
        # skip if gated by access control inside the body (admin rescue pattern)
        if re.search(r"enforceAccessControl|contractOwner|onlyOwner|_checkOwner|"
                     r"_checkRole|hasRole|msg\.sender\s*[!=]=\s*\w*[Oo]wner", body):
            continue
        if ARBCALL.search(body):
            out.append((rel, lineno(text, m.start()), f"function {name}(...)",
                        "PERMISSIONLESS (address + bytes) + low-level call -> arbitrary "
                        "external call? route to token.transferFrom = approval drain", 0))
    return out


# ── Detector 7: signature / ecrecover (replay, malleability, no expiry) ──
def det_signature(text, rel):
    """Raw ecrecover has two classic bugs: (1) a malformed/empty signature
    recovers to address(0) -> if not rejected it can impersonate; (2) without a
    nonce the signed message is REPLAYABLE, without a deadline it never expires.
    OZ's ECDSA.recover handles (1); raw ecrecover does not."""
    if "ecrecover" not in text:
        return []
    has_zero = bool(re.search(r"address\(0\)|\bECDSA\b|tryRecover", text))
    has_nonce = bool(re.search(r"\bnonce", text, re.I))
    has_deadline = bool(re.search(r"deadline|expir|validUntil|validAfter", text, re.I))
    out = []
    for m in re.finditer(r"\becrecover\s*\(", text):
        miss = []
        if not has_zero:
            miss.append("address(0) check (malleable/empty sig)")
        if not has_nonce:
            miss.append("nonce (replay)")
        if not has_deadline:
            miss.append("deadline (no expiry)")
        note = ("raw ecrecover, file MISSING: " + ", ".join(miss)) if miss else \
               "raw ecrecover but file has zero/nonce/deadline guards (review)"
        out.append((rel, lineno(text, m.start()), "ecrecover(...)", note, 0 if miss else 2))
    return out


# ── Detector 8: upgrade safety (unprotected UUPS) ──
def det_upgrade(text, rel):
    """UUPS proxies gate upgrades in _authorizeUpgrade. If its body has no owner/
    role check, ANYONE can swap the implementation -> total takeover or brick.
    Also flags upgradeTo* declared without gating and without _authorizeUpgrade."""
    out = []
    for m in re.finditer(r"function\s+_authorizeUpgrade\s*(\([^{};]*?)\{", text, re.S):
        blob = m.group(1)
        nxt = text.find("function ", m.end())
        body = text[m.end():(nxt if nxt > 0 else m.end() + 240)]
        gated = ("only" in blob.lower() or re.search(
            r"msg\.sender|hasRole|_checkRole|_checkOwner|owner\(\)|require|revert", body))
        if not gated:
            out.append((rel, lineno(text, m.start()), "function _authorizeUpgrade(...)",
                        "UUPS _authorizeUpgrade with NO access check -> anyone upgrades the "
                        "impl (total takeover / brick)", 0))
    if not re.search(r"_authorizeUpgrade", text):
        for m in re.finditer(r"function\s+(upgradeTo\w*)\s*(\([^{};]*?)\{", text, re.S):
            if "only" not in m.group(2).lower():
                out.append((rel, lineno(text, m.start()), f"function {m.group(1)}(...)",
                            "upgradeTo* with no onlyX and no _authorizeUpgrade -> unguarded upgrade", 0))
    return out


# ── Detector 9: unchecked ERC20 return (silent transfer failure) ──
def det_unchecked(text, rel):
    """A bare ERC20 transfer/transferFrom whose bool return is dropped. Non-
    standard tokens (USDT, ZRX, OMG) return false instead of reverting, so the
    transfer silently fails while the contract assumes success -> accounting
    corruption / fund loss. Fix = OpenZeppelin SafeERC20."""
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("//") or s.startswith("*") or s.startswith("/*"):
            continue
        m = re.search(r"\.transfer(From)?\s*\(", s)
        if not m or "safeTransfer" in s or "payable" in s or "super." in s:
            continue                       # SafeERC20 / ETH / token's own override
        head = s[:m.start()]
        if re.search(r"=|require|assert|return|\bif\b|&&|\|\||\?", head):
            continue                       # return value captured or checked
        if "," not in s[m.end():]:
            continue                       # 1 arg => ETH x.transfer(amt) (reverts), skip
        out.append((rel, i, s[:90],
                    "ERC20 transfer/transferFrom return ignored -> use SafeERC20 "
                    "(USDT/ZRX return false, not revert)", 0))
    return out


# ── Detector 10: ERC4626 first-depositor inflation ──
def det_erc4626(text, rel):
    """ERC4626 vaults can be hit by the first-depositor 'inflation attack': the
    attacker mints 1 wei of shares, donates assets to skew the share price, and
    later deposits round down to 0 shares (stolen). Mitigations: override
    _decimalsOffset() (OZ virtual shares) or seed dead shares / a minimum. Flag
    vaults with none -> verify by hand."""
    if not re.search(r"\bERC4626\b", text):
        return []
    protected = bool(re.search(
        r"_decimalsOffset|MINIMUM_(SHARES|LIQUIDITY|DEPOSIT)|"
        r"_mint\s*\(\s*(address\(0|0x0|0xdead|DEAD|address\(this)", text, re.I))
    if protected:
        return []
    m = re.search(r"\bcontract\s+(\w+)", text)
    name = m.group(1) if m else "?"
    return [(rel, lineno(text, m.start()) if m else 1, f"contract {name} (ERC4626)",
             "ERC4626 vault: no _decimalsOffset / dead-shares / minimum -> "
             "first-depositor inflation attack? (verify by hand)", 0)]


DETECTORS = [
    ("DISABLED signals (commented-out invariant/check, security TODO)", det_disabled,
     "Heuristic 4: 'a verification that doesn't verify'. Real leads here twice."),
    ("ACCESS-CONTROL sibling inconsistency (regression technique)", det_sibling,
     "Heuristic 3: in this contract some privileged fns ARE gated, this one is NOT."),
    ("ACCESS CONTROL leads (privileged fn, no modifier)", det_access,
     "Heuristic 3: who SHOULD call this? Compare siblings / old version."),
    ("SUPPLY INTEGRITY (mint/burn entry points)", det_mint,
     "Heuristic 5: can the token be minted from nothing? EVM cousin of Zcash counterfeiting."),
    ("REENTRANCY (external call then state write)", det_reentrancy,
     "Heuristic 6: external call before state update (CEI violation), no nonReentrant."),
    ("ARBITRARY external call (bridge-aggregator approval drain)", det_arbcall,
     "Heuristic 7: (address+bytes) param + low-level call -> route to transferFrom = drain."),
    ("SIGNATURE / ecrecover (replay, malleability, no expiry)", det_signature,
     "Raw ecrecover: needs address(0) check + nonce (anti-replay) + deadline (expiry)."),
    ("UPGRADE safety (unprotected UUPS _authorizeUpgrade)", det_upgrade,
     "Upgrade auth with no owner/role check -> anyone swaps the impl = total takeover."),
    ("UNCHECKED ERC20 return (silent transfer failure)", det_unchecked,
     "Bare transfer/transferFrom return dropped -> USDT/ZRX fail silently; use SafeERC20."),
    ("ERC4626 inflation (first-depositor share-price attack)", det_erc4626,
     "Vault with no _decimalsOffset / dead-shares -> first depositor skews the share price."),
    ("ORACLE usage vs 3-guard checklist", det_oracle,
     "Heuristic 2: staleness(updatedAt) + price>0 + decimals()."),
    ("DANGEROUS primitives", det_danger,
     "delegatecall / tx.origin / selfdestruct / call / open initialize."),
]


def det_key(title):
    """Stable short key for a detector title -> used by the triage ledger so a
    verdict survives wording changes. Check 'sibling' before 'access' (the
    sibling title contains both)."""
    t = title.lower()
    for sub, k in (("sibling", "sibling"), ("access control leads", "access"),
                   ("supply", "supply"), ("reentrancy", "reentrancy"),
                   ("arbitrary", "arbcall"), ("signature", "signature"),
                   ("upgrade", "upgrade"), ("unchecked", "unchecked"),
                   ("erc4626", "erc4626"), ("oracle", "oracle"),
                   ("dangerous", "danger"), ("disabled", "disabled")):
        if sub in t:
            return k
    return "other"


def main():
    ap = argparse.ArgumentParser(description="Solidity lead-surfacer (vault heuristics)")
    ap.add_argument("repo", help="path to a cloned Solidity repo")
    ap.add_argument("--out", help="also write the report to this markdown file")
    ap.add_argument("--top", type=int, default=25, help="max leads shown per detector")
    args = ap.parse_args()

    files = list(iter_sol(args.repo))
    results = {title: [] for title, _, _ in DETECTORS}
    for path in files:
        rel = os.path.relpath(path, args.repo).replace("\\", "/")
        try:
            text = open(path, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        for title, fn, _ in DETECTORS:
            results[title].extend(fn(text, rel))

    out = [f"# Recon report: {os.path.basename(os.path.abspath(args.repo))}",
           f"\nScanned {len(files)} .sol files. Triage only - verify every lead by hand.",
           "Priority: [!] high (review first), [.] medium, [ ] low.\n"]
    total = 0
    for title, _, why in DETECTORS:
        # deprioritize test/mock/script files (noise for production hunting)
        hits = [(r, ln, s, n, min(2, p + 1) if _TESTRE.search(r) else p)
                for (r, ln, s, n, p) in results[title]]
        hits = sorted(hits, key=lambda h: h[4])
        total += len(hits)
        shown = [h for h in hits if h[4] <= 1][:args.top] or hits[:args.top]
        out.append(f"\n## {title}  ({len(hits)})\n_{why}_\n")
        if not hits:
            out.append("  (none)")
            continue
        mark = {0: "[!]", 1: "[.]", 2: "[ ]"}
        for rel, ln, snippet, note, prio in shown:
            out.append(f"- {mark[prio]} `{rel}:{ln}` - {note}\n    `{snippet}`")
        rest = len(hits) - len(shown)
        if rest > 0:
            out.append(f"  ... and {rest} more (lower priority; raise --top to see)")

    out.append(f"\n---\nTotal leads: {total}. Next: filter known (past audits) -> "
               f"verify impact -> PoC. High-signal [!] first.")
    report = "\n".join(out)
    print(report)
    if args.out:
        open(args.out, "w", encoding="utf-8").write(report)
        print(f"\n[written to {args.out}]")


if __name__ == "__main__":
    main()
