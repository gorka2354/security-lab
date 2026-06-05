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
        # peek the body, but stop at the next function so we don't read its auth
        nxt = text.find("function ", m.end())
        body = text[m.end():(m.end() + 280 if nxt < 0 else min(m.end() + 280, nxt))]
        if "only" in blob.lower() or re.search(
                r"msg\.sender|hasRole|_checkRole|_checkOwner|_authorizeUpgrade", body):
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
        if not gname:  # no modifier -> also check the body for inline auth
            nxt = text.find("function ", m.end())
            body = text[m.end():(m.end() + 280 if nxt < 0 else min(m.end() + 280, nxt))]
            if re.search(r"msg\.sender|hasRole|_checkRole|_checkOwner|_authorizeUpgrade", body):
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
                 or re.search(r"msg\.sender|hasRole|_check", body))
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
    ("ORACLE usage vs 3-guard checklist", det_oracle,
     "Heuristic 2: staleness(updatedAt) + price>0 + decimals()."),
    ("DANGEROUS primitives", det_danger,
     "delegatecall / tx.origin / selfdestruct / call / open initialize."),
]


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
