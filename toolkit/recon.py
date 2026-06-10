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
    r"hasRole|_checkRole|_checkOwner|_authorizeUpgrade|enforce[A-Za-z]\w*\s*\(|"   # fix#18: Diamond/library enforce-auth (enforceIsContractOwner / enforceIsController / LibX.enforce*)
    r"_verifySignatures|verifySignature|_?checkAccess\s*\(|_checkSender|"   # fix#15: selector-gating checkAccess(this.fn.selector) (Cap / OZ-AccessManager pattern)
    r"_?require\w*Only\b|_?check\w*Only\b|"   # e.g. requireGovernanceOnly()
    r"_only\w+\s*\(|"   # fix#14: inline auth-helper call, e.g. _onlyAdminOrRole(...)
    r"_is(?:Manager|Authoriz\w*|Authed|Ward|Admin|Owner|Operator|HubManager|PoolManager|PoolAdmin)\w*\s*\(|"  # fix#27: inline predicate gate (Centrifuge Hub `_isManager(poolId)`)
    r"_authorize\s*\(|_validate(?:Controller|Caller|Sender|Owner|Operator|Signature|Sig)\w*\s*\(")  # fix#30: caller-auth helpers (DRE `_authorize` EIP-712 sig, MagicSwap `_validateController`) -- NOT input validators (_validateAmount/_validateAddress sanctions)

# fix#27: ward-model (MakerDAO dss / Centrifuge): `modifier auth { require(wards[msg.sender]==1) }`,
# applied as a trailing modifier `external auth`. Recognize it as a gate (it's not "only*"-named and
# not a body call, so INLINE_AUTH misses it). Word-boundary keeps it off `authority`/`getAuth`.
# fix#32: OZ AccessManager's `restricted` modifier (AccessManagedUpgradeable) is the same shape -- a
# trailing auth modifier (`external restricted`), not "only*"-named -> recognize it (OZ v5's recommended
# access-control, increasingly common; Royco V2 used it on ~all privileged fns -> 47 false leads without this).
WARD_MOD = re.compile(r"\bauth\b|\bauthOrHook\b|\bauthOrManager\b|\bonlyWards?\b|\brestricted\b|"
                      r"\bisManager\b|\bisAuthoriz\w*|\brequiresAuth\b|\bauthenticated\b")

# fix#19: a thin facet/wrapper whose body just delegates to a library call (Lib*.fn(...)) often has
# its auth INSIDE that library (Chikn _claimEggs, Crypto Unicorns LibStaking.unstake) -> the wrapper
# looks "ungated" but isn't. Don't suppress (the lib MIGHT not gate), but downgrade [!] -> [.] + note.
LIB_DELEGATE = re.compile(r"\b(?:Lib|I?[A-Z]\w*Lib)\w*\.\w+\s*\(")

# fix#25: a thin mint/burn WRAPPER whose body just calls a sibling mint entrypoint
# (EtherOrcs mintRogues -> loops mintRogue(); the gate lives in the sibling) looks ungated
# but isn't the real mint. Matches a call to a sibling `mintX(`/`burnX(` that is NOT the
# `_mint`/`_burn` primitive or an external `.mint()` -> downgrade [!]->[.] (fix#19 family).
MINT_WRAPPER = re.compile(r"(?<![._A-Za-z0-9])(?:mint|burn)(?:[A-Z]\w*)?\s*\(")  # fix#31: also a bare `mint(`/`burn(` public-sibling call (Mellow mintAllocatedShares -> gated mint())

# ── research-engine harvest (patterns/ -> detectors). Each is a LEAD, not a verdict. ──
# Pattern 03 reward-accounting: a write to an "already-claimed" marker. If a reward payout
# transfers value but never writes one (or writes it AFTER the transfer), suspect double-claim.
REWARD_MARKER = re.compile(
    r"(claimed|rewardDebt|rewardPaid|hasClaimed|lastClaim\w*|userReward\w*|_claimed|"
    r"checkpoint\w*|lastUpdate\w*|rewards?)\s*(\[[^\]]*\])?(\.\w+)?\s*(\+?=)(?!=)", re.I)


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
        if ("only" in blob.lower() or INLINE_AUTH.search(blob)   # fix#15: auth modifier in signature (checkAccess(...))
                or WARD_MOD.search(blob)   # fix#27: ward-model `auth` modifier (MakerDAO/Centrifuge)
                or INLINE_AUTH.search(text[m.end():end])
                # fix#26 (MagicSwap StakingContract.claimRewards): self-scope by a mapping KEY
                # anywhere in the body, not just the first 280 chars -- user-claim fns index
                # userStakes[msg.sender] deep in a loop. The [msg.sender]-as-key shape is specific
                # (not the bare msg.sender of fix#13) so widening it won't unmask a real admin setter.
                or re.search(r"\[\s*(msg\.sender|_msgSender\(\))\s*\]", text[m.end():end])):
            continue
        if PRIV.search(name):
            delegates = bool(LIB_DELEGATE.search(text[m.end():end]))   # fix#19: thin facet delegator
            note = "external/public + privileged name, NO only* / inline auth"
            if delegates:
                note += " (thin facet delegator -> auth may be enforced in the Lib fn; verify there)"
            out.append((rel, lineno(text, m.start()), f"function {name}(...)", note, 1 if delegates else 0))
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
        if not gname and WARD_MOD.search(blob):   # fix#27: ward-model `auth` modifier
            gname = "auth"
        if not gname and re.search(r"\b(re)?initializer\b", blob):
            gname = "initializer"  # OZ initializer guards one-time init -> gated
        if not gname and INLINE_AUTH.search(blob):   # fix#15: non-only auth modifier in signature (checkAccess(this.fn.selector))
            gname = "checkAccess"
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
        # fix#30: scan the FULL function body (not just 280 chars) so a gate deep behind preamble
        # is seen -- DRE mintFrom's `_authorize` sits past validations/reverts (cf. fix#26 for det_access).
        body = text[m.end():(nxt if nxt > 0 else m.end() + 1500)]
        gated = ("only" in blob.lower() or re.search(r"\b(re)?initializer\b", blob)
                 or INLINE_AUTH.search(blob)   # fix#16: auth modifier in signature, e.g. checkAccess(this.mint.selector)
                 or WARD_MOD.search(blob)   # fix#27: ward-model `auth` / authOrHook modifier
                 or "super.mint(" in body or "super.burn(" in body   # fix#27: thin override -> parent gate (Centrifuge ShareToken)
                 or INLINE_AUTH.search(body) or "msg.sender" in body)
        is_test = bool(re.search(r"(^|/)(test|tests|mock|mocks)", rel, re.I))
        if gated:
            out.append((rel, lineno(text, m.start()), f"function {name}(...)",
                        "mint/burn entry, GATED -> verify the gate + that supply stays bounded",
                        2 if is_test else 1))
        else:
            # fix#25: a thin wrapper delegating to a gated sibling mint fn (mintRogues ->
            # mintRogue()) isn't the real ungated mint -> downgrade + note, don't suppress.
            delegates = (MINT_WRAPPER.search(body) is not None
                         and not re.search(r"_mint\s*\(|_burn\s*\(|\.mint\s*\(|\.burn\s*\(", body))
            if delegates:
                out.append((rel, lineno(text, m.start()), f"function {name}(...)",
                            "mint/burn WRAPPER delegating to a sibling mint fn (thin delegator -> "
                            "gate may be in the called fn; verify there)", 2 if is_test else 1))
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
    # spot-reserve sub-check (pattern 02 §4): a value/price/health fn that reads spot AMM reserves
    # and divides by them is manipulable in 1 block UNLESS the reserves are TWAP/clamped/cumulative.
    for fm in re.finditer(r"function\s+(\w*(?:[Pp]rice|[Vv]alue|[Qq]uote|[Vv]aluation|[Hh]ealth|"
                          r"[Cc]ollateral|getAmount)\w*)\s*\([^{};]*?\{", text, re.S):
        name = fm.group(1)
        nxt = text.find("function ", fm.end())
        body = text[fm.end():(nxt if nxt > 0 else fm.end() + 1200)]
        reads_spot = re.search(r"\bgetReserves\s*\(|\breserve0\b|\breserve1\b", body)
        if reads_spot and re.search(r"/|mulDiv", body) \
                and not re.search(r"truncat|TWAP|timeWeighted|cumulative|observe|consult|\bEMA\b", body, re.I):
            out.append((rel, lineno(text, fm.start()), f"function {name}(...)",
                        "value/price fn reads SPOT AMM reserves and divides -> manipulable in 1 "
                        "block unless TWAP/clamped (verify the consumer; cf. Likwid truncatedReserves)", 0))
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
        # skip if gated by access control inside the body (admin rescue/replay pattern).
        # fix#24 (EtherOrcs MainlandPortal.replayCall): INLINE_AUTH recognizes an inline
        # require(msg.sender==admin) / role / enforce* gate, so an admin-only arbitrary call
        # is no longer a permissionless-drain FP. (+contractOwner: Diamond owner getter.)
        if INLINE_AUTH.search(body) or "contractOwner" in body:
            continue
        # fix#28 (Centrifuge Gateway.withBatch): the drain pattern is <attackerAddr>.call(<data>).
        # A call to msg.sender / address(this) is a callback-to-caller / self batching pattern, not an
        # arbitrary-target drain. Strip self/caller low-level calls, then require a non-self one remains.
        non_self = re.sub(r"(?:msg\.sender|_msgSender\(\)|address\s*\(\s*this\s*\)|\bthis)\s*\.\s*"
                          r"(?:call|delegatecall)", "", body)
        if ARBCALL.search(non_self):
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
        gated = ("only" in blob.lower() or INLINE_AUTH.search(blob)   # fix#17: auth modifier in signature, e.g. checkAccess(bytes4(0))
                 or re.search(r"msg\.sender|hasRole|_checkRole|_checkOwner|owner\(\)|require|revert", body))
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
        # fix#29 (dreUSD dreShareOFTAdapter): `try X.transfer(...) returns (bool ok)` captures the
        # return in try/catch (bridge-delivery-must-not-revert pattern) -> not unchecked.
        if re.search(r"\btry\b", head) and re.search(r"\breturns\s*\(", s[m.end():]):
            continue
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
    # fix#20: totalAssets() reading balanceOf(address(this)) (no internal accounting) means a
    # DIRECT donation moves the share price -> the dStake flavor; sharper than the generic lead.
    balance_based = bool(re.search(
        r"function\s+totalAssets\b[\s\S]{0,240}?\.balanceOf\s*\(\s*address\s*\(\s*this", text))
    note = ("ERC4626 vault: no _decimalsOffset / dead-shares / minimum -> "
            "first-depositor inflation attack? (verify by hand)")
    if balance_based:
        note = ("ERC4626 vault: no _decimalsOffset/dead-shares AND totalAssets() is balance-based "
                "(.balanceOf(this)) -> a direct donation moves the share price (dStake flavor); "
                "verify the empty-vault window (fix#20)")
    return [(rel, lineno(text, m.start()) if m else 1, f"contract {name} (ERC4626)", note, 0)]


# ── Detector 7: L2 / native Account-Abstraction footguns (zkSync Era) ──
L2_FOOTGUNS = [
    (r"\bextcodesize\b",
     "extcodesize as EOA/contract check -> zkSync & native-AA: EOAs can have code and a counterfactual "
     "smart-account has none; auth/signature gates on 'isContract' are bypassable"),
    (r"\b\w+\.code\.length\b",
     "address.code.length as an EOA/contract check -> unreliable on AA chains (zkSync)"),
    (r"function\s+\w*[Ii]sContract\b",
     "custom isContract() -> if it branches signature/auth verification, the EOA-vs-smart-account split "
     "breaks on zkSync AA (cf. zkMarkets TransactFacet.verifySignature)"),
]


def det_l2_footgun(text, rel):
    """zkSync-Era / native Account-Abstraction footguns: code that assumes 'EOA == no code' or
    branches signature/auth on extcodesize breaks where ANY account can be a smart contract.
    Learned from zkMarkets' extcodesize-branched EIP-1271/ECDSA signature path."""
    out = []
    for pat, note in L2_FOOTGUNS:
        for m in re.finditer(pat, text):
            out.append((rel, lineno(text, m.start()), m.group(0)[:60], note, 1))
    return out


# ── Detector 14: reward / claim accounting (double-claim) ── research pattern 03
def det_reward(text, rel):
    """A reward-payout function that transfers value but never writes an 'already-claimed'
    marker (claimed/rewardDebt/...), or writes it AFTER the transfer, is a double-claim lead.
    Honest limit: the marker may live in a called library (Crypto Unicorns LibRewards) -> when the
    body just delegates we downgrade [!]->[.] + note. Gated keeper-only harvests are skipped
    (no per-user double-claim surface)."""
    out = []
    for m in re.finditer(r"function\s+(\w+)\s*(\([^{};]*?)\{", text, re.S):
        name, blob = m.group(1), m.group(2)
        if not re.search(r"\b(external|public)\b", blob) or re.search(r"\b(view|pure)\b", blob):
            continue
        if not (re.search(r"claim|harvest|getreward", name, re.I)
                or re.search(r"(collect|redeem)\w*reward", name, re.I)):
            continue
        if "only" in blob.lower() or INLINE_AUTH.search(blob):   # keeper/admin-gated -> not a per-user vector
            continue
        nxt = text.find("function ", m.end())
        body = text[m.end():(nxt if nxt > 0 else m.end() + 1500)]
        cm = CALL.search(body)
        if not cm:                       # nothing of value leaves this body -> not a payout here
            continue
        pre = body[:cm.start()]
        marker = REWARD_MARKER.search(body)
        # fix#21 (Morpho Midnight): a decrement of a claimable/balance var BEFORE the payout
        # (e.g. `claimableFee[token] -= amount`) consumes the entitlement just like a named
        # claimed-marker -> not a double-claim. Recognize it so admin fee-claims don't FP
        # (their accounting var isn't named like a reward marker, and SafeTransferLib looks
        # like a thin Lib delegator).
        if re.search(r"-=", pre) or (marker and marker.start() < cm.start()):
            continue
        if marker:                       # a reward-marker exists, but it's written AFTER the transfer
            out.append((rel, lineno(text, m.start()), f"function {name}(...)",
                        "claimed-marker written AFTER the transfer (accounting CEI) -> re-entrant "
                        "double-claim? (verify order / nonReentrant)", 1))
        elif LIB_DELEGATE.search(body):
            out.append((rel, lineno(text, m.start()), f"function {name}(...)",
                        "reward payout transfers but no claimed-marker/decrement here (thin delegator "
                        "-> marker may be in the Lib fn; verify there)", 1))
        else:
            out.append((rel, lineno(text, m.start()), f"function {name}(...)",
                        "reward payout transfers value but NO claimed-marker / decrement before it "
                        "-> double-claim? (verify the accounting)", 0))
    return out


# ── Detector 15: interest-index inflation (Aave-fork empty-market) ── research pattern 04
def det_index(text, rel):
    """Aave-style interest accumulators (liquidityIndex / variableBorrowIndex) compound as
    delta/scaledSupply; on an empty market a tiny premium is a huge relative jump (dTRINITY $257k).
    Flag index writes / cumulateToLiquidityIndex and note whether a min-liquidity/cap/seed guard
    is visible. LEAD: whether the market can actually be empty+collateralizable is config (T2)."""
    if not re.search(r"liquidityIndex|variableBorrowIndex|\bborrowIndex\b|"
                     r"cumulateToLiquidityIndex|getReserveNormalizedIncome", text):
        return []
    guarded = bool(re.search(r"MIN_(LIQUIDITY|SUPPLY|RESERVE|AMOUNT)|minLiquidity|supplyCap|"
                             r"borrowCap|seedAmount|seedDeposit|isolationMode", text, re.I))
    out = []
    for m in re.finditer(r"\bcumulateToLiquidityIndex\s*\(|"
                         r"\b(?:liquidityIndex|variableBorrowIndex|borrowIndex)\s*=(?!=)", text):
        note = ("Aave-fork interest index update"
                + ("" if guarded else " with no visible min-liquidity / cap / seed guard")
                + " -> empty-market index inflation? (dTRINITY $257k class; verify a fresh reserve "
                "can't be collateral while scaledSupply ~ 0)")
        out.append((rel, lineno(text, m.start()), m.group(0)[:40], note, 1 if guarded else 0))
    return out


# ── Detector 16: cached EIP-712 domain separator (cross-chain / fork replay) ── research pattern 06
def det_domain(text, rel):
    """An EIP-712 DOMAIN_SEPARATOR cached once (constructor / immutable) with block.chainid and no
    recompute-on-fork path -> signatures replay across a chain fork or a sibling deployment
    (zkMarkets class). OZ's EIP712 (_domainSeparatorV4 + chainid-changed branch) is the fix; if it's
    present this is safe and we don't flag."""
    if not re.search(r"DOMAIN_SEPARATOR|_domainSeparator|\bEIP712\b", text):
        return []
    safe = bool(re.search(r"_domainSeparatorV4|block\.chainid\s*==|_buildDomainSeparator|"
                          r"EIP712Upgradeable", text))
    cached = bool(re.search(r"DOMAIN_SEPARATOR\s*=|_domainSeparator\s*=|immutable\s+DOMAIN_SEPARATOR", text))
    uses_chainid = "chainid" in text.lower()
    if cached and uses_chainid and not safe:
        m = re.search(r"DOMAIN_SEPARATOR|_domainSeparator", text)
        return [(rel, lineno(text, m.start()), "DOMAIN_SEPARATOR",
                 "EIP-712 domain separator cached with block.chainid and NO recompute-on-fork path "
                 "-> cross-chain / post-fork signature replay (zkMarkets class; use OZ EIP712)", 0)]
    return []


# ── Detector 17: liquidation math (self-liq, rounding, manipulable health) ── research pattern 05
def det_liquidation(text, rel):
    """Surfaces each liquidation entrypoint with the 4-check (manipulable health price? self-liq?
    close-factor cap? rounding direction?). Bumps to [!] when there's no self-liquidation guard or
    the seize/repay rounds UP (mulDivUp) -> may favor the liquidator. Core bugs (manipulable health,
    bad-debt routing) are economic/cross-file (T3); this is a triage surfacer, not a verdict."""
    out = []
    for m in re.finditer(r"function\s+(\w*[Ll]iquidat\w*|\w*[Ss]eize\w*)\s*(\([^{};]*?)\{", text, re.S):
        name, blob = m.group(1), m.group(2)
        if not re.search(r"\b(external|public)\b", blob) or re.search(r"\b(view|pure)\b", blob):
            continue
        nxt = text.find("function ", m.end())
        body = text[m.end():(nxt if nxt > 0 else m.end() + 1800)]
        self_guard = bool(re.search(r"!=\s*msg\.sender|msg\.sender\s*!=|\bborrower\s*!=|"
                                    r"SelfLiquidat", body))
        # fix#23 (from Morpho Midnight): collateral-OUT (what the liquidator RECEIVES) rounding UP
        # favors the liquidator (bad); repaid/debt-side rounding up favors the protocol (fine). Only
        # flag the former -> match an up-rounding assigned to a seize/collateral-out/amount-out var.
        seize_up = bool(re.search(
            r"\b(seiz\w*|\w*[Cc]ollateralOut\w*|\w*[Aa]mountOut\w*|liquidatorGets\w*)\s*=\s*"
            r"[^;]*?(mulDivUp|mulDivRoundingUp|divUp|ceilDiv)", body, re.I))
        health = bool(re.search(r"health|getUserAccountData|isHealthy|solvent|collateralValue|"
                                r"_validate|liquidatable", body, re.I))
        flags = []
        if not self_guard:
            flags.append("no self-liquidation guard (liquidator==borrower?)")
        if seize_up:
            flags.append("collateral-OUT (liquidator's seize) rounds UP -> favors the liquidator, verify")
        base = ("liquidation entrypoint -> 4-check: manipulable health price? self-liq? "
                "close-factor cap? rounding direction?")
        note = base + (" | " + "; ".join(flags) if flags else (" (health gate present)" if health else ""))
        # fix#22 (Morpho Midnight): reserve [!] for the real bug -- NO visible health gate (can a
        # solvent position be liquidated?). With a health gate, self-liq is harmless and up-rounding
        # is usually on the repaid/debt side -> these are [.] leads to verify, not [!].
        out.append((rel, lineno(text, m.start()), f"function {name}(...)", note, 0 if not health else 1))
    return out


# ── Detector 18: weak on-chain randomness (predictable RNG in an outcome path) ── GameFi class
RNG_ENTROPY = re.compile(
    r"block\.(timestamp|difficulty|prevrandao|coinbase|basefee|number)\b|\bblockhash\s*\(|(?<![\w.])now\b")
RNG_VRF = re.compile(r"\bVRFConsumer\w*|requestRandomness|fulfillRandomWords|requestRandomWords|"
                     r"vrfCoordinator|\bVRFCoordinator\w*|fulfillRandomness", re.I)
RNG_OUTCOME = re.compile(r"random|\brand\b|\b_rand\b|\bseed\b|\broll\b|spin|raffle|lottery|jackpot|"
                         r"winner|reward|rarity|\bloot\b|gacha|breed|summon|\bmint\b|\bdraw\b|"
                         r"dice|shuffle|chance|odds", re.I)
RNG_EOA = re.compile(r"tx\.origin\s*==\s*(msg\.sender|_msgSender)|"
                     r"(msg\.sender|_msgSender\(\))\s*==\s*tx\.origin|extcodesize|noCheaters", re.I)
# stricter outcome words for the DIRECT-modulo path (no keccak) -> drops the common/ambiguous ones
# (mint/reward/draw/loot/breed) that would FP on `block.number % epoch`; keeps the unambiguous-RNG words.
RNG_OUTCOME_STRICT = re.compile(r"random|\brand\b|\bseed\b|\broll\b|spin|raffle|lottery|jackpot|"
                                r"winner|rarity|gacha|dice|shuffle|\bodds\b|wager", re.I)


def det_weak_random(text, rel):
    """Predictable on-chain 'randomness' -- keccak256 over block entropy (block.timestamp/
    blockhash/difficulty/prevrandao/coinbase/basefee) -- feeding an OUTCOME (reward tier, mint
    species, raffle winner) is grindable: a contract can predict-and-revert, and even a
    tx.origin==msg.sender EOA-gate is only a SPEED BUMP (an EOA simulates the next block and
    selectively submits -- how Wolf Game was actually exploited). Real fix = commit-reveal or
    Chainlink VRF; if the file uses VRF we downgrade (verify which path drives the outcome).
    The #1 on-chain-game bug class; learned from EtherOrcs Raids._rand + Wolf Game Woolf.random."""
    has_vrf = bool(RNG_VRF.search(text))
    eoa = bool(RNG_EOA.search(text))
    out, seen = [], set()
    for m in re.finditer(r"keccak256\s*\(", text):
        # scope the entropy/modulo check to THIS statement (cut at the next ';') so a benign
        # keccak doesn't borrow block-entropy from the following line/function.
        semi = text.find(";", m.end())
        end = semi if 0 < semi < m.end() + 400 else m.end() + 240
        blob = text[m.end():end]
        if not RNG_ENTROPY.search(blob):
            continue
        if "chainid" in blob.lower():            # EIP-712 domain separator, not RNG
            continue
        # confirm it's used as RANDOMNESS (not a timestamped id): an outcome-y identifier
        # nearby, OR a modulo applied to the hash result (in this statement).
        ctx = text[max(0, m.start() - 400):end]
        if not (RNG_OUTCOME.search(ctx) or "%" in blob):
            continue
        ln = lineno(text, m.start())
        if ln in seen:
            continue
        seen.add(ln)
        note = ("predictable on-chain RNG: keccak256 over block entropy (timestamp/blockhash/"
                "difficulty/coinbase) drives an outcome -> grindable (predict-and-revert; use "
                "commit-reveal or Chainlink VRF)")
        if eoa:
            note += (" | EOA-gate present: blocks an atomic contract grind but NOT "
                     "simulation+selective-submission (Wolf Game class)")
        if has_vrf:
            note += " | file ALSO references VRF -> verify which path actually drives the outcome"
        out.append((rel, ln, "keccak256(... block entropy ...)", note, 1 if has_vrf else 0))
    # DIRECT modulo of block entropy (NO keccak) feeding an outcome -> e.g. `block.prevrandao % numPlayers`,
    # `blockhash(n) % 100`. Same grind (predict-and-revert / revert-to-reroll). Stricter outcome guard to
    # avoid `block.number % epoch` FPs; skip statements already counted by the keccak loop.
    for m in RNG_ENTROPY.finditer(text):
        semib = text.rfind(";", max(0, m.start() - 200), m.start())
        s0 = semib + 1 if semib > 0 else max(0, m.start() - 200)
        semia = text.find(";", m.end())
        s1 = semia if 0 < semia < m.end() + 120 else m.end() + 120
        stmt = text[s0:s1]
        if "keccak256" in stmt or "chainid" in stmt.lower() or "%" not in stmt:
            continue
        if not RNG_OUTCOME_STRICT.search(text[max(0, m.start() - 300):s1]):
            continue
        ln = lineno(text, m.start())
        if ln in seen:
            continue
        seen.add(ln)
        note = ("DIRECT modulo of block entropy (no keccak) drives an outcome -> predictable RNG; "
                "grindable (predict-and-revert / revert-to-reroll). Use commit-reveal or Chainlink VRF")
        if eoa:
            note += " | EOA-gate = speed bump only (simulate+selective-submit)"
        out.append((rel, ln, "block.<entropy> % n (direct)", note, 0))
    return out


# ── Detector 18b: ERC721/1155 receiver-hook reentrancy (the #1 on-chain-game/NFT bug class) ──
NFT_SAFE = re.compile(r"\b_?safeMint\s*\(|\bsafeBatchTransferFrom\s*\(|\b_?safeTransferFrom\s*\(|\b_safeTransfer\s*\(")
NFT_MINT_HOOK = re.compile(r"\b_?safeMint\s*\(")   # unambiguous: ERC721/1155 mint -> always a receiver hook
NFT_CTX = re.compile(r"\btokenId\b|ERC721|ERC1155|onERC721Received|onERC1155Received|_safeMint|"
                     r"IERC721|IERC1155|\bNFT\b|tokenURI|_mintBatch", re.I)


def det_nft_callback(text, rel):
    """ERC721/1155 `safeMint`/`safeTransferFrom` calls the RECIPIENT's `onERCxxxReceived` hook -- an
    attacker-controlled callback -- and if a state write (supply counter, claimed flag, reward) follows it
    (CEI violation) with no nonReentrant, the recipient reenters mid-mint/claim: re-mint past a supply cap,
    double-claim a reward, or skip a per-address limit. This is the #1 NFT-game root cause (~35% of NFT
    audit findings); det_reentrancy MISSES it because safeMint isn't a low-level `.call`/`.transfer`.
    Scoped to NFT-context files to avoid SafeERC20 `safeTransferFrom` (which has no hook)."""
    out = []
    if not NFT_CTX.search(text):          # not an NFT file -> a bare safeTransferFrom is SafeERC20, skip
        return out
    for m in re.finditer(r"function\s+(\w+)\s*(\([^{};]*?)\{", text, re.S):
        name, blob = m.group(1), m.group(2)
        if not re.search(r"\b(external|public)\b", blob) or re.search(r"\b(view|pure)\b", blob):
            continue
        if GUARD.search(blob):            # nonReentrant -> protected
            continue
        nxt = text.find("function ", m.end())
        body = text[m.end():(nxt if nxt > 0 else m.end() + 1500)]
        sm = NFT_SAFE.search(body)
        if not sm:
            continue
        # _safeMint is always an NFT hook; a safeTransfer needs LOCAL NFT context (else maybe SafeERC20)
        if not NFT_MINT_HOOK.search(body) and not NFT_CTX.search(body):
            continue
        after = body[sm.end():]
        # state write AFTER the hook-triggering call = CEI violation (incl. `counter++` supply bumps,
        # which the shared WRITE regex doesn't catch)
        if WRITE.search(after) or re.search(r"\b\w+\s*(\+\+|--)", after):
            out.append((rel, lineno(text, m.start()), f"function {name}(...)",
                        "ERC721/1155 safeMint/safeTransfer triggers the recipient's onERCxxxReceived hook "
                        "THEN a state write follows (CEI), no nonReentrant -> receiver-hook reentrancy "
                        "(re-mint past supply cap / double-claim / skip per-addr limit). #1 NFT-game bug.", 0))
    return out


# ── Detector 19: swap slippage / deadline guard (sandwich / MEV) ── backlog (basic DeFi)
SWAP_FN = re.compile(r"\b(swapExactTokensFor\w+|swapTokensForExactTokens|swapExactETHFor\w+|"
                     r"swapETHForExact\w+|exactInputSingle|exactInput|exactOutputSingle|exactOutput)\s*\(", re.I)
SWAP_ZERO_MIN = re.compile(
    r"(amountOutMin\w*|amountOutMinimum|minAmountOut|minOut|minReturn\w*|minTokensOut|minDy|minDx)\s*[:=]\s*0\b"
    r"|swapExactTokensFor\w+\s*\(\s*[^,()]+,\s*0\s*,"     # V2 positional: 2nd arg (amountOutMin) == 0
    r"|swapExactETHFor\w+\s*\(\s*0\s*,", re.I)
SWAP_NO_DEADLINE = re.compile(r"deadline\s*[:=]\s*(block\.timestamp|type\s*\(\s*uint\d*\s*\)\s*\.\s*max)", re.I)


def det_swap_guard(text, rel):
    """A swap with no slippage bound (amountOutMin / amountOutMinimum == 0) is a free
    sandwich: an MEV bot front-runs, moves the price, and the victim accepts ANY output.
    A deadline of block.timestamp (or type(uint).max) gives no expiry -> a mempool-held tx
    executes later at a stale price. Basic DeFi hygiene; verify the min-out is derived from
    an oracle/quote, not hardcoded 0. (LEAD: an off-chain-supplied minOut is fine.)"""
    out = []
    for m in SWAP_ZERO_MIN.finditer(text):
        out.append((rel, lineno(text, m.start()), m.group(0)[:70].strip().replace("\n", " "),
                    "swap with amountOutMin == 0 -> NO slippage protection (sandwich/MEV); "
                    "derive min-out from an oracle/quote, not 0", 0))
    for m in SWAP_NO_DEADLINE.finditer(text):
        ctx = text[max(0, m.start() - 220):m.start() + 220]
        if SWAP_FN.search(ctx) or "swap" in ctx.lower():
            out.append((rel, lineno(text, m.start()), m.group(0)[:60].strip().replace("\n", " "),
                        "swap deadline = block.timestamp / uint.max -> no expiry (a mempool-held "
                        "tx can execute later at a stale price)", 1))
    return out


# ── Detector 20: mapping-default-trust (Nomad class, $190M) ── our first studied hack
# A security decision reads a mapping whose DEFAULT (unset = 0 / false / bytes32(0)) wrongly
# satisfies the gate -> an attacker submits an unset key and passes. Nomad: process() did
# require(acceptableRoot(messages[hash])); an unproven message gives messages[hash]==0, and
# confirmAt[0] had been mis-set to non-zero -> any unproven message accepted.
# REASONING-TIER lead (the real root is config/init, not single-line) -> vault heuristic #1.
SEC_GATE = (r"acceptableRoot|confirmAt|provenRoots?|verifiedRoots?|trustedRoots?|knownRoots?|"
            r"validRoots?|merkleRoots?|isProven|isVerified|isAcceptable|isKnownRoot|"
            r"commitments?|nullifiers?")
SEC_NESTED = SEC_GATE + r"|roots?|messages|processedExits?"
SEC_GATE_RE = re.compile(r"\b(" + SEC_GATE + r")\b", re.I)
# guards that explicitly exclude the default value -> the gate is safe
DEFAULT_REJECT = re.compile(r"!=\s*(0\b|0x0|bytes32\(0\)|address\(0\)|false\b)|"
                            r">\s*0\b|\.length\b|\bexists?\b|\bisSet\b", re.I)


def det_mapping_default(text, rel):
    """Nomad class ($190M; our first studied hack): a trust gate reads a mapping whose DEFAULT
    value (unset = 0 / false / bytes32(0)) passes, so an attacker submits an unset key. A
    REASONING-TIER lead (verify by hand; cf. vault heuristic #1) -- two shapes:
    (A) [!] a security mapping indexed by ANOTHER mapping's result on one line (value-as-key);
    (B) [.] a require/if gate over a security mapping with no visible default-rejection (!=0 / >0)."""
    out, seen = [], set()
    # Shape A: SEC mapping/fn taking a nested mapping/array read -> value-as-key (rare, sharp)
    for m in re.finditer(r"\b(" + SEC_NESTED + r")\s*[\[(]\s*\w+\s*\[", text, re.I):
        ln = lineno(text, m.start())
        seen.add(ln)
        out.append((rel, ln, m.group(0)[:48] + "...",
                    "security check fed by ANOTHER mapping's result -> if the inner read defaults "
                    "(unset=0), the gate is evaluated at key 0 (Nomad value-as-key); verify the "
                    "inner can't be the default", 0))
    # Shape B: require/if gate over a SEC mapping with no explicit default-rejection
    for m in re.finditer(r"\b(require|assert|if)\s*\(([^;{]{0,200})", text):
        cond = m.group(2)
        if not SEC_GATE_RE.search(cond):
            continue
        ln = lineno(text, m.start())
        if ln in seen or DEFAULT_REJECT.search(cond):
            continue
        seen.add(ln)
        out.append((rel, ln, (m.group(1) + "(" + cond)[:64].strip().replace("\n", " "),
                    "trust gate reads a security mapping with no visible default-rejection "
                    "(!=0 / >0 / exists) -> can the DEFAULT (unset=0/false) pass it? (Nomad class; verify)", 1))
    return out


# ── Detector 21: strict balance equality (force-feed DoS) ── basic classic
STRICT_BAL = re.compile(
    r"(?:address\s*\([^)]*\)\s*\.\s*balance\b|\b\w+\s*\.\s*balance\b|balanceOf\s*\([^;{}]*\))\s*(?:==|!=)"
    r"|(?:==|!=)\s*(?:address\s*\([^)]*\)\s*\.\s*balance\b|\b\w+\s*\.\s*balance\b|balanceOf\s*\([^;{}]*\))")


def det_strict_balance(text, rel):
    """A strict == / != on an ETH or token balance is brittle: anyone can force ETH in
    (selfdestruct, a pre-funded CREATE2 address, block reward) or transfer tokens IN to
    break the exact match -> the gated path bricks (DoS) or an accounting assumption fails.
    Use >= / <= and track deltas, not absolute equality."""
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("//") or s.startswith("*") or s.startswith("/*"):
            continue
        if STRICT_BAL.search(s):
            out.append((rel, i, s[:85],
                        "strict == / != on a balance (this.balance / balanceOf) -> force-feed "
                        "(selfdestruct / direct transfer) breaks the exact match (DoS / bad "
                        "accounting); use >= or <= and deltas", 0))
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
    ("ARBITRARY external call (bridge-aggregator approval drain)", det_arbcall,
     "Heuristic 7: (address+bytes) param + low-level call -> route to transferFrom = drain."),
    ("SIGNATURE / ecrecover (replay, malleability, no expiry)", det_signature,
     "Raw ecrecover: needs address(0) check + nonce (anti-replay) + deadline (expiry)."),
    ("DOMAIN SEPARATOR cached (cross-chain / fork replay)", det_domain,
     "Pattern 06: EIP-712 separator cached with block.chainid, no recompute -> fork/cross-chain replay."),
    ("UPGRADE safety (unprotected UUPS _authorizeUpgrade)", det_upgrade,
     "Upgrade auth with no owner/role check -> anyone swaps the impl = total takeover."),
    ("UNCHECKED ERC20 return (silent transfer failure)", det_unchecked,
     "Bare transfer/transferFrom return dropped -> USDT/ZRX fail silently; use SafeERC20."),
    ("ERC4626 inflation (first-depositor share-price attack)", det_erc4626,
     "Vault with no _decimalsOffset / dead-shares -> first depositor skews the share price."),
    ("REWARD / claim accounting (double-claim, late marker)", det_reward,
     "Pattern 03: reward payout with no claimed/rewardDebt marker write (or written after transfer)."),
    ("ORACLE usage vs 3-guard checklist", det_oracle,
     "Heuristic 2: staleness(updatedAt) + price>0 + decimals(); + spot-reserve pricing sub-check."),
    ("INTEREST-INDEX inflation (Aave-fork empty-market)", det_index,
     "Pattern 04: liquidityIndex/borrowIndex compounds delta/supply -> empty market inflates it (dTRINITY)."),
    ("LIQUIDATION math (self-liq, rounding, bad-debt)", det_liquidation,
     "Pattern 05: liquidation entrypoint 4-check; [!] if no self-liq guard or rounds-up seize."),
    ("WEAK randomness (predictable on-chain RNG in an outcome path)", det_weak_random,
     "GameFi class: keccak OR direct-modulo of block.timestamp/blockhash/difficulty driving a reward/"
     "mint/raffle outcome -> grindable; an EOA-gate is only a speed bump. Use commit-reveal / Chainlink VRF."),
    ("NFT receiver-hook reentrancy (safeMint/safeTransfer callback)", det_nft_callback,
     "GameFi/NFT #1 class (~35%): ERC721/1155 safeMint/safeTransfer fires the recipient's onERCxxxReceived "
     "hook, then a state write follows (CEI), no nonReentrant -> reenter to re-mint/double-claim. det_reentrancy misses it."),
    ("SWAP slippage / deadline guard (sandwich / MEV)", det_swap_guard,
     "Basic DeFi: amountOutMin==0 = free sandwich; deadline=block.timestamp = no expiry. "
     "Verify min-out is an oracle/quote, not hardcoded 0."),
    ("MAPPING-DEFAULT trust (Nomad: unset key passes a gate)", det_mapping_default,
     "Heuristic 1 / Nomad $190M: a trust gate reads a security mapping whose default (unset=0/"
     "false) passes -> attacker submits an unset key. Reasoning-tier LEAD; verify by hand."),
    ("STRICT balance equality (force-feed DoS)", det_strict_balance,
     "== / != on this.balance or balanceOf is brittle: anyone force-feeds ETH/tokens to break "
     "the exact match -> DoS / bad accounting. Use >= / <= and deltas."),
    ("DANGEROUS primitives", det_danger,
     "delegatecall / tx.origin / selfdestruct / call / open initialize."),
    ("L2 / AA footguns (zkSync: extcodesize EOA-check, isContract sig branch)", det_l2_footgun,
     "zkSync native AA: 'EOA == no code' is false -> isContract/extcodesize-gated auth+signatures bypassable."),
]


def det_key(title):
    """Stable short key for a detector title -> used by the triage ledger so a
    verdict survives wording changes. Check 'sibling' before 'access' (the
    sibling title contains both)."""
    t = title.lower()
    for sub, k in (("sibling", "sibling"), ("access control leads", "access"),
                   ("supply", "supply"), ("receiver-hook", "nftcallback"), ("reentrancy", "reentrancy"),
                   ("arbitrary", "arbcall"), ("signature", "signature"),
                   ("domain", "domain"), ("upgrade", "upgrade"),
                   ("unchecked", "unchecked"), ("erc4626", "erc4626"),
                   ("reward", "reward"), ("oracle", "oracle"),
                   ("interest-index", "index"), ("liquidation", "liquidation"),
                   ("randomness", "weakrand"), ("slippage", "swapguard"),
                   ("mapping-default", "mapdefault"), ("strict balance", "strictbal"),
                   ("dangerous", "danger"), ("footgun", "l2"), ("disabled", "disabled")):
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
