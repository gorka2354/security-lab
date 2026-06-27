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
import sys

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
    r"_check(?:Controller|Manager|Admin|Operator|Gov\w*|Authoriz\w*)\s*\(|"   # fix#34: Balancer/PowerPool BPool inline auth `_checkController()` (NOT input-validators like _checkAmount)
    r"_?require\w*Only\b|_?check\w*Only\b|"   # e.g. requireGovernanceOnly()
    r"_?require\w*Caller\w*\s*\(|"   # fix#33: Liquity/Threshold inline caller-auth (_requireCallerIsBorrowerOperations / _requireCallerIsStabilityPool / _requireCallerIsBOorTroveM) -- the #1 fork-CDP FP source
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
        # fix#35: a SELF-burn (`_burn(_msgSender()/msg.sender, ...)`) is safe -- you can only destroy your OWN
        # balance, no supply-integrity risk (the #1 det_mint FP: every ERC20Burnable.burn). _msgSender() too.
        self_burn = bool(re.search(r"\b_?[Bb]urn\w*\s*\(\s*(?:_msgSender\s*\(\s*\)|msg\.sender\b)", body))
        gated = ("only" in blob.lower() or re.search(r"\b(re)?initializer\b", blob)
                 or INLINE_AUTH.search(blob)   # fix#16: auth modifier in signature, e.g. checkAccess(this.mint.selector)
                 or WARD_MOD.search(blob)   # fix#27: ward-model `auth` / authOrHook modifier
                 or "super.mint(" in body or "super.burn(" in body   # fix#27: thin override -> parent gate (Centrifuge ShareToken)
                 or INLINE_AUTH.search(body) or "msg.sender" in body or self_burn)
        is_test = bool(re.search(r"(^|/)(test|tests|mock|mocks)", rel, re.I))
        if gated:
            note = ("self-burn of the caller's OWN balance -> safe (no supply-integrity risk)" if self_burn
                    else "mint/burn entry, GATED -> verify the gate + that supply stays bounded")
            out.append((rel, lineno(text, m.start()), f"function {name}(...)", note,
                        2 if (is_test or self_burn) else 1))
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


# ── Detector: Pyth / pull-oracle missing guards ── grounded in the Vena finding (2026); det_oracle only does Chainlink
def det_pyth_oracle(text, rel):
    """Pyth (and pull-oracle) price reads that skip the 3 Pyth-specific guards: price>0 (Pyth price is a
    SIGNED int64 -> can be <=0), confidence-interval (.conf; a wide band = unreliable/manipulated), and
    staleness (getPriceUnsafe EXPLICITLY bypasses the freshness check -> needs a manual publishTime guard;
    getPriceNoOlderThan is self-guarding). Naive `int256(price)` straight into valuation = the Vena
    PythAggregatorAdapter class. Chainlink is handled by det_oracle; this fills the pull-oracle gap."""
    out = []
    has_price_guard = bool(re.search(r"\.price\s*[<>=]|price\s*<=?\s*0|price\s*>\s*0|"
                                     r"InvalidPrice|NegativePrice|PriceLessThanZero|require\([^)]*price", text))
    has_conf = bool(re.search(r"\.conf\b|confidence|confInterval|maxConf", text))
    has_publishtime = bool(re.search(r"publishTime|block\.timestamp\s*-|getPriceNoOlderThan|maxAge|staleness", text))
    seen = set()
    for m in re.finditer(r"\b(getPriceUnsafe|getEmaPriceUnsafe|getPriceNoOlderThan|getEmaPriceNoOlderThan|"
                         r"getPrice|getEmaPrice)\s*\(", text):  # the actual price-READ call, not the IPyth type ref
        call = m.group(1)
        ln = lineno(text, m.start())
        if ln in seen:
            continue
        seen.add(ln)
        is_unsafe = call in ("getPriceUnsafe", "getEmaPriceUnsafe", "getPrice", "getEmaPrice")  # no built-in staleness
        self_fresh = call in ("getPriceNoOlderThan", "getEmaPriceNoOlderThan")
        miss = []
        if not has_price_guard:
            miss.append("price>0 (signed int64)")
        if not has_conf:
            miss.append("confidence(.conf)")
        if is_unsafe and not has_publishtime and not self_fresh:
            miss.append("staleness(publishTime)")
        if not miss:
            continue
        prio = 0 if ("price>0 (signed int64)" in miss or "staleness(publishTime)" in miss) else 2
        out.append((rel, ln, call, "Pyth/pull-oracle read MISSING: " + ", ".join(miss)
                    + (" [getPriceUnsafe bypasses freshness]" if is_unsafe and not self_fresh else ""), prio))
    return out


# ── Detector: payable-multicall / msg.value reuse ── classic value-reuse (N deposits for 1 payment)
def det_multicall_value(text, rel):
    """msg.value reused across batched calls. (a) A delegatecall-multicall (multicall/aggregate/batch that
    loops delegatecall(data[i])) keeps the SAME msg.value for EVERY sub-call -> batching N payable calls
    each reading msg.value credits N payments for ONE (the payable-multicall drain; OZ added a guard, many
    forks didn't). (b) msg.value read INSIDE a for-loop -> same value credited per iteration."""
    out = []
    mc = re.search(r"function\s+(multi[cC]all|aggregate|batch\w*)\s*\([^)]*\)[^{;]*\{", text)
    has_dc_loop = bool(mc and re.search(r"delegatecall", text[mc.end():mc.end() + 1500]))
    payable_value = []
    for fm in re.finditer(r"function\s+(\w+)\s*\([^;{]*\bpayable\b[^;{]*\{", text):
        name = fm.group(1)
        if re.match(r"multi|aggregate|batch", name, re.I):
            continue
        nxt = text.find("function ", fm.end())
        body = text[fm.end():(nxt if nxt > 0 else fm.end() + 1200)]
        if "msg.value" in body:
            payable_value.append(name)
    if has_dc_loop and payable_value:
        out.append((rel, lineno(text, mc.start()), f"function {mc.group(1)}(...)",
                    "delegatecall-multicall + payable fn(s) reading msg.value (" + ",".join(payable_value[:3])
                    + ") -> msg.value REUSED across batched sub-calls (N payments for 1); forbid value in "
                    "multicall or track consumed value", 0))
    # (b) msg.value inside a loop body (bounded window, cut at the next function so it can't leak across fns)
    for fm in re.finditer(r"\bfor\s*\([^)]*\)\s*\{", text):
        win = text[fm.end():fm.end() + 400]
        cut = win.find("function ")
        if cut >= 0:
            win = win[:cut]
        if "msg.value" in win:
            out.append((rel, lineno(text, fm.start()), "for(...) { ... msg.value ... }",
                        "msg.value read INSIDE a loop -> same tx value credited each iteration (value-reuse)", 0))
    return out


# ── Detector: read-only reentrancy ── shadow.py #1 blind-spot (Curve/lending class)
def det_readonly_reentrancy(text, rel):
    """Read-only reentrancy: a contract that DOES guard state-changers with nonReentrant but exposes a
    PRICING/VALUE view (get_virtual_price/getReserves/totalAssets/pricePerShare/convertToAssets/exchangeRate)
    that is NOT reentrancy-guarded -> an external integrator (a lending market using this view as an oracle)
    reading it DURING a withdraw/remove_liquidity reentrant callback sees stale/inconsistent state = a wrong
    price (Curve, dozens of lending hacks). Fix = a VIEW-side guard (Twyne's nonReentrantView /
    require(_status != _ENTERED) / _reentrancyGuardEntered). Only fires when the contract is reentrancy-AWARE
    (uses nonReentrant) but left a pricing view un-guarded -- the subtle case det_reentrancy misses."""
    out = []
    if not re.search(r"\bnonReentrant\b|ReentrancyGuard", text):
        return out  # not reentrancy-aware -> plain reentrancy story (det_reentrancy), not the read-only variant
    view_guard = r"nonReentrantView|_reentrancyGuardEntered|notEntered|_status\s*!=\s*_ENTERED|ReentrancyGuardReentrantCall"
    price_view = (r"function\s+(\w*(?:get_virtual_price|getReserves|totalAssets|pricePerShare|getPricePerFullShare|"
                  r"convertToAssets|convertToShares|exchangeRate|sharePrice|virtualPrice|getRate|stEthPerToken)\w*)"
                  r"\s*\([^;{]*\bview\b[^;{]*\{")
    for fm in re.finditer(price_view, text, re.I):
        name = fm.group(1)
        nxt = text.find("function ", fm.end())
        sig_body = text[fm.start():(nxt if nxt > 0 else fm.end() + 600)]
        if re.search(view_guard, sig_body):
            continue  # this view IS reentrancy-guarded (the Twyne nonReentrantView pattern) -> fine
        out.append((rel, lineno(text, fm.start()), f"function {name}(...) view",
                    "pricing/value VIEW is reentrancy-UNGUARDED while the contract guards state-changers with "
                    "nonReentrant -> READ-ONLY REENTRANCY: an integrator reading this mid-withdraw/remove-liquidity "
                    "callback gets stale state = a wrong oracle value (Curve/lending class). Add a view-side guard.", 0))
    return out


# ── Detector 4: dangerous primitives ── (unprotected-init moved to dedicated det_unprotected_init #37)
def det_danger(text, rel):
    out = []
    for pat, note in [(r"\bdelegatecall\b", "delegatecall - storage/context risk"),
                      (r"\btx\.origin\b", "tx.origin - auth bypass / phishing"),
                      (r"\bselfdestruct\b", "selfdestruct"),
                      (r"\.call\{", "low-level call{...} - reentrancy/return check")]:
        for m in re.finditer(pat, text):
            out.append((rel, lineno(text, m.start()), m.group(0), note, 1))
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


# ── Detector 7: signature gaps (ecrecover replay/malleability + ERC-1271 caller-supplied verifier) ── class F
# ERC-1271 verify where the VERIFIER is a decoded calldata STRUCT FIELD (order.signer) not bound to a trusted
# signer -> the attacker passes their own contract returning the magic value, so any signature is "valid". The
# struct-field gate is essential: a BARE-param verifier (`isValidSignatureNow(owner,...)`) is the safe EIP-2612
# permit shape (owner self-authorizes) and is INDISTINGUISHABLE from the MureDistribution bug at T0 (the only
# difference is fund flow: self vs 3rd-party pull) -> that bare-param shape is reasoning-tier (caller-supplied-
# authority invariant-seed in hypothesize.py), NOT flagged here.
SIG1271 = re.compile(r"IERC1271\s*\(\s*(\w+(?:\.\w+)+)\s*\)\s*\.\s*isValidSignature|"
                     r"\bisValidSignatureNow\s*\(\s*(\w+(?:\.\w+)+)\s*,", re.I)
# a nonce/used-digest that is actually CONSUMED (written), not merely declared/read -> real anti-replay.
# Covers: nonces[x]++ / nonces[x]= ; OZ Counters `_nonces[x].increment()` ; OZ 5.x `_useNonce`/`_useCheckedNonce` ;
# a used-digest mapping write. Recognizing .increment() kills the Apiary/OZ-permit FP (Counters-based consumption).
NONCE_CONSUMED = re.compile(r"nonce\w*\s*(?:\[[^\]]*\])?\s*(?:\+\+|--|\+=|-=|=(?!=))|"
                            r"\b(?:used|_used|seen|executed|consumed|invalidated)\w*\s*\[[^\]]+\]\s*=(?!=)|"
                            r"_?nonce\w*\s*(?:\[[^\]]*\])?\s*\.\s*increment|\b_useNonce\b|\b_useCheckedNonce\b|"
                            r"invalidateNonce|\.consume\s*\(", re.I)


def _verifier_bound(text, name):
    """The ERC-1271 verifier struct-field `name` (order.signer) is BOUND/safe if it's the result of an ECDSA
    .recover() or compared (`==`) to a trusted value somewhere in the file (a verified signed order)."""
    full = re.escape(name)
    if re.search(full + r"\s*=\s*[^;\n]*\.recover\s*\(", text):
        return True
    if re.search(r"\b" + full + r"\s*==|==\s*" + full + r"\b", text):
        return True
    return False


def det_signature(text, rel):
    """Class-F signature gaps. (1) Raw ecrecover: empty/malleable sig recovers to address(0) (no zero-check ->
    impersonation); REPLAYABLE with no nonce OR a nonce that's declared-but-never-consumed; never-expiring with
    no deadline. (2) ERC-1271 isValidSignature on a CALLER-SUPPLIED verifier that is a decoded calldata STRUCT
    FIELD (order.signer), not bound to a trusted signer -> the attacker passes a contract returning the magic
    value, so any signature passes (MureDistribution class; the bare-param permit shape is reasoning-tier)."""
    out = []
    # (2) ERC-1271 with an attacker-supplied (calldata-struct) verifier
    for m in SIG1271.finditer(text):
        signer = m.group(1) or m.group(2) or ""
        if _verifier_bound(text, signer):
            continue
        out.append((rel, lineno(text, m.start()), f"isValidSignature({signer})",
                    "ERC-1271 isValidSignature on a CALLER-SUPPLIED verifier (a decoded calldata struct field) not "
                    "bound to a trusted/stored signer -> the attacker passes their own contract returning the magic "
                    "value, so any signature passes (MureDistribution class). Verify the signer is a trusted address "
                    "(or a recovered+compared signer), not taken from calldata.", 0))
    # (1) raw ecrecover guards
    if "ecrecover" in text:
        has_zero = bool(re.search(r"address\(0\)|\bECDSA\b|tryRecover", text))
        has_nonce = bool(re.search(r"\bnonce", text, re.I))
        nonce_consumed = bool(NONCE_CONSUMED.search(text))
        has_deadline = bool(re.search(r"deadline|expir|validUntil|validAfter", text, re.I))
        for m in re.finditer(r"\becrecover\s*\(", text):
            miss = []
            if not has_zero:
                miss.append("address(0) check (malleable/empty sig)")
            if not has_nonce:
                miss.append("nonce (replay)")
            elif not nonce_consumed:
                miss.append("nonce declared but NEVER consumed/incremented (still replayable)")
            if not has_deadline:
                miss.append("deadline (no expiry)")
            note = ("raw ecrecover, file MISSING: " + ", ".join(miss)) if miss else \
                   "raw ecrecover but file has zero/nonce/deadline guards (review)"
            out.append((rel, lineno(text, m.start()), "ecrecover(...)", note, 0 if miss else 2))
        # (1b) Lixir permit drain (2026): recovered signer checked != address(0) but NEVER compared `== owner/
        # signer` -> any well-formed sig recovering to a NONZERO addr is accepted = forgeable permit/auth.
        binds_signer = bool(re.search(
            r"==\s*(owner|_owner|signer|signatory|expectedSigner|maker|trustedSigner)\b|"
            r"\b(owner|_owner|signer|signatory|expectedSigner|maker|trustedSigner)\s*==|"
            r"isSigner\s*\[|authorizedSigner|signers\s*\[|isValidSigner|_trustedSigner", text))
        if "address(0)" in text and not binds_signer:
            mm = next(re.finditer(r"\becrecover\s*\(", text), None)
            out.append((rel, lineno(text, mm.start()) if mm else 0, "ecrecover(...) result not bound to owner",
                        "ecrecover result validated as NONZERO (address(0) check) but NEVER compared `== owner/"
                        "signer` -> any well-formed sig recovering to a nonzero address passes = FORGEABLE "
                        "permit/auth (Lixir permit drain, 2026). Bind the recovered address to the expected signer.", 0))
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


# ── Detector: custom-vault share-price rounding (Thetanuts $2.1M, non-ERC4626) ──
VAULT_FN = re.compile(r"function\s+\w*(?:redeem|withdraw|mint|deposit|convertTo|preview|claim|"
                      r"pricePerShare|sharesToAssets|assetsToShares|burn)\w*", re.I)
SHARE_DIV = re.compile(r"\*[\w.\[\]()\s]+?/\s*(?:total[_]?Supply|total[_]?Shares|_?totalSupply|_?totalShares)\b", re.I)
# Real protection = a PERMANENT supply floor (minimum / dead-shares / virtual-shares), NOT a `totalSupply==0`
# first-deposit case -- the Thetanuts bug was supply SHRINKING toward 0 via burns, which a zero-case never guards.
SHARE_PROT = re.compile(r"MINIMUM_|_decimalsOffset|dead[_ ]?shares?|0xdead|virtual[_ ]?shares|"
                        r"_mint\s*\(\s*(?:address\s*\(\s*0|0x0|address\s*\(\s*this)", re.I)


def det_vault_share_math(text, rel):
    """A custom vault prices shares as `X * amount / totalSupply` (or /totalShares) with NO low/zero-supply
    protection -> when supply shrinks toward 0 (burns) the per-share backing explodes and redeem returns
    inflated value, while mint rounds shares to ~0 (free) -> mint-and-redeem + flashloan drains it
    (Thetanuts deprecated Index Vault, 2026-06, ~$2.1M). Generalizes det_erc4626's first-depositor inflation
    to ANY custom (non-ERC4626) vault. Cedes the ERC4626 case to det_erc4626. Suppressed by a minimum /
    dead-shares / virtual-shares / totalSupply==0 guard. T3 LEAD: verify the near-empty-supply window."""
    if re.search(r"\bERC4626\b", _strip_comments(text)):
        return []                                   # det_erc4626 owns the ERC4626 flavor (code, not a comment)
    if not VAULT_FN.search(text) or not SHARE_DIV.search(text):
        return []
    if SHARE_PROT.search(text):
        return []                                   # minimum / dead-shares / zero-guard closes the low-supply window
    out = []
    for i, line in enumerate(text.splitlines(), 1):  # line-based + comment-skip (det_precision idiom)
        s = line.strip()
        if not s or s.startswith(("//", "*", "/*")):
            continue
        code = s.split("//")[0]
        if "*/" in code or "/*" in code:
            continue
        if SHARE_DIV.search(code):
            out.append((rel, i, s[:80],
                    "custom-vault share math (X * amount / totalSupply) with no minimum/dead-shares/zero-supply "
                    "guard -> as totalSupply shrinks toward 0 the per-share backing explodes (redeem inflates) "
                    "and mint rounds shares to ~0 (free) -> mint-and-redeem + flashloan drain (Thetanuts $2.1M). "
                    "Verify the near-empty-supply window; add a minimum/dead-shares seed.", 0))
    return out


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


# ---- vault gap-analysis detectors (DeFiVulnLabs 48-types vs our coverage) ----
DOWNCAST = re.compile(r"\b(u?int(\d{1,3}))\s*\(")


def _balanced_arg(s, start):
    """The substring inside the parens opened just before `start` (single line); None if unbalanced."""
    depth, buf = 1, []
    for ch in s[start:]:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return "".join(buf)
        buf.append(ch)
    return None


def det_downcast(text, rel):
    """Casting a COMPUTED value to a smaller int -- uint128(a + b), uint64(x * rate) -- silently TRUNCATES
    in all 0.8.x: a result exceeding the smaller type wraps (lost funds / broken accounting). High-signal
    only: we flag casts whose arg does ARITHMETIC (a bare uint8(stat) / uint16(field) is intentional
    packing -> skipped, else games drown the report). Also skips uint160 (address idiom) + literals."""
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith(("//", "*", "/*")):
            continue
        for m in DOWNCAST.finditer(s):
            full, bits = m.group(1), int(m.group(2))
            if bits == 0 or bits >= 256 or bits == 160 or bits % 8 != 0:
                continue  # int256 = no truncation; uint160 = address idiom; non-/8 = not a real type
            arg = _balanced_arg(s, m.end())
            if not arg:
                continue
            a = arg.strip()
            if a[:1].isdigit() or a.startswith(("0x", "block.timestamp", "block.number")):
                continue  # literal / block-time source can't overflow -> safe
            if not re.search(r"[+\-*/]|<<", a):
                continue  # a bare var/field cast is usually intentional packing -> skip (precision > recall)
            out.append((rel, i, s[:90],
                        f"downcast {full}(<arithmetic>) -> SILENT truncation if the result exceeds "
                        f"type({full}).max -> bound it", 1))
            break
    return out


DIV_BEFORE_MUL = re.compile(r"/\s*[\w.()\[\]]+\s*\*")


def det_precision(text, rel):
    """`a / b * c` (or `(a/b)*c`) divides BEFORE multiplying -> the division truncates first and the
    multiply can't recover the lost precision (rounding favors someone). Reorder to multiply first: a*c/b."""
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith(("//", "*", "/*")):
            continue
        code = s.split("//")[0]
        if "*/" in code or "/*" in code:  # block-comment fragment -> the */ would false-match
            continue
        if DIV_BEFORE_MUL.search(code):
            out.append((rel, i, s[:90],
                        "divide-before-multiply -> precision loss (the divide truncates first); "
                        "reorder to multiply first", 1))
    return out


# ── Detector: decimal-scaling truncation (bridge/wrapper non-18 token; ZKFair gas-token, bridge playbook E) ──
_DEC_FACTOR = (r"\w*(?:decimal[_]?diff\w*|decimals?[_]?factor|scal\w*factor|conversion\w*factor|"
               r"scaling\w*factor|normaliz\w*factor)\w*")
DECIMAL_SCALE = re.compile(r"[*/]=?\s*" + _DEC_FACTOR + r"\b|\b" + _DEC_FACTOR + r"\s*[*/]", re.I)


def det_decimal_scale(text, rel):
    """A bridge/wrapper scales an amount by a DECIMALS-difference factor via a LONE mul/div (`amount /= factor`
    / `amount *= factor`) -- NOT a divide-before-multiply (det_precision's domain). The division TRUNCATES (dust
    loss / round-to-zero) and the */ asymmetry can break the round-trip & locked==minted invariant on non-18
    tokens (the ZKFair gas-token shape; bridge playbook E). T2 LEAD: verify the sub-divisor amount loss AND that
    the deposit-scale and withdraw-scale are EXACT inverses. Line-based + comment-skip (a comment can't fire it)."""
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith(("//", "*", "/*")):
            continue
        code = s.split("//")[0]
        if "*/" in code or "/*" in code:
            continue
        if DECIMAL_SCALE.search(code):
            out.append((rel, i, s[:90],
                        "amount scaled by a decimals-difference factor (lone mul/div, not divide-before-multiply) "
                        "-> the divide truncates (dust / round-to-zero) and a */ asymmetry breaks the round-trip / "
                        "locked==minted invariant on non-18 tokens (ZKFair gas-token class). Verify sub-divisor loss "
                        "+ that deposit and withdraw scaling are exact inverses.", 0))
    return out


ENCODE_PACKED = re.compile(r"abi\.encodePacked\s*\(")


def _is_dynamic_param(arg, scope):
    """True if `arg` is declared as a DYNAMIC type (array `T[]`, `bytes`, or `string`) in the scope (the enclosing
    function's params) -> it packs with no length prefix in abi.encodePacked. A constant/literal/fixed arg is False."""
    if not arg:
        return False
    a = re.escape(arg)
    return bool(re.search(r"\b\w+\s*\[\s*\]\s*(?:calldata|memory|storage)?\s+" + a + r"\b", scope)      # T[] name
                or re.search(r"\b(?:bytes|string)\s+(?:calldata|memory|storage)?\s*" + a + r"\b", scope))  # bytes/string name


def det_encodepacked(text, rel):
    """keccak256(abi.encodePacked(a, b, ...)) HASH-COLLIDES when two ADJACENT args are dynamic:
    encodePacked([A,B],[C]) == encodePacked([A],[B,C]) -> the same hash/signature accepts a re-partitioned
    input. [!] when >=2 ADJACENT args are dynamic PARAMS (array/bytes/string) -- the real collision primitive
    (Gigaverse ImportExportSystem `itemIds||itemAmounts` signed export -> item over-mint). [.] otherwise (a
    'verify the types' lead). All-fixed args (uint/address/bytes32) and a single dynamic arg are safe."""
    out = []
    for m in ENCODE_PACKED.finditer(text):
        semi = text.rfind(";", 0, m.start())
        brace = text.rfind("{", 0, m.start())
        stmt = text[max(semi, brace) + 1:m.start()]               # the assignment/expression up to encodePacked
        if "keccak256" not in stmt and "sha256" not in stmt:       # only HASHED encodePacked collides meaningfully
            continue
        depth, k, buf, parts = 1, m.end(), "", []                  # depth-1 split of the encodePacked args
        while k < len(text) and depth > 0:
            ch = text[k]
            if ch == "(":
                depth += 1; buf += ch
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    break
                buf += ch
            elif ch == "," and depth == 1:
                parts.append(buf); buf = ""
            else:
                buf += ch
            k += 1
        parts.append(buf)
        if len(parts) < 2:
            continue
        # only a BARE identifier (the whole array/bytes) is dynamic; `arr[i]` (one element), `a.b`, `f(x)`,
        # and literals are NOT -- this kills the `encodePacked(leaves[0], leaves[1])` Merkle-element FP.
        args = [(re.match(r"\s*([A-Za-z_]\w*)\s*$", p) or [None, ""])[1] for p in parts]
        fs = text.rfind("function ", 0, m.start())
        scope = text[fs:m.start()] if fs >= 0 else text[:m.start()]
        dyn = [_is_dynamic_param(a, scope) for a in args]
        ln = lineno(text, m.start())
        if any(dyn[i] and dyn[i + 1] for i in range(len(dyn) - 1)):  # 2+ ADJACENT dynamic params = the collision
            out.append((rel, ln, "keccak256(abi.encodePacked(...,DYN,DYN,...))",
                        "2+ ADJACENT DYNAMIC args (array/bytes/string PARAMS) in a hashed/signed abi.encodePacked -> "
                        "the boundary is ambiguous: a player re-partitions the input to the SAME hash -> signature/"
                        "commitment collision (Gigaverse ImportExport itemIds||itemAmounts -> item over-mint). Use "
                        "abi.encode (length-prefixed) or EIP-712 typed data.", 0))
        else:
            out.append((rel, ln, "keccak256(abi.encodePacked(2+ args))",
                        "abi.encodePacked(2+ args) in a hash -> verify no two ADJACENT dynamic (string/bytes/array) "
                        "args (hash collision); use abi.encode if so", 1))
    return out


PULL_IN = re.compile(r"\b(?:safeTransferFrom|transferFrom)\s*\(")
BAL_MEASURE = re.compile(r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)|balanceBefore|balanceAfter|amountReceived|_received\b")


def det_feeontransfer(text, rel):
    """Pulling tokens IN via transferFrom and crediting the REQUESTED amount (not the measured balance
    delta) over-credits on a fee-on-transfer / deflationary token. Flagged only when the file pulls to
    address(this) and NEVER measures a balanceOf(this) delta (the standard mitigation)."""
    if not PULL_IN.search(text) or BAL_MEASURE.search(text):
        return []
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith(("//", "*", "/*")):
            continue
        if PULL_IN.search(s) and "address(this)" in s.replace(" ", ""):
            out.append((rel, i, s[:90],
                        "transferFrom pulls to address(this) but the file never measures a balanceOf(this) "
                        "delta -> a fee-on-transfer token over-credits; credit the MEASURED received amount", 1))
    return out


STRUCT_WITH_MAP = re.compile(r"struct\s+\w+\s*\{[^}]*\bmapping\s*\(", re.S)
DELETE_STMT = re.compile(r"\bdelete\s+[\w.\[\]]+")


def det_delete_mapping(text, rel):
    """`delete x` of a struct that CONTAINS a mapping does NOT clear the mapping (Solidity can't) -> stale
    entries survive (replay / bad accounting). Flagged when the file defines a struct-with-mapping AND deletes."""
    if not STRUCT_WITH_MAP.search(text) or not DELETE_STMT.search(text):
        return []
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith(("//", "*", "/*")):
            continue
        if DELETE_STMT.search(s):
            out.append((rel, i, s[:90],
                        "delete of a struct that may contain a mapping leaves the mapping UNCLEARED "
                        "(stale state) -> verify this delete's type has no nested mapping", 1))
    return out


PRE08_PRAGMA = re.compile(r"pragma\s+solidity\s+[\^>=~]*\s*0\.[0-7]\b")
UNCHECKED_BLOCK = re.compile(r"\bunchecked\s*\{")


def det_overflow(text, rel):
    """Arithmetic overflow/underflow: a PRE-0.8 pragma has NO built-in checks (the classic counterfeiting
    bug), and an `unchecked { }` block in 0.8+ opts OUT of them. 0.8.x outside unchecked reverts on overflow,
    so a modern target's risk lives in its unchecked blocks -> verify the math there can't wrap."""
    out = []
    pre08 = False
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not pre08 and PRE08_PRAGMA.search(s):
            pre08 = True
            out.append((rel, i, s[:90],
                        "pre-0.8 pragma -> arithmetic has NO overflow/underflow protection (use 0.8.x or SafeMath)", 0))
        if s.startswith(("//", "*", "/*")):
            continue
        if UNCHECKED_BLOCK.search(s):
            out.append((rel, i, s[:90],
                        "unchecked{} opts OUT of 0.8 overflow checks -> verify the arithmetic inside can't wrap", 1))
    return out


FLASHLOAN_CB = re.compile(
    r"function\s+(onFlashLoan|executeOperation|receiveFlashLoan|onMorphoFlashLoan|"
    r"uniswapV2Call|uniswapV3SwapCallback|pancakeCall|DPPFlashLoanCall)\s*\(")


def det_flashloan(text, rel):
    """A flash-loan / swap CALLBACK (onFlashLoan/executeOperation/uniswapV2Call/...) that doesn't verify the
    INITIATOR was itself AND that msg.sender is the real lender/pool lets anyone invoke it with crafted
    params -> drains the contract's approvals / spoofs a loan. Flag callbacks whose body lacks that check."""
    out = []
    for m in FLASHLOAN_CB.finditer(text):
        name = m.group(1)
        window = text[m.end():m.end() + 800]
        nxt = window.find("function ")  # don't bleed into the next function
        if nxt != -1:
            window = window[:nxt]
        if not re.search(r"initiator\s*==|==\s*initiator|msg\.sender\s*==|==\s*msg\.sender|"
                         r"require\s*\([^;)]*sender|onlyPool|onlyLender|onlyVault", window):
            ln = text[:m.start()].count("\n") + 1
            out.append((rel, ln, m.group(0).strip()[:90],
                        f"flash/swap callback {name}() with NO initiator/sender check -> anyone calls it with "
                        "crafted params (approval drain / spoofed loan); require initiator==self + msg.sender==pool", 0))
    return out


# ---- operator-power / RUG class (scam-game + meme-token backdoors; defensive: "who can steal/trap you") ----
def _fn_body(text, start):
    """The {...} body of the function whose ')' is near `start` (first '{' after start, brace-balanced)."""
    i = text.find("{", start)
    if i < 0:
        return None
    depth = 0
    for j in range(i, min(len(text), i + 4000)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[i:j + 1]
    return text[i:i + 4000]


OWNER_GATE = re.compile(r"onlyOwner|onlyAdmin|onlyGov\w*|onlyRole|onlyOperator|onlyTreasury|onlyDev|"
                        r"require\s*\([^;{]*\bowner\b|if\s*\([^;{)]*\b(?:owner|admin)\b", re.IGNORECASE)
RUG_DRAIN = re.compile(r"function\s+(\w*(?:sweep|rescue|recover|salvage|emergencyWithdraw|drain|skim|"
                       r"withdrawAll|withdrawToken|withdrawStuck|withdrawEth|claimTokens|retrieve)\w*)\s*\(",
                       re.IGNORECASE)


def det_owner_drain(text, rel):
    """An OWNER-gated sweep/rescue/emergencyWithdraw/withdrawToken that moves the contract's balance out is the
    canonical RUG lever (and a centralization risk in 'legit' code). Verify it can only take STRAY tokens, not
    user deposits / the core asset."""
    out = []
    for m in RUG_DRAIN.finditer(text):
        if OWNER_GATE.search(text[m.start():m.start() + 400]):
            ln = text[:m.start()].count("\n") + 1
            out.append((rel, ln, m.group(1)[:60],
                        f"owner-gated drain `{m.group(1)}` -> operator can pull contract funds; verify it can't "
                        "take user deposits / the core asset (rug / centralization)", 1))
    return out


FEE_SETTER = re.compile(r"function\s+((?:set|update|change)\w*(?:Fee|Fees|Tax|Taxes|Rate|Bps|Percent)\w*)\s*\(",
                        re.IGNORECASE)
FEE_BOUND = re.compile(r"require\s*\([^;{]*[<>]=?|[<>]=?\s*\w*(?:MAX|LIMIT|CAP|DENOM|PRECISION)|\brevert\b|assert\s*\(",
                       re.IGNORECASE)


def det_fee_backdoor(text, rel):
    """A fee/tax setter with NO upper bound lets the operator set 100% -> a honeypot/rug (you deposit, the tax
    eats it). Flag set*Fee/set*Tax/... whose body has no bounding require -> verify a hard cap."""
    out = []
    for m in FEE_SETTER.finditer(text):
        body = _fn_body(text, m.end())
        if body is not None and not FEE_BOUND.search(body):
            ln = text[:m.start()].count("\n") + 1
            out.append((rel, ln, m.group(1)[:60],
                        f"fee/tax setter `{m.group(1)}` with NO upper bound -> operator can set 100% "
                        "(honeypot/rug); verify a hard cap (require(fee <= MAX))", 1))
    return out


HONEYPOT_LEVER = re.compile(r"function\s+(\w*(?:blacklist|blocklist|setBots?|addBots?|banAddr\w*|"
                            r"enableTrading|setTrading\w*|setMaxTx\w*|setMaxWallet\w*|setMaxSell\w*|"
                            r"setSwapEnabled|setCooldown|setTradingStatus)\w*)\s*\(", re.IGNORECASE)


def det_honeypot_lever(text, rel):
    """Owner levers that FREEZE users or block sells (blacklist/setBots/enableTrading/setMaxTx) are the
    honeypot / exit-scam toolkit -- and a real centralization risk in 'normal' tokens too (USDC has a blacklist).
    Flag owner-gated levers -> know who can trap holders."""
    out = []
    for m in HONEYPOT_LEVER.finditer(text):
        if OWNER_GATE.search(text[m.start():m.start() + 300]):
            ln = text[:m.start()].count("\n") + 1
            out.append((rel, ln, m.group(1)[:60],
                        f"owner lever `{m.group(1)}` can freeze/block exits (honeypot / exit-scam / "
                        "centralization -- know who can trap holders)", 1))
    return out


# ── Detector 33: reward-FORMULA accumulator inside the balance-multiply (Synthetix mis-bracket) ──
# posi-vaults (PositionExchange) class, found by the L4 read but MISSED by recon-32 (it is a math-SHAPE
# bug, not an access/marker/RNG pattern). Synthetix earned() is
#   balance.mul(rPT - paid).div(1e18).add(rewards)      <- stored reward added OUTSIDE the .mul(balance)
# The bug moves .add(rewards) INSIDE the .mul(...) argument:
#   balance.mul( (rPT - paid).div(1e18).add(rewards) )  == balance*delta + balance*rewards
# so every updateReward (which writes earned() back into `rewards`) re-multiplies the stored reward by the
# balance -> ~balance^2 reward inflation -> reward drain / harvest insolvency. We flag a per-user reward
# accumulator that is summed INSIDE a .mul(balance) / balance*(...) instead of outside it.
_ACC_RE = (r"\b(?:rewards?|rewardDebt|rewardsOwed|owed|unclaimed|"
           r"pendingReward\w*|accruedReward\w*|userReward\w*)\b")
_REW_ACC = re.compile(_ACC_RE, re.I)
# a multiplicand that is a user balance/stake/amount/shares -- the quantity the reward must be added OUTSIDE of
_BAL_LHS = (r"(?:balanceOf\s*\([^;{}]{0,80}?\)|"
            r"\b\w*(?:[Bb]alance|[Aa]mount|[Ss]hares?|[Ss]tak\w*|[Dd]eposit\w*|[Ll]p\w*|[Ll]iquidity)\w*)")
_BAL_MUL = re.compile(_BAL_LHS + r"\s*\.\s*mul\s*\(")
_BAL_OPMUL = re.compile(_BAL_LHS + r"\s*\*\s*\(")


def _match_paren(text, open_idx):
    """open_idx points AT a '('. Return the index just AFTER its matching ')', or -1 if unbalanced.
    Walks char-by-char so it spans newlines (the buggy earned() is written across several lines)."""
    depth = 0
    for i in range(open_idx, len(text)):
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i + 1
    return -1


def det_reward_formula(text, rel):
    """A Synthetix-style reward view that ADDS the stored per-user reward accumulator INSIDE
    .mul(balance) / balance*(...) instead of outside -> ~balance^2 reward inflation -> drain
    (posi-vaults class). Correct: `balance.mul(delta).add(rewards)`; bug: `balance.mul(delta.add(rewards))`.
    We extract the balanced .mul(...) / *(...) argument and flag a reward accumulator summed inside it."""
    out, seen = [], set()
    for pat, is_mul in ((_BAL_MUL, True), (_BAL_OPMUL, False)):
        for m in pat.finditer(text):
            open_idx = text.find("(", m.end() - 1)
            if open_idx < 0:
                continue
            close = _match_paren(text, open_idx)
            if close < 0:
                continue
            arg = text[open_idx + 1:close - 1]
            if not _REW_ACC.search(arg):                 # a stored reward term appears inside the multiply
                continue
            if is_mul:
                if not re.search(r"\.\s*add\s*\(", arg):  # ...and it's being .add()ed in (not just read)
                    continue
            elif "+" not in arg:                          # operator form: ...and joined with a '+'
                continue
            ln = lineno(text, m.start())
            if ln in seen:
                continue
            seen.add(ln)
            out.append((rel, ln, re.sub(r"\s+", " ", text[m.start():close])[:70],
                        "reward accumulator added INSIDE .mul(balance) / balance*(...) instead of OUTSIDE "
                        "-> stored reward re-multiplied by balance each update -> ~balance^2 inflation -> "
                        "reward drain / harvest insolvency (Synthetix mis-bracket; posi-vaults class). "
                        "Verify the earned()/pending() bracketing.", 0))
    return out


# ── Detector 34: spot-AMM-as-oracle (the #1 DeFiHackLabs class, every year 2021-2026, ~100+ hacks) ──
# A value-bearing decision (mint/borrow/collateral/redeem/reward) priced off a SAME-TX manipulable spot source
# (getReserves / balanceOf(pair) / getAmountsOut / pricePerShare / get_virtual_price / slot0) with no TWAP/Chainlink
# on the path -> flashloan moves it, protocol reads it, attacker profits, unwinds. recon's oracle-staleness only
# checks Chainlink freshness; this catches the spot-source family (PancakeBunny/Cream/EGD/UwuLend/Moonwell/GMX...).
SPOT_ORACLE = re.compile(
    r"\.getReserves\s*\(|\bgetPricePerFullShare\s*\(|\bpricePerShare\s*\(|"
    r"\bget_virtual_price\s*\(|\.slot0\s*\(", re.I)
# a LENDING/VAULT VALUATION sink (where a manipulable price IS a bug) -- NOT swap/LP math (where reserves are
# the legitimate input). Narrowed after a real FP pass on Uniswap/Velodrome cores.
VALUE_SINK = re.compile(
    r"\b(borrow|collateral|liquidat|redeem|reward|payout|valueOf|debt|exchangeRate|healthFactor|"
    r"_mint|sharesFor|assetsFor|getUnderlyingPrice|getAssetPrice)\w*", re.I)
# a manipulation-resistant source on the path -> NOT a spot-oracle bug
TWAP_SAFE = re.compile(
    r"latestRoundData|\bconsult\s*\(|\bobserve\s*\(|twap|timeWeighted|AggregatorV3|chainlink|updatedAt", re.I)
# AMM-internal fns where spot reserves ARE the legitimate input (swap/LP/quote math), not an external oracle -> skip
SPOT_AMM_FN = re.compile(r"^(_?swap|add_?liquidity|remove_?liquidity|quote|_?update|sync|skim|getAmounts?(In|Out)|_v[23])", re.I)


def det_spot_oracle(text, rel):
    """A borrow/collateral/redeem/reward VALUATION priced from a SAME-TX manipulable spot source
    (getReserves/pricePerShare/get_virtual_price/slot0) with no TWAP/Chainlink on the path = the #1 DeFiHackLabs
    root cause. recon's oracle-staleness only checks Chainlink freshness; this catches the spot-AMM-as-oracle
    family (PancakeBunny $45M, Cream $130M, EGD, UwuLend, Moonwell, GMX $41M). AMM-core swap/LP fns are skipped
    (there the reserves ARE the legitimate input, not an external oracle)."""
    out = []
    for m in re.finditer(r"function\s+(\w+)\s*(\([^{};]*?)\{", text, re.S):
        name = m.group(1)
        if SPOT_AMM_FN.search(name):   # swap/addLiquidity/quote -> reserves are the point here, not an oracle
            continue
        nxt = text.find("function ", m.end())
        body = text[m.end():(nxt if nxt > 0 else m.end() + 1200)]
        sm = SPOT_ORACLE.search(body)
        if sm and VALUE_SINK.search(body) and not TWAP_SAFE.search(body):
            out.append((rel, lineno(text, m.start()), f"function {name}(...) {sm.group(0).strip()[:24]}",
                        "spot AMM/share source (getReserves/pricePerShare/get_virtual_price/slot0) feeds a "
                        "borrow/collateral/redeem/reward valuation with NO TWAP/Chainlink -> flashloan price-manip "
                        "(the #1 DeFiHackLabs class). Verify the price can't be moved in-tx.", 0))
    return out


# ── Detector 35: self-transfer balance inflation (LPC/SSS/GPU class, ~6 DeFiHackLabs hacks) ──
# A custom token transfer that caches BOTH balances[from] AND balances[to] into locals, then writes both back
# from the stale cache with no from==to guard: for a self-transfer (from==to) the `to` write overwrites the
# `from` debit using the stale to-cache + amount => balance inflates for free. OZ's _update caches only `from`
# and uses `+=` for the credit, so it is NOT flagged.
# The bug's true tell is the WRITE-BACK: both balances are written from a PRE-CAPTURED local (`_balances[from] =
# senderBalance.sub(amount)` + `_balances[to] = recipientBalance.add(...)`). For a self-transfer the `to` write
# overwrites the `from` debit using the stale local -> free inflation. This matches the direct-cache (GPU) AND the
# tuple-cache-via-helper (LPC `(bool,uint senderBalance)=_updateBalance(sender)`) variants. The safe in-place form
# `balances[to] = balances[to].add(v)` (UniswapV2ERC20) and OZ's `_balances[to] += v` do NOT match (RHS is the
# mapping itself / a compound `+=`, not a bare local), so they are not flagged.
_WB_FROM = re.compile(r"(?:_balances|balances|balanceOf|_balanceOf|_tOwned|_rOwned)\s*\[\s*"
                      r"(?:from|sender|_from|src)\s*\]\s*=\s*(\w+)\s*[.\-]", re.I)
_WB_TO = re.compile(r"(?:_balances|balances|balanceOf|_balanceOf|_tOwned|_rOwned)\s*\[\s*"
                    r"(?:to|recipient|_to|dst)\s*\]\s*=\s*(\w+)\s*[.+]", re.I)
_BAL_NAMES = {"_balances", "balances", "balanceof", "_balanceof", "_towned", "_rowned"}
_SELF_GUARD = re.compile(r"\bfrom\s*[=!]=\s*to\b|\b(?:sender|src)\s*[=!]=\s*(?:recipient|dst|to)\b|"
                         r"require\s*\([^;]*[!=]=\s*(?:to|recipient|dst)", re.I)


def det_self_transfer(text, rel):
    """Custom token transfer that writes BOTH balances back from pre-captured locals (`_balances[from]=fromBal-amt`
    + `_balances[to]=toBal+amt`) with no from==to guard -> a self-transfer overwrites the debit with the stale
    to-local -> free balance inflation (LPC/SSS/GPU DeFiHackLabs class). OZ's `+=` credit and the in-place
    `balances[x]=balances[x].op(v)` form are NOT flagged (RHS is a compound-op / the mapping itself, not a local)."""
    out = []
    for m in re.finditer(r"function\s+(\w+)\s*(\([^{};]*?)\{", text, re.S):
        name = m.group(1)
        if not re.search(r"transfer|_update", name, re.I):
            continue
        nxt = text.find("function ", m.end())
        body = text[m.end():(nxt if nxt > 0 else m.end() + 2400)]
        mf = _WB_FROM.search(body)
        mt = _WB_TO.search(body)
        if (mf and mt and mf.group(1).lower() not in _BAL_NAMES and mt.group(1).lower() not in _BAL_NAMES
                and not _SELF_GUARD.search(body)):
            out.append((rel, lineno(text, m.start()), f"function {name}(...)",
                        "custom transfer writes BOTH balances from pre-captured locals with no from==to guard -> "
                        "self-transfer (from==to) overwrites the debit with the stale to-local -> free balance "
                        "inflation (LPC/SSS/GPU class). Add a from==to guard or use += for the credit.", 0))
    return out


# ── Detector 36: pair-reserve mutation (reflection/deflationary BSC class, ~30+ DeFiHackLabs hacks) ──
# A custom token / public fn that calls pair.sync()/skim() or burns the DEX pair's balance from an UNPRIVILEGED
# path -> shrinks the pair's token reserve -> constant-product overvalues the attacker's tokens -> swap dust for
# the paired asset (BIGFI, LAURA, BYToken, MTToken, YSDAO, the 9+ reflection-token hacks of 2023). Owner-gated = ok.
# burn/balance-mutation TARGETING a pair/LP address = the token-side reserve drain (strong, UNIQUE signal).
PAIR_BURN = re.compile(r"\b_?burn\s*\(\s*(?:address\s*\(\s*)?"
                       r"(?:uniswapV2Pair|\w*[Pp]air\w*|\w*[Ll][Pp]\w*|pair|lp)\b", re.I)
# a sync/skim CALL re-syncs reserves -- only the EXPLOIT when called from a reflection/deflation token, NOT from
# DEX router/pair periphery (which sync legitimately) -> gate this branch behind reflection markers.
PAIR_SYNC = re.compile(r"\.sync\s*\(\s*\)|\.skim\s*\(", re.I)
REFLECTION_MARK = re.compile(r"_reflectFee|_rOwned|_tOwned|isExcluded|_taxFee|_liquidityFee|reflectionFromToken|"
                             r"_getRate\b|triggerAutoBurn|autoBurn|\brebase\b|_takeLiquidity|\bdeliver\s*\(", re.I)


def det_pair_reserve_mutation(text, rel):
    """Token-side DEX-reserve drain: an unprivileged path that BURNS the pair's balance (always suspicious) or,
    in a reflection/deflationary token, calls pair.sync()/skim() to re-sync the shrunk reserve -> constant-product
    overvalues the attacker's tokens (BIGFI/LAURA/BYToken/MTToken/YSDAO, ~30+ DeFiHackLabs hacks). DEX router/pair
    sync (no reflection markers) and owner/auth-gated ops are NOT flagged."""
    out, seen = [], set()
    is_reflection = REFLECTION_MARK.search(text) is not None
    for rx, needs_reflection in ((PAIR_BURN, False), (PAIR_SYNC, True)):
        if needs_reflection and not is_reflection:
            continue   # bare sync/skim in a non-reflection contract = DEX periphery, legit -> skip the branch
        for m in rx.finditer(text):
            fn_start = text.rfind("function ", 0, m.start())
            if fn_start < 0:
                continue
            brace = text.find("{", fn_start)
            fn_head = text[fn_start:brace + 1] if brace > 0 else ""
            scope = text[fn_start:m.end() + 200]
            if "only" in fn_head.lower() or INLINE_AUTH.search(scope) or WARD_MOD.search(fn_head):
                continue   # admin/auth-gated reserve op is legitimate
            ln = lineno(text, m.start())
            if ln in seen:
                continue
            seen.add(ln)
            out.append((rel, ln, m.group(0).strip()[:40],
                        "token-side pair-balance burn or reflection-token pair.sync()/skim() -> crashes the DEX "
                        "reserve so the constant-product curve overvalues the attacker's tokens (reflection/"
                        "deflationary BSC class: BIGFI/LAURA/BYToken). Verify no flashloan triggers it + gate it.", 0))
    return out


# ── Detector 37: unprotected initializer (front-runnable ownership/role grab) ── DeFiHackLabs class E
# An external/public `initialize`/`init` that grants ownership / an admin role with NO `initializer` modifier, no
# `only*`/auth modifier, and no manual one-shot flag -> anyone can front-run the deploy (or re-init the proxy /
# call it on the implementation) and seize the contract (DaoMaker, Telcoin, PikeFinance, Renegade).
INIT_NAME = re.compile(r"^(?:initiali[sz]e|reinitiali[sz]e|init|__\w*_?init)\w*$", re.I)
INIT_AUTHORITY = re.compile(
    r"\b_?owner\s*=(?!=)|\b_?admin\s*=(?!=)|\b_?governance\s*=(?!=)|"
    r"_transferOwnership|transferOwnership\s*\(|__Ownable_init|__AccessControl\w*_init|"
    r"_grantRole|_setupRole|grantRole\s*\(|DEFAULT_ADMIN_ROLE|_setOwner\b|setOwner\s*\(", re.I)
# one-shot / access guards that make an init safe: OZ initializer, an only*/auth modifier, a manual `initialized`
# flag, a msg.sender check, or _disableInitializers in the ctor.
INIT_GUARD = re.compile(r"\b(?:re)?initializer\b|\binitializ(?:ed|ing)\b|\b_init(?:ialized|ialised)\b|"
                        r"\bonly\w+|\bauth\b|\brestricted\b|\bonlyWards?\b|_disableInitializers|"
                        r"require\s*\([^;]*msg\.sender", re.I)


def det_unprotected_init(text, rel):
    """An external/public initializer that grants ownership/admin role with no initializer/only*/one-shot guard ->
    anyone front-runs it (or re-inits the proxy) and takes the contract (DaoMaker/Telcoin/PikeFinance class).
    Internal inits and ones carrying the OZ `initializer` modifier / an only* gate / a manual `initialized` flag
    are NOT flagged."""
    out = []
    for m in re.finditer(r"function\s+(\w+)\s*\(", text):
        name = m.group(1)
        if not INIT_NAME.match(name):
            continue
        brace = text.find("{", m.end())
        if brace < 0:
            continue
        pc = text.rfind(")", m.end(), brace)
        if pc < 0:
            continue
        mods = text[pc + 1:brace]                       # visibility + modifiers only (not the params)
        if not re.search(r"\b(external|public)\b", mods):
            continue                                    # internal/private init = called by a guarded outer, safe
        if INIT_GUARD.search(mods):
            continue                                    # initializer / only* / auth modifier present
        nxt = text.find("function ", brace)
        body = text[brace:(nxt if nxt > 0 else brace + 1500)]
        if INIT_AUTHORITY.search(body) and not INIT_GUARD.search(body):
            out.append((rel, lineno(text, m.start()), f"function {name}(...)",
                        "external/public initializer grants ownership/admin role with NO initializer/only*/one-shot "
                        "guard -> anyone can front-run it (or re-init the proxy / call it on the impl) and seize the "
                        "contract (DaoMaker/Telcoin/PikeFinance class). Add the OZ `initializer` modifier or auth.", 0))
    return out


# ── Detector 38: caller-supplied authority (transferFrom source = decoded calldata field) ── class E, #1 of 2026
# transferFrom/safeTransferFrom whose SOURCE (the debited party) is a STRUCT/DECODED field (order.maker,
# params.owner) -> authority taken from attacker-supplied calldata, not bound to msg.sender. A bare-param `from`
# is allowance-gated (safe router); a decoded struct-field source with no signature / msg.sender binding is the
# 2026 drain class (TrustedVolumes, NewMarketTrading, Ekubo, MAPProtocol).
CALLER_AUTH_SRC = re.compile(r"\.(?:safeTransferFrom|transferFrom)\s*\(\s*(\w+\.\w+)\s*,", re.I)
AUTH_BIND = re.compile(r"msg\.sender\s*==|==\s*msg\.sender|_msgSender\(\)\s*==|==\s*_msgSender|"
                       r"\becrecover\b|isValidSignature|SignatureChecker|_verif|_checkSig|"
                       r"require\s*\([^;]*sign|EIP712|_hashTypedData", re.I)


def det_caller_supplied_authority(text, rel):
    """A transferFrom whose source (the debited party) is a caller-supplied struct/decoded field (`order.maker`),
    in an external/public fn that neither binds it to msg.sender nor verifies a signature over it -> the caller
    names any victim that approved this contract as the debited party (the #1 2026 class: TrustedVolumes/
    MAPProtocol/Ekubo). A bare-param `from` (allowance-gated router) does NOT match; a signed/msg.sender-bound
    source is skipped."""
    out, seen = [], set()
    for m in CALLER_AUTH_SRC.finditer(text):
        src = m.group(1)
        if re.match(r"(?:address|msg|block|tx)\b", src):   # msg.sender / tx.origin source = caller's own, safe
            continue
        srcvar = src.split(".")[0]
        fn_start = text.rfind("function ", 0, m.start())
        if fn_start < 0:
            continue
        brace = text.find("{", fn_start)
        head = text[fn_start:brace + 1] if brace > 0 else ""
        if not re.search(r"\b(external|public)\b", head):
            continue
        # the authority must be decoded from a CALLDATA struct param (attacker-supplied) -- NOT a `memory` struct
        # populated by trusted internal code (the Aave/Compound logic-library pattern, where the Pool entrypoint
        # already bound `.user`/`.caller` to msg.sender upstream -> a memory-struct source is a cross-file FP).
        if not re.search(r"\bcalldata\s+" + re.escape(srcvar) + r"\b", head):
            continue
        nxt = text.find("function ", m.start() + 1)
        fn_text = text[fn_start:(nxt if nxt > 0 else m.end() + 400)]
        if AUTH_BIND.search(fn_text):
            continue                                       # bound to caller / signature-verified -> safe
        ln = lineno(text, m.start())
        if ln in seen:
            continue
        seen.add(ln)
        out.append((rel, ln, f"transferFrom({src}, ...)",
                    "transferFrom source is a caller-supplied struct/decoded field, not bound to msg.sender and with "
                    "no signature check -> the caller can name any victim that approved this contract as the debited "
                    "party (caller-supplied-authority, the #1 2026 class: TrustedVolumes/MAPProtocol/Ekubo). Bind the "
                    "source to msg.sender or verify a signature over it.", 0))
    return out


# ── Detector: off-chain trust anchor (single signer/measurement, no quorum/revocation) ──
_COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)


def _strip_comments(text):
    """Blank out // line and /* */ block comments so a stray word in a comment (e.g. 'TODO: add quorum',
    'no revocation yet') can't silently SUPPRESS a code-level gate -> a false-negative, the worst outcome.
    Used only for boolean searches; offsets are not preserved (detection keeps using the raw text)."""
    return _COMMENT_RE.sub(" ", text)


TRUST_ANCHOR_TERM = re.compile(
    r"\bmr[_]?signer\b|\bmr[_]?enclave\b|\benclave\w*|\battestation\w*|\bsgx\w*|\bteeProof\b|"
    r"\btrusted(?:Signer|Key|Instance|Prover|Root)s?\b|\bverifyingKey\b|\bprover\w*|\binstanceId\b", re.I)
TRUST_VERIFY_FN = re.compile(
    r"function\s+(\w*(?:verifyProof|verifyAttestation|verify|register|addInstances?|setInstance|"
    r"attest|enroll|proveBlock|submitProof)\w*)\s*\(", re.I)
TRUST_QUORUM = re.compile(
    r"\bthreshold\b|\bquorum\b|\bsignaturesRequired\b|\bminSigners?\b|\brequiredSignatures?\b|"
    r"\bnumSigners?\b|\bM[\s_-]?of[\s_-]?N\b", re.I)
TRUST_REVOKE = re.compile(
    r"\brevoke\w*|\bremoveInstance\w*|\bdeleteInstance\w*|\bdisableInstance\w*|\brotat\w*|"
    r"\bdeprecat\w*|\bremoveProver\w*|\bremoveSigner\w*", re.I)
# A zk-SNARK verifier's key is the PUBLIC verifying key (toxic-waste destroyed) -> NOT a leakable signing
# key, so it is NOT this class (ZKFair FflonkVerifier FP). Distinguish from a TEE/signature verifier, whose
# trust IS a leakable signing key/measurement.
TRUST_SNARK = re.compile(r"fflonk|plonk|groth16|\bsnark|pairing|pubSignals|verifyingKey.*trusted\s*setup", re.I)
TRUST_TEE = re.compile(r"mr[_]?signer|mr[_]?enclave|enclave|attestation|\bsgx|teeProof|ecrecover|"
                       r"isValidSignature|trusted(?:Signer|Instance|Prover)", re.I)


def det_trust_anchor(text, rel):
    """A verifier/registrar whose authority reduces to ONE stored trust anchor (an SGX MrSigner/MrEnclave,
    a verifying key, a single trusted signer/prover) matched in a verify/register/attest fn, with NO M-of-N
    quorum -> whoever obtains that one key forges valid proofs and the chain accepts them (Taiko/Raiko 2026,
    ~$1.7M). A reactive revocation alone does NOT downgrade it (Taiko HAD deleteInstances and was still
    drained); only a quorum bounds a leaked key. T3 trust-model LEAD: the regex sees the missing quorum, NOT
    the off-chain key leak -> pair with the secrets lane (gitleaks) + confirm by hand. See
    research/patterns/trust-anchor/off-chain-signer-authority.md."""
    if not TRUST_ANCHOR_TERM.search(text):
        return []
    if TRUST_SNARK.search(text) and not TRUST_TEE.search(text):
        return []                                   # pure zk-SNARK verifier: the verifying key is PUBLIC, not a leakable signing key (FflonkVerifier FP)
    code = _strip_comments(text)                    # suppression must read CODE, not comments (a comment can't hide a bug)
    if TRUST_QUORUM.search(code):
        return []                                   # an M-of-N quorum bounds a single-key leak -> not this pattern
    has_revoke = bool(TRUST_REVOKE.search(code))
    out, seen = [], set()
    for m in TRUST_VERIFY_FN.finditer(text):
        name = m.group(1)
        nxt = text.find("function ", m.end())
        body = text[m.end():(nxt if nxt > 0 else m.end() + 400)]
        if not TRUST_ANCHOR_TERM.search(body):
            continue                                # the fn must actually touch the trust anchor
        ln = lineno(text, m.start())
        if ln in seen:
            continue
        seen.add(ln)
        # Revocation does NOT downgrade: Taiko HAD deleteInstances and was still drained -- a reactive
        # revoke can't stop a forged registration before an operator notices. Only an M-of-N quorum
        # (absent here) bounds a leaked key, so a no-quorum anchor stays [!] regardless of revocation.
        miss = ("no M-of-N quorum (the file has a reactive revocation path, but that can't stop a forged "
                "registration before it's noticed)" if has_revoke else "no M-of-N quorum and no revocation/rotation")
        out.append((rel, ln, f"function {name}(...)",
                    "verifier/registrar accepts a proof/instance by matching a SINGLE stored trust anchor (SGX "
                    "measurement / verifying key / trusted signer-prover) with " + miss + " -> whoever obtains that "
                    "one key forges valid proofs the chain accepts (Taiko/Raiko key-leak class, ~$1.7M). Require an "
                    "M-of-N multi-prover quorum; and secret-scan the repo/CI for the key (it lives off-chain).", 0))
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
    ("SIGNATURE / ecrecover (replay, malleability, no expiry) + ERC-1271 caller-supplied verifier", det_signature,
     "Class F: raw ecrecover needs address(0) check + a CONSUMED nonce (anti-replay) + deadline; ERC-1271 "
     "isValidSignature on a calldata-struct verifier = attacker deploys a yes-contract (MureDistribution)."),
    ("DOMAIN SEPARATOR cached (cross-chain / fork replay)", det_domain,
     "Pattern 06: EIP-712 separator cached with block.chainid, no recompute -> fork/cross-chain replay."),
    ("UPGRADE safety (unprotected UUPS _authorizeUpgrade)", det_upgrade,
     "Upgrade auth with no owner/role check -> anyone swaps the impl = total takeover."),
    ("UNCHECKED ERC20 return (silent transfer failure)", det_unchecked,
     "Bare transfer/transferFrom return dropped -> USDT/ZRX fail silently; use SafeERC20."),
    ("ERC4626 inflation (first-depositor share-price attack)", det_erc4626,
     "Vault with no _decimalsOffset / dead-shares -> first depositor skews the share price."),
    ("VAULT share-price rounding (custom/non-ERC4626, near-empty-supply manipulation)", det_vault_share_math,
     "Thetanuts $2.1M (2026): a custom vault prices `X*amount/totalSupply` with no minimum/dead-shares/zero "
     "guard -> shrinking supply inflates redeem + mint rounds to ~0 -> mint-and-redeem+flashloan drain. det_erc4626 misses non-4626."),
    ("REWARD / claim accounting (double-claim, late marker)", det_reward,
     "Pattern 03: reward payout with no claimed/rewardDebt marker write (or written after transfer)."),
    ("ORACLE usage vs 3-guard checklist", det_oracle,
     "Heuristic 2: staleness(updatedAt) + price>0 + decimals(); + spot-reserve pricing sub-check."),
    ("PYTH / pull-oracle missing guards (price>0 / confidence / staleness)", det_pyth_oracle,
     "Vena (2026): Pyth getPriceUnsafe/.price (signed int64) into valuation with no price>0/.conf/publishTime "
     "check -> zero/stale/wide-confidence push mis-prices the market. det_oracle covers Chainlink; this is the pull-oracle gap."),
    ("MULTICALL / msg.value reuse (N payments for 1)", det_multicall_value,
     "Payable delegatecall-multicall keeps the SAME msg.value for every batched sub-call -> N payable deposits "
     "for ONE payment (OZ guards it, forks don't); also msg.value read inside a loop = per-iteration credit."),
    ("READ-ONLY REENTRANCY (pricing view un-guarded while state-changers are)", det_readonly_reentrancy,
     "shadow.py #1 blind-spot: a nonReentrant-aware contract leaves a pricing VIEW (get_virtual_price/totalAssets/"
     "pricePerShare) un-guarded -> an integrator reading it mid-withdraw callback gets stale state (Curve/lending). "
     "Fix = view-side guard (Twyne's nonReentrantView)."),
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
     "delegatecall / tx.origin / selfdestruct / low-level call."),
    ("L2 / AA footguns (zkSync: extcodesize EOA-check, isContract sig branch)", det_l2_footgun,
     "zkSync native AA: 'EOA == no code' is false -> isContract/extcodesize-gated auth+signatures bypassable."),
    ("DOWNCAST truncation (uintN(x) silent overflow)", det_downcast,
     "DeFiVulnLabs: downcasting a value past type(uintN).max wraps silently (all 0.8.x). Frequent High."),
    ("DIVIDE-BEFORE-MULTIPLY precision loss", det_precision,
     "DeFiVulnLabs: (a/b)*c truncates before the multiply -> rounding favors someone; multiply first."),
    ("DECIMAL-SCALING truncation (bridge/wrapper non-18 token)", det_decimal_scale,
     "ZKFair gas-token / bridge playbook E: amount *=/ a decimals-diff factor (lone, not divide-before-multiply) "
     "-> dust/round-to-zero + */ asymmetry breaks round-trip & locked==minted on non-18 tokens. det_precision misses it."),
    ("abi.encodePacked HASH-COLLISION (dynamic args)", det_encodepacked,
     "DeFiVulnLabs: encodePacked of 2+ adjacent dynamic args collides ('a'+'bc'=='ab'+'c'); use abi.encode."),
    ("FEE-ON-TRANSFER over-credit (no balance-delta)", det_feeontransfer,
     "DeFiVulnLabs: crediting the requested amount (not the measured delta) over-credits on deflationary tokens."),
    ("DELETE struct-with-mapping (stale state)", det_delete_mapping,
     "DeFiVulnLabs: delete of a struct containing a mapping can't clear the mapping -> leftover entries."),
    ("OVERFLOW / underflow (pre-0.8 pragma or opt-out math block)", det_overflow,
     "Shadow-backlog: pre-0.8 has no overflow checks; an opt-out math block bypasses them in 0.8+."),
    ("FLASHLOAN/swap callback no initiator check", det_flashloan,
     "Shadow-backlog: onFlashLoan/executeOperation/uniswapV2Call without an initiator+sender check = drain."),
    ("RUG: owner-drain (sweep/rescue/emergencyWithdraw)", det_owner_drain,
     "Operator-power class: owner-gated drain of contract funds -> verify it can't take user deposits."),
    ("RUG: fee/tax setter with no cap", det_fee_backdoor,
     "Operator-power class: set*Fee/set*Tax with no upper bound -> operator can set 100% (honeypot)."),
    ("RUG: honeypot levers (blacklist/trading-toggle/maxTx)", det_honeypot_lever,
     "Operator-power class: owner can freeze/block exits -> exit-scam toolkit / centralization risk."),
    ("REWARD-FORMULA inflation (accumulator inside .mul(balance), Synthetix mis-bracket)", det_reward_formula,
     "posi-vaults class: earned()/pending() adds the stored reward INSIDE .mul(balance) instead of outside "
     "-> ~balance^2 inflation -> drain. recon-32 missed it (a math-shape bug, found by the L4 read)."),
    ("SPOT-AMM-AS-ORACLE (flashloan price-manip, #1 DeFiHackLabs class)", det_spot_oracle,
     "A mint/borrow/collateral/reward priced from a same-tx spot source (getReserves/pricePerShare/"
     "get_virtual_price/slot0/getAmountsOut) with no TWAP/Chainlink -> flashloan-movable (PancakeBunny/Cream/EGD/UwuLend)."),
    ("SELF-TRANSFER balance inflation (from==to overwrites the debit)", det_self_transfer,
     "DeFiHackLabs LPC/SSS/GPU class: a custom transfer caches BOTH balances[from] and balances[to] then writes "
     "back from the stale cache with no from==to guard -> self-send inflates balance for free."),
    ("PAIR-RESERVE mutation (unprivileged sync/skim/burn-of-pair -> price crash)", det_pair_reserve_mutation,
     "DeFiHackLabs reflection/deflationary BSC class (~30+): unprivileged pair.sync()/skim() or burn-of-pair-balance "
     "shrinks the DEX reserve -> constant-product overvalues the attacker's tokens (BIGFI/LAURA/BYToken)."),
    ("UNPROTECTED INITIALIZER (front-run ownership/role grab)", det_unprotected_init,
     "DeFiHackLabs class E: an external/public initialize/init that grants ownership/admin role with no "
     "initializer/only*/one-shot guard -> front-run the deploy or re-init the proxy and seize it (DaoMaker/Telcoin/PikeFinance)."),
    ("CALLER-SUPPLIED AUTHORITY (transferFrom source from calldata struct)", det_caller_supplied_authority,
     "DeFiHackLabs class E, #1 of 2026: transferFrom source is a decoded calldata field (order.maker) not bound to "
     "msg.sender / no signature -> caller debits any victim that approved this contract (TrustedVolumes/MAPProtocol/Ekubo)."),
    ("TRUST-ANCHOR single signer/measurement (SGX/zk verifier, no quorum/revocation)", det_trust_anchor,
     "Taiko/Raiko 2026 (~$1.7M): a verify/register/attest fn trusts ONE stored anchor (MrSigner/verifyingKey/"
     "trustedSigner) with no M-of-N quorum + no revocation -> a leaked key forges valid proofs. Pair w/ secrets lane."),
]


def det_key(title):
    """Stable short key for a detector title -> used by the triage ledger so a
    verdict survives wording changes. Check 'sibling' before 'access' (the
    sibling title contains both)."""
    t = title.lower()
    for sub, k in (("sibling", "sibling"), ("access control leads", "access"),
                   ("share-price rounding", "vaultsharemath"), ("supply", "supply"), ("receiver-hook", "nftcallback"),
                   ("read-only reentrancy", "roreentrancy"), ("reentrancy", "reentrancy"),
                   ("arbitrary", "arbcall"), ("signature", "signature"),
                   ("domain", "domain"), ("upgrade", "upgrade"),
                   ("unchecked", "unchecked"), ("erc4626", "erc4626"),
                   ("reward-formula", "rewardformula"), ("reward", "reward"),
                   ("spot-amm", "spotoracle"), ("self-transfer", "selftransfer"),
                   ("pair-reserve", "pairreserve"), ("unprotected init", "uinit"),
                   ("caller-supplied", "callerauth"), ("trust-anchor", "trustanchor"),
                   ("pyth", "pyth"), ("oracle", "oracle"), ("multicall", "multicallvalue"),
                   ("interest-index", "index"), ("liquidation", "liquidation"),
                   ("randomness", "weakrand"), ("slippage", "swapguard"),
                   ("mapping-default", "mapdefault"), ("strict balance", "strictbal"),
                   ("dangerous", "danger"), ("footgun", "l2"), ("disabled", "disabled"),
                   ("downcast", "downcast"), ("decimal-scaling", "decimalscale"), ("divide-before", "precision"),
                   ("encodepacked", "encodepacked"), ("fee-on-transfer", "feeontransfer"),
                   ("delete struct", "delmap"), ("overflow", "overflow"), ("flashloan", "flashloan"),
                   ("owner-drain", "ownerdrain"), ("fee/tax setter", "feebackdoor"),
                   ("honeypot levers", "honeypot")):
        if sub in t:
            return k
    return "other"


def detect_all(text, rel):
    """Run EVERY detector on one (text, rel) with a per-detector guard, so a single detector that throws
    on a malformed file can't abort the whole scan (a silent partial/false-clean risk). Returns
    {title: [leads]}; a crashing detector yields [] + a stderr WARN. Shared by recon/analyze/deepdive."""
    out = {}
    for title, fn, _why in DETECTORS:
        try:
            out[title] = list(fn(text, rel))
        except Exception as e:  # noqa: BLE001 - one bad file must not kill the scan
            sys.stderr.write(f"[recon] WARN: detector '{title}' crashed on {rel}: {e} (skipped that file)\n")
            out[title] = []
    return out


_VYPER = re.compile(r"^\s*#\s*@version\b|^\s*@(external|internal|view|pure|payable|nonpayable)\b|^\s*def\s+\w+\s*\(", re.M)


def is_vyper(text):
    """recon's detectors are Solidity regexes; a Vyper file (Yearn v2 vaults, Curve, ...) would get a
    misleading all-clear (false-clean = a silent miss -- the worst outcome). Detect it so main() WARNS
    + skips instead of emitting 0s that read as 'safe'. Learned on the yUSD read (Yearn V2 Vault.vy)."""
    return bool(_VYPER.search(text))


def main():
    ap = argparse.ArgumentParser(description="Solidity lead-surfacer (vault heuristics)")
    ap.add_argument("repo", help="path to a cloned Solidity repo")
    ap.add_argument("--out", help="also write the report to this markdown file")
    ap.add_argument("--top", type=int, default=25, help="max leads shown per detector")
    args = ap.parse_args()

    files = list(iter_sol(args.repo))
    results = {title: [] for title, _, _ in DETECTORS}
    vyper = []
    for path in files:
        rel = os.path.relpath(path, args.repo).replace("\\", "/")
        try:
            text = open(path, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        if is_vyper(text):
            vyper.append(rel)
            continue                       # Solidity detectors don't apply -> skip, NEVER emit a false-clean on Vyper
        for title, leads in detect_all(text, rel).items():
            results[title].extend(leads)

    out = [f"# Recon report: {os.path.basename(os.path.abspath(args.repo))}",
           f"\nScanned {len(files) - len(vyper)} Solidity file(s). Triage only - verify every lead by hand.",
           "Priority: [!] high (review first), [.] medium, [ ] low.\n"]
    if vyper:
        out.append(f"[!] {len(vyper)} VYPER file(s) NOT scanned -- recon is Solidity-only, so this is NOT a clean "
                   f"bill (false-clean = silent miss). Read by hand (Yearn v2 / Curve class): "
                   + ", ".join(vyper[:8]) + (" ..." if len(vyper) > 8 else "") + "\n")
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
