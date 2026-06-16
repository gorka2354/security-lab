#!/usr/bin/env python3
"""decompile_match.py -- detect share-inflation MATH on DECOMPILED bytecode (the ThetaNuts frontier).

`reach_bytecode.py` recovers the SURFACE of an unverified contract (which functions exist). This goes one
layer deeper: it runs a share-inflation matcher on DECOMPILED pseudocode, where the round-to-zero math
survives even though the source is unverified. It is the second stage AFTER reach_bytecode flags a target
as vault-shaped -- not a broad scan.

LANE: decompilation (panoramix/heimdall) needs SIGALRM/setitimer + a real toolchain and does NOT run
natively on this Windows box -- run the decompile step in WSL/CI (see toolkit/WSL-LANE.md). This matcher
itself is pure-regex and runs anywhere on the resulting text.

EMPIRICAL BASIS (the real ThetaNuts 0xC2C3AE0a, decompiled with panoramix in WSL): the share-conversion
renders as `<backing> * <amount> / totalSupply` -- panoramix resolves the standard `totalSupply` getter,
so the inflation form is visible by name. det_erc4626 (source) needs BOTH a `* totalSupply /` deposit
shape AND a `* x / totalSupply` redeem shape; decompiled output only carries the latter (18 sites on
ThetaNuts, 0 of the former), so this matcher keys on the `/ totalSupply` proportional form + the absence
of a dead-shares/min guard.

Usage: python decompile_match.py <decompiled.txt>
"""
import re
import sys

# proportional share-conversion `<backing> * <amount> / totalSupply` (redeem/claim inflation form).
SHARE_CONV = re.compile(r"\*\s*\w+\s*\)?\s*/\s*_?total(?:Supply|Shares)\b")
# the dead-shares / min-supply / virtual-offset mitigations det_erc4626 also looks for.
GUARD = re.compile(r"MINIMUM_(SHARES|LIQUIDITY|DEPOSIT)|_decimalsOffset|dead.?shares|virtual_?shares", re.I)


def match_share_inflation(text):
    """Return the list of (line_no, source_line) where a `* x / totalSupply` share-conversion appears."""
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)  # strip ANSI colour codes from panoramix dumps
    lines = text.splitlines()
    hits = []
    for m in SHARE_CONV.finditer(text):
        ln = text.count("\n", 0, m.start())
        hits.append((ln + 1, lines[ln].strip()[:110]))
    return hits, bool(GUARD.search(text))


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
    hits, guarded = match_share_inflation(text)
    uniq = sorted(set(ln for ln, _ in hits))
    if hits and not guarded:
        print(f"[!] SHARE-INFLATION math on DECOMPILED bytecode: {len(hits)} proportional "
              f"`backing * amount / totalSupply` site(s) across {len(uniq)} lines, NO dead-shares/min "
              f"guard -> round-to-zero deposit / inflated redeem (ThetaNuts $2.1M class). Sample sites:")
        for ln, src in hits[:8]:
            print(f"    L{ln}: {src}")
        print("    NOTE: staged confirmer -- run only on reach_bytecode-flagged vault targets; a lone "
              "`reward*rate/totalSupply` staking site can also match, so verify it's a deposit/redeem path.")
    elif hits and guarded:
        print(f"  [.] {len(hits)} proportional share-conversion site(s) BUT a dead-shares/min guard is "
              f"present in the decompiled output -> likely mitigated (verify the guard covers the bootstrap)")
    else:
        print("  [ ] no proportional `* / totalSupply` share-conversion in the decompiled output "
              "(panoramix may not have resolved totalSupply -> a slot-based pass is the next layer)")


if __name__ == "__main__":
    main()
