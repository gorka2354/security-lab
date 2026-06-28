#!/usr/bin/env python3
"""Golden tests for the SECRETS lane (secrets.py scanner + secrets_sweep.py radar).

Same style as test_detectors.py: pure asserts, no pytest, exits 1 on any fail (CI-friendly).

    python tests/test_secrets.py

Pins: content/filename scan, test-path downgrade (no cry-wolf), git-history catch of a removed key
(the Taiko enclave-key shape), range-aware scan_history, lead_key stability, and the sweep() incremental
diff (first sweep reports the 2-year-old leak; re-run is quiet).
"""
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "toolkit"))
import secrets as S          # noqa: E402
import secrets_sweep as SW   # noqa: E402

_p, _f = 0, 0


def check(cond, msg):
    global _p, _f
    if cond:
        _p += 1
    else:
        _f += 1
        print("  FAIL:", msg)


_PEM = "-----BEGIN PRIVATE KEY-----\nMIIBVAIBADANBgkqh\n-----END PRIVATE KEY-----\n"


def _git(repo, *a):
    subprocess.run(["git", "-C", repo, *a], capture_output=True, text=True)


def _fixture_repo(d):
    """A repo shaped like the Taiko leak: a prod-path key committed then REMOVED from HEAD,
    plus a test-fixture key that must never alert."""
    _git(d, "init", "-q")
    _git(d, "config", "user.email", "t@t.t")
    _git(d, "config", "user.name", "t")
    open(os.path.join(d, "enclave-key.pem"), "w").write(_PEM)
    open(os.path.join(d, "README.md"), "w").write("ok\n")
    _git(d, "add", "-A")
    _git(d, "commit", "-qm", "init with key")
    os.remove(os.path.join(d, "enclave-key.pem"))
    _git(d, "add", "-A")
    _git(d, "commit", "-qm", "remove key from HEAD")
    os.makedirs(os.path.join(d, "test", "fixtures"))
    open(os.path.join(d, "test", "fixtures", "throwaway.pem"), "w").write(_PEM)
    _git(d, "add", "-A")
    _git(d, "commit", "-qm", "add test fixture")


print("== secrets.scan_text / scan_filename (content + path leads) ==")
hits = S.scan_text('private_key = "abcdef0123456789ghil"', "src/Config.sol")
check(any("secret assigned" in h[2] for h in hits), "literal secret assignment caught")
check(not S.scan_text('apiKey = process.env.API_KEY', "x.js"), "env-indirection placeholder dropped (no FP)")
check(S.scan_filename("deploy/enclave-key.pem"), "sensitive .pem filename is a lead by path alone")
check(not S.scan_filename(".env.example"), "*.example is not a leak")

print("== git-history catch of a removed key (the Taiko shape) + range scan ==")
with tempfile.TemporaryDirectory() as d:
    _fixture_repo(d)
    leads = SW.high_leads(d)
    check(len(leads) == 1, f"exactly one [!] prod-path leak (got {len(leads)})")
    check(leads and "git history" in leads[0][2], "the leak is found IN HISTORY (removed from HEAD)")
    check(SW.high_leads(d, no_history=True) == [], "tree-only is clean (key only in history; fixture downgraded)")
    # test-fixture key never surfaces as [!]
    allpem = [h for h in (S.scan_tree(d)) if "PRIVATE KEY" in h[2]]
    check(all(S._TEST_PATH.search(h[0]) for h in allpem), "the only tree PEM is the downgraded test fixture")
    # range scan: HEAD..HEAD yields no history commits
    head = SW.head_sha(d)
    check(S.scan_history(d, rng=f"{head}..HEAD") == [], "empty commit range -> no history leads (incremental)")

print("== lead_key stability (strips commit prefix; same secret -> same key) ==")
a = SW.lead_key("o/r", ("aaaaaaaaaa:enclave-key.pem", 0, "private-key PEM block [in git history]", "X", 0))
b = SW.lead_key("o/r", ("bbbbbbbbbb:enclave-key.pem", 0, "private-key PEM block [in git history]", "X", 0))
check(a == b, "same secret under different commit hashes -> stable key (alerts once)")
c = SW.lead_key("o/r", ("src/Foo.sol", 12, "secret assigned to a literal", "Y", 0))
check(c != a, "different secret -> different key")

print("== sweep() incremental: first sweep reports the leak, re-run is quiet ==")
with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as root:
    _fixture_repo(d)
    os.makedirs(os.path.join(root, "monitor"))
    os.makedirs(os.path.join(root, "hunts", "_radar"))
    import json as _json
    _json.dump({"repos": [{"slug": "fake/proto", "protocol": "proto", "chain": "eth"}]},
               open(os.path.join(root, "monitor", "repos.json"), "w"))
    _orig_root = SW.ROOT
    SW.ROOT = root
    try:
        cloner = lambda slug, **kw: d                      # noqa: E731  - inject the fixture as the clone
        ev1 = SW.sweep("2026-06-28", cloner=cloner)
        check(len(ev1) == 1 and "history" in ev1[0]["name"], "first sweep reports the 2-year-old leak")
        body = open(os.path.join(root, "hunts", "_radar", "SECRETS.md")).read()
        check("NEW leak" in body and "enclave-key.pem" in body, "SECRETS.md names the leak")
        ev2 = SW.sweep("2026-06-28", cloner=cloner)
        check(ev2 == [], "re-run is quiet (leak already seen -> alerts once)")
        check("All quiet" in open(os.path.join(root, "hunts", "_radar", "SECRETS.md")).read(), "quiet queue on re-run")
    finally:
        SW.ROOT = _orig_root

print(f"\n{_p} passed, {_f} failed")
sys.exit(1 if _f else 0)
