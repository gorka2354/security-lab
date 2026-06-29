#!/usr/bin/env python3
"""secrets.py - the SECRETS lane: hunt committed keys/credentials in a repo + its git HISTORY.

The Taiko/Raiko bug (June 2026, ~$1.7M) was an SGX enclave PRIVATE KEY (`enclave-key.pem`) committed to a
public repo. That is layer A of the trust-anchor class (recon's det_trust_anchor covers layer B, the
on-chain missing-quorum). A source-logic scan never sees it - it lives in repo opsec, often in OLD commits
that were later "removed" from HEAD (but git keeps them forever). So this lane scans BOTH the working tree
AND git history.

    python toolkit/secrets.py <repo>                 # working tree + full history
    python toolkit/secrets.py <repo> --no-history    # working tree only (fast)

Pure-python (no dep), so it always runs; if `gitleaks` is on PATH it is ALSO run and merged (deeper rules).
History scan is pre-filtered with `git log -G<regex>` so git only emits the commits that actually match -
cheap even on a monorepo. White-hat: report only; egor decides disclosure. ASCII output.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys

# --- content patterns: (name, regex, priority, redact?) ; priority 0 = [!] high ---
CONTENT = [
    ("private-key PEM block", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----"), 0, False),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 0, True),
    ("eth keystore json (ciphertext+kdf)", re.compile(r'"ciphertext"\s*:\s*"[0-9a-f]{16,}"'), 0, True),
    ("hardcoded private key (hex near key-context)",
     re.compile(r"(?i)(?:private|priv|secret)[_a-z]*key[^\n]{0,40}?0x?[a-f0-9]{64}\b"), 0, True),
    ("secret assigned to a literal",
     re.compile(r"""(?ix) \b (private_?key|secret_?key|api_?key|auth_?token|access_?token|client_?secret
                     |passwo?rd|passwd|mnemonic|seed_?phrase)
                     \s* [:=]{1,2} \s* (["'])([^"'\s]{12,})\2"""), 0, True),
]
# obvious non-secrets that match "secret assigned to a literal" -> drop (placeholders / env indirection)
# NOTE: split into \b-gated WORD alternatives + un-gated SYMBOL alternatives. The old single `\b(...)` group
# made `\$\{` / `<...>` / `...` DEAD (no word-boundary exists before a non-word char like `$`), so shell-var
# values `api_key="${api_keys[$i]}"` leaked as [!]. Now symbol forms match anywhere; also added bare `$VAR`.
_PLACEHOLDER = re.compile(r"(?i)(\b(your[-_ ]?|example|changeme|placeholder|dummy|xxx+|getenv|"
                          r"process\.env|os\.environ|import\.meta\.env|vault:|secret_ref)"
                          r"|<[^>]+>|\.\.\.|\$\{|\$[A-Za-z_][A-Za-z0-9_]{2,})")
# --- filename patterns: a sensitive file is a lead by its PATH alone ---
FILENAME = [
    ("private-key file (.pem/.key/.p12/.pfx)", re.compile(r"(?i)\.(pem|key|p12|pfx|asc|ppk)$"), 0),
    ("ssh/enclave private key", re.compile(r"(?i)(^|/)(id_(rsa|dsa|ecdsa|ed25519)|enclave[-_]?key\w*)$"), 0),
    ("keystore file", re.compile(r"(?i)(keystore|^UTC--.*--[0-9a-f]{40}$)"), 0),
    ("dotenv (live, not an example)", re.compile(r"(?i)(^|/)\.env(\.(local|prod\w*))?$"), 1),
]
# git -G prefilter: an ERE-safe (no inline flags / no \b) alternation so `git log -G` only emits matching
# commits. It only needs to be a SUPERSET trigger - scan_text (full Python regex) does the precise match.
_HISTORY_PREFILTER = (
    "-----BEGIN [A-Z0-9 ]*PRIVATE KEY"
    "|AKIA[0-9A-Z]{16}"
    "|ciphertext"
    "|[Pp][Rr][Ii][Vv][Aa][Tt][Ee][_ ]?[Kk][Ee][Yy]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Aa][Pp][Ii][_ ]?[Kk][Ee][Yy]"
    "|[Mm]nemonic|[Ss]eed[_ ]?[Pp]hrase|[Pp]assw|enclave"
    "|0x?[a-fA-F0-9]{64}"
)
_SKIP_DIR = re.compile(r"(^|/)(\.git|node_modules|\.yarn|\.pnp|lib|out|artifacts|cache|dist|build|vendor|"
                       r"forge-std|openzeppelin|\.venv|venv|__pycache__)(/|$)")
_EXAMPLE = re.compile(r"(?i)\.(example|sample|template|dist)$|\.env\.(example|sample|template)")
# generated / minified / doc files are not source -> a "key=" match there is junk (minified JS in an .html,
# integrity hashes in a lockfile). Skip CONTENT scan (filename scan still runs). (ion offchain/output.html FP.)
_GENERATED_EXT = re.compile(r"(?i)\.(html?|min\.js|map|svg|csv|lock|ipynb)$")
# well-known PUBLIC dev keys (anvil/hardhat default mnemonic "test test ... junk" accounts 0-9). They appear
# in deploy scripts/tests everywhere and are NOT secrets. Deny by value. (ion deploy-sim.sh/node.sh FP.)
_KNOWN_DEV_KEYS = {
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    "7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
    "47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
    "8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
    "92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
    "4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356",
    "dbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97",
    "2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6",
}
# test/fixture paths hold throwaway keys (test-vectors, mocks) -> downgrade, don't cry wolf (recon _TESTRE parallel)
_TEST_PATH = re.compile(r"(^|[:/])(tests?|test-?suites?|mocks?|scripts?|fixtures?|test-?vectors?|testdata|examples?|audits?|docs?)([/]|$)", re.I)

# Generated dev-account / config dumps that are NOT leaks: hardhat/ganache/anvil deterministic test accounts
# (the public 2000-key list - every install ships it), test-wallet fixtures, *.config.* dev keys. The Liquity
# sweep produced ~4000 hits from ONE such file. Two independent signals so neither has to be perfect:
#  (1) filename (a *.js/.ts/.json named hardhat/ganache/anvil/account/wallet/mnemonic, or *.config.*);
#  (2) per-file DENSITY - a real committed secret is 1-2 hits; a generated key dump is dozens-to-thousands.
_DEV_KEYLIST = re.compile(r"(?i)(hardhat|ganache|anvil|truffle|foundry|genesis|devnet|"
                          r"account|wallet|mnemonic)[-_a-z0-9]*\.(js|ts|cjs|mjs|json)$|(^|[-_.])config\.(js|ts|cjs|mjs)$")
BULK_KEY_THRESHOLD = 8


# whole-FILE dummy content: an obvious placeholder secret (a sensitive-named file holding one of these is a
# fixture, not a leak). Anchored single-token match, applied to the stripped file body.
_DUMMY_VALUE = re.compile(r"(?i)^(super[-_ ]?secret\w*|secret\w*|passw[o0]rd\w*|p[a@]ss\w*|changeme\w*|"
                          r"dummy\w*|example\w*|placeholder\w*|test\w*|admin\w*|root|foobar|none|todo|"
                          r"0x0+|1234\d*|abc123)$")


def _is_dummy_content(text):
    s = (text or "").strip()
    if not s or len(s) > 40 or "\n" in s:
        return False
    # an anchored dummy word (superSecretPassword/changeme/test...) OR the whole body is a single env-var
    # indirection (${VAR}/$VAR). NOT the broad _PLACEHOLDER (it matches a bare `$` inside a REAL secret).
    return bool(_DUMMY_VALUE.match(s) or re.fullmatch(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?", s))


def _locfile(rel):
    """Strip a history commit prefix (commit:file) so per-file density groups by the real file."""
    return rel.split(":", 1)[1] if (":" in rel and not rel.startswith("0x")) else rel


def suppress_dev_dumps(leads):
    """Downgrade the two giant non-leak classes below [!] so they never bury a real secret:
    (1) generated dev-account / test-wallet / *.config.* files (by name); (2) any file with
    >= BULK_KEY_THRESHOLD key hits (a 2000-key hardhat dump is bulk). Real production secrets stay [!].
    Reused by secrets_sweep so the radar and the per-repo report agree. Unit-tested."""
    from collections import Counter
    counts = Counter(_locfile(h[0]) for h in leads if "key" in h[2].lower() or "secret" in h[2].lower())
    out = []
    for rel, ln, name, prev, prio in leads:
        f = _locfile(rel)
        bulk = counts.get(f, 0) >= BULK_KEY_THRESHOLD
        dev = bool(_DEV_KEYLIST.search(os.path.basename(f)))
        tag = " [bulk dev-key list]" if bulk else (" [dev/config key file]" if dev else "")
        out.append((rel, ln, name + tag, prev, max(prio, 2) if (bulk or dev) else prio))
    return out


def git(repo, *args):
    """Run a git command in `repo`; return stdout (or '' on failure). Mirrors diffscan.git."""
    try:
        r = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True,
                           errors="ignore", timeout=120)
        return r.stdout if r.returncode == 0 else ""
    except Exception:
        return ""


def has_history(repo):
    return bool(git(repo, "rev-parse", "--is-inside-work-tree").strip())


def redact(s):
    """Mask the middle of a secret so the report proves the hit without re-leaking it."""
    s = s.strip()
    return s if len(s) <= 10 else f"{s[:4]}...({len(s)} chars)...{s[-4:]}"


def lineno(text, idx):
    return text.count("\n", 0, idx) + 1


def scan_text(text, rel):
    """Pure content scan of one blob. Returns [(rel, line, name, redacted-preview, prio)]. Unit-testable."""
    out = []
    for name, rx, prio, do_redact in CONTENT:
        for m in rx.finditer(text):
            hit = m.group(0)
            low = hit.lower()
            if any(k in low for k in _KNOWN_DEV_KEYS):    # anvil/hardhat public default key -> not a secret
                continue
            if name.startswith("secret assigned"):
                if _PLACEHOLDER.search(hit):
                    continue                              # a placeholder / env-indirection, not a real secret
                hit = m.group(3)                          # the literal value only
                # entropy gate: a bare dictionary-word value (all letters, no digit/sep, not long) is a config
                # TOKEN, not a secret -- e.g. `api_key: "verifyContract"` (a testnet explorer verifier accepts any
                # string). Real keys/tokens carry entropy: a digit, a separator, or length. (Abracadabra sweep FP.)
                if re.fullmatch(r"[A-Za-z]{1,20}", hit):
                    continue
            preview = redact(hit) if do_redact else "-----BEGIN ... PRIVATE KEY-----"
            out.append((rel, lineno(text, m.start()), name, preview, prio))
    return out


def scan_filename(rel):
    """Path-only leads: a .pem / enclave-key / keystore is a lead before we even read it."""
    base = os.path.basename(rel)
    if _EXAMPLE.search(base):
        return []
    out = []
    for name, rx, prio in FILENAME:
        if rx.search(rel) or rx.search(base):
            out.append((rel, 0, name, f"(sensitive filename: {base})", prio))
    return out


def scan_tree(repo, max_bytes=2_000_000):
    out = []
    for root, dirs, fnames in os.walk(repo):
        rel_root = os.path.relpath(root, repo).replace("\\", "/")
        if _SKIP_DIR.search("/" + rel_root):
            dirs[:] = []
            continue
        for fn in fnames:
            rel = os.path.normpath(os.path.join(rel_root, fn)).replace("\\", "/").lstrip("./")
            fn_leads = scan_filename(rel)
            skip_content = bool(_EXAMPLE.search(fn) or _GENERATED_EXT.search(fn))
            text = None
            try:
                if os.path.getsize(os.path.join(root, fn)) <= max_bytes:
                    text = open(os.path.join(root, fn), encoding="utf-8", errors="ignore").read()
            except Exception:
                text = None
            # content-aware filename leads: a sensitive-NAMED file whose body is an obvious placeholder is not a
            # leak (Puffer validator-keystore-password.txt == "superSecretPassword", consumed by a key-GEN script).
            if fn_leads and text is not None and _is_dummy_content(text):
                fn_leads = [(r, l, n + " [placeholder content]", p, max(2, pr)) for (r, l, n, p, pr) in fn_leads]
            out.extend(fn_leads)
            if not skip_content and text is not None:
                out.extend(scan_text(text, rel))
    return out


def scan_history(repo, rng=None):
    """Scan git history for committed secrets. Pre-filtered with `git log -G<alt>` so git only emits the
    matching commits (cheap even on a monorepo). Returns [(commit:file, line, name, preview, prio)].
    `rng` (e.g. 'abc123..HEAD') scans only that commit range -> incremental sweeps; default '--all'."""
    if not has_history(repo):
        return []
    scope = [rng] if rng else ["--all"]
    patch = git(repo, "log", *scope, "-p", "--no-color", "-G", _HISTORY_PREFILTER, "--")
    if not patch:
        return []
    out, commit, rel = [], "?", "?"
    for line in patch.splitlines():
        if line.startswith("commit "):
            commit = line.split()[1][:10]
        elif line.startswith("+++ b/"):
            rel = line[6:]
        elif (line.startswith("+") and not line.startswith("+++") and not _SKIP_DIR.search("/" + rel)
              and not _EXAMPLE.search(os.path.basename(rel)) and not _GENERATED_EXT.search(os.path.basename(rel))):
            for (_, _l, name, preview, prio) in scan_text(line[1:], f"{commit}:{rel}"):
                out.append((f"{commit}:{rel}", 0, name + " [in git history]", preview, max(0, prio)))
    # de-dup identical (commit:file, name, preview)
    seen, uniq = set(), []
    for h in out:
        k = (h[0], h[2], h[3])
        if k not in seen:
            seen.add(k)
            uniq.append(h)
    return uniq


def run_gitleaks(repo):
    """If gitleaks is installed, run it too and fold its findings in (deeper ruleset)."""
    if not shutil.which("gitleaks"):
        return [], False
    try:
        r = subprocess.run(["gitleaks", "detect", "--no-banner", "--report-format", "json",
                            "--report-path", "/dev/stdout", "--source", repo],
                           capture_output=True, text=True, timeout=300)
        data = json.loads(r.stdout or "[]")
        out = []
        for f in data:
            loc = f"{f.get('File','?')}:{f.get('StartLine','?')}"
            out.append((loc, 0, f"gitleaks:{f.get('RuleID','rule')}", redact(f.get("Secret", "") or ""), 0))
        return out, True
    except Exception:
        return [], True


def main():
    ap = argparse.ArgumentParser(description="Secrets lane: committed keys/credentials in tree + git history")
    ap.add_argument("repo", help="path to a repo (clone WITHOUT --depth 1 to scan history)")
    ap.add_argument("--no-history", action="store_true", help="working tree only (skip git history)")
    args = ap.parse_args()
    repo = args.repo

    tree = scan_tree(repo)
    hist = [] if args.no_history else scan_history(repo)
    gl, gl_present = run_gitleaks(repo)
    leads = tree + hist + gl

    print(f"# Secrets report: {os.path.basename(os.path.abspath(repo))}")
    print(f"\nScanned working tree{'' if args.no_history else ' + git history'}"
          f"{' + gitleaks' if gl_present else ''}. Triage only - verify + responsible-disclose by hand.")
    if not args.no_history and not has_history(repo):
        print("[!] no git history (shallow --depth 1 clone?). Deepen: git -C <repo> fetch --unshallow"
              " - the Taiko key lived in OLD commits, so history is the point.")
    if not gl_present:
        print("[.] gitleaks not installed (optional, deeper rules): brew install gitleaks")

    # Downgrade test/fixture/test-vector paths (mirrors recon's _TESTRE): a key under test-vectors/ is
    # fixture material (the ZKFair helpers.json + .env Anvil-key lesson), not a live leak -- keep the
    # signal but drop it below [!] so it never cries wolf over real, production-path secrets.
    leads = suppress_dev_dumps(leads)                     # hardhat 2k-account / *.config.* dumps -> not [!]
    leads = [(h[0], h[1], h[2], h[3], min(2, h[4] + 1)) if _TEST_PATH.search(h[0]) else h for h in leads]
    by_prio = sorted(leads, key=lambda h: h[4])
    if not by_prio:
        print("\n(no secrets surfaced) - clean, OR history unreachable (see above).")
        return
    mark = {0: "[!]", 1: "[.]", 2: "[ ]"}
    print(f"\n## Findings ({len(by_prio)})\n")
    for rel, ln, name, preview, prio in by_prio:
        loc = rel if ln == 0 else f"{rel}:{ln}"
        tag = "  (test/fixture path - likely not a live secret)" if _TEST_PATH.search(rel) else ""
        print(f"- {mark[prio]} {name} - `{loc}`  ->  {preview}{tag}")
    print(f"\n---\nTotal: {len(by_prio)}. A live private key in-scope -> rotate-and-disclose path;"
          " pair with recon det_trust_anchor (the on-chain blast radius).")


if __name__ == "__main__":
    main()
