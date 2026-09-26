#!/usr/bin/env python3
"""Contract test for toolkit/sync-stand.sh -- which copy wins when the workstation and the stand both hold a file.

Same style as test_detectors.py: pure asserts, no pytest, exits 1 if any fail (CI-friendly).

    python tests/test_sync_stand.py

Runs the REAL script against a FAKE stand: a temp dir as the stand's $HOME and an `ssh` shim first on PATH that
runs the remote command locally (never touches the real mini-PC). Pins the ownership split:
  - workstation-owned files (registry, toolkit, ...) are overwritten on the stand, even by an older copy;
  - the shared regenerable caches (programs / contacts / repo-meta -- the stand's 04:00 cron refreshes them too)
    sync NEWEST-WINS both ways: a fresher stand copy is pulled back and never clobbered (the 2026-09-25 bug).
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
_p, _f = 0, 0


def check(cond, msg):
    global _p, _f
    if cond:
        _p += 1
    else:
        _f += 1
        print("  FAIL:", msg)


def eq(a, b, msg):
    check(a == b, f"{msg}  (got {a!r}, want {b!r})")


def find_bash():
    # on Windows a bare "bash" can resolve to System32 WSL bash (see labcore._autosync) -> use Git's RAW msys bash:
    # the Git\bin\bash.exe launcher re-prepends its /usr/bin to PATH, which would put the real ssh before our shim
    if os.name == "nt":
        for c in (r"C:\Program Files\Git\usr\bin\bash.exe",):
            if os.path.exists(c):
                return c
    return shutil.which("bash")


def put(path, obj, age_s):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh)
    t = time.time() - age_s
    os.utime(path, (t, t))


def get(path):
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def script(path, body):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("#!/usr/bin/env bash\n" + body + "\n")
    os.chmod(path, 0o755)


HOUR, MONTH = 3600, 30 * 86400

bash = find_bash()
if not bash:
    print("SKIP: no bash on this host (sync-stand.sh is a bash script)")
    sys.exit(0)

tmp = tempfile.mkdtemp(prefix="syncstand-")
try:
    ws, home, shims = (os.path.join(tmp, d) for d in ("ws", "stand", "bin"))
    stand = os.path.join(home, "security-lab")
    for d in (os.path.join(ws, "toolkit"), os.path.join(ws, "web"), os.path.join(stand, "monitor"), shims):
        os.makedirs(d, exist_ok=True)
    shutil.copy(os.path.join(ROOT, "toolkit", "sync-stand.sh"), os.path.join(ws, "toolkit", "sync-stand.sh"))
    with open(os.path.join(ws, "toolkit", "labstate.py"), "w", encoding="utf-8") as fh:  # remote rebuild stub
        fh.write("import json\njson.dump({'findings': []}, open('monitor/lab-state.json', 'w'))\n")
    with open(os.path.join(ws, "web", "index.html"), "w", encoding="utf-8") as fh:
        fh.write("<p>dash</p>\n")
    open(os.path.join(home, ".seclab_env"), "w").close()

    # ssh shim: drop the -o options + host, run the remote command locally with HOME = the fake stand
    script(os.path.join(shims, "ssh"),
           'while [ $# -gt 0 ]; do case "$1" in -o) shift 2 ;; -*) shift ;; *) break ;; esac; done\n'
           'shift\nHOME="$FAKE_STAND_HOME" exec bash -c "$*"')
    script(os.path.join(shims, "python3"), 'exec "%s" "$@"' % sys.executable.replace("\\", "/"))

    M = lambda base, f: os.path.join(base, "monitor", f)  # noqa: E731
    put(M(ws, "programs.json"), {"v": "ws-stale"}, MONTH)        # stand's daily refresh is fresher -> pull it
    put(M(stand, "programs.json"), {"v": "stand-fresh"}, HOUR)
    put(M(ws, "contacts.json"), {"v": "ws-fresh"}, HOUR)         # workstation's ad-hoc run is fresher -> push it
    put(M(stand, "contacts.json"), {"v": "stand-stale"}, MONTH)
    put(M(stand, "repo-meta.json"), {"v": "stand-only"}, HOUR)   # missing locally -> pulled
    put(M(ws, "registry.json"), {"v": "ws-owned"}, MONTH)        # workstation-owned: overwrites even when older
    put(M(stand, "registry.json"), {"v": "stand-drift"}, HOUR)

    env = dict(os.environ, FAKE_STAND_HOME=home.replace("\\", "/"), SECLAB_STAND="fake@stand")
    path = [shims] + ([r"C:\Program Files\Git\usr\bin"] if os.name == "nt" else []) + [env.get("PATH", "")]
    env["PATH"] = os.pathsep.join(path)
    r = subprocess.run([bash, "toolkit/sync-stand.sh"], cwd=ws, env=env, stdin=subprocess.DEVNULL,
                       capture_output=True, text=True, timeout=120)

    print("== sync-stand.sh against a fake stand ==")
    eq(r.returncode, 0, "script exits 0")
    if r.returncode != 0:
        print(r.stdout[-1500:], r.stderr[-1500:])
    eq(get(M(ws, "programs.json")), {"v": "stand-fresh"}, "fresher stand cache is pulled back to the workstation")
    eq(get(M(stand, "programs.json")), {"v": "stand-fresh"}, "fresher stand cache is NOT clobbered by a stale push")
    eq(get(M(stand, "contacts.json")), {"v": "ws-fresh"}, "fresher workstation cache is pushed to the stand")
    eq(get(M(ws, "contacts.json")), {"v": "ws-fresh"}, "fresher workstation cache is NOT replaced by the pull")
    eq(get(M(ws, "repo-meta.json")), {"v": "stand-only"}, "cache missing locally is pulled from the stand")
    eq(get(M(stand, "registry.json")), {"v": "ws-owned"}, "workstation-owned file overwrites the stand copy")
    eq(get(M(stand, "lab-state.json")), {"findings": []}, "remote lab-state rebuild ran after the push")
    check("newest wins" in r.stdout, "prints the shared-cache line")
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print(f"\n{_p} passed, {_f} failed")
sys.exit(1 if _f else 0)
