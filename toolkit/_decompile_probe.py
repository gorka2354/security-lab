#!/usr/bin/env python3
"""Probe: decompile bytecode with panoramix.
  python _decompile_probe.py <address|0xBYTECODE|file.hex> [chain_or_-] [out.txt] [only_func]
RPCs are blocked here, so for an address we fetch the code via Etherscan; or pass raw bytecode / a file.
"""
import os
import sys
import signal

# panoramix uses signal.SIGALRM for its per-function timeout -- Unix-only. Shim it on Windows
# (neutralizes the alarm; the outer `timeout` is our real guard).
if not hasattr(signal, "SIGALRM"):
    signal.SIGALRM = 14
    signal.ITIMER_REAL = 0
    signal.alarm = lambda *a, **k: 0
    signal.setitimer = lambda *a, **k: (0.0, 0.0)
    signal.getitimer = lambda *a, **k: (0.0, 0.0)
    _orig_signal = signal.signal
    signal.signal = lambda sig, h: None if sig == 14 else _orig_signal(sig, h)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from panoramix.decompiler import decompile_bytecode  # noqa: E402

arg = sys.argv[1]
chain = sys.argv[2] if len(sys.argv) > 2 else "1"
out = sys.argv[3] if len(sys.argv) > 3 else "hunts/thetanuts/_decompiled.txt"
only_func = sys.argv[4] if len(sys.argv) > 4 else None

if os.path.isfile(arg):
    code = open(arg).read().strip()
elif arg.startswith("0x") and len(arg) > 60:
    code = arg
else:
    from reach_bytecode import get_code  # noqa: E402
    code = get_code(arg, chain)

print(f"bytecode bytes: {(len(code) - 2) // 2}; only_func={only_func}", flush=True)
d = decompile_bytecode(code, only_func) if only_func else decompile_bytecode(code)
text = None
for attr in ("text", "asm", "pretty", "code"):
    v = getattr(d, attr, None)
    if v:
        text = v if isinstance(v, str) else str(v)
        break
if text is None:
    text = str(d)
with open(out, "w", encoding="utf-8") as f:
    f.write(text)
print(f"wrote {len(text)} chars -> {out}", flush=True)
