#!/usr/bin/env python3
"""watch.py - CHANGE-EVENT monitor over our tracked targets (real findings + key live targets).

Snapshots each watchlist target's on-chain state (code-hash + native/tracked-token value + activity) and
emits EVENTS on MATERIAL change, so a dormant finding that goes LIVE -- or a funded target that gets DRAINED
(possible exploit) -- surfaces automatically instead of us re-checking by hand. Complements radar.py, which
already covers IMPL-UPGRADE (proxy-impl swap) + BOUNTY-OPEN; watch.py adds the VALUE/LIVENESS delta.

  FUNDED   - value appeared where there was none  -> a finding may have gone LIVE (reassess + disclose)
  GREW     - tracked value rose >=2x              -> TVL growth -> a bounded finding is now worth more
  DRAINED  - tracked value dropped >=50%          -> POSSIBLE EXPLOIT / mass-withdrawal -> INVESTIGATE
  CODE-CHANGE - eth_getCode hash changed          -> redeploy / proxy-impl swap -> re-review the drift
  REACTIVATED - dormant (>30d) -> active (<7d)     -> usage resumed

Notifies: appends to hunts/_radar/QUEUE.md (dashboard radar + session-start), writes monitor/watch-events.json,
and (Windows) pops a balloon for HIGH events. Exit 10 if any NEW event (cron-friendly).

    python toolkit/watch.py add <key> <chain> <addr> [--token 0x..] [--note "..."]
    python toolkit/watch.py run [--notify]      # snapshot all -> diff vs last -> emit events (+ notify)
    python toolkit/watch.py list | events [--n 20]

Stdlib only. White-hat: read-only on-chain reads over public data.
NOT the parked-lead go-live watcher (bounty-open / code-appears over monitor/watchlist.json) -- that is
toolkit/parkwatch.py, run daily by .github/workflows/watch.yml.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import urllib.parse
import tlsfix  # noqa: F401,E402  -- current CA bundle on stale-CA Windows hosts (see tlsfix.py)
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fetch_source as fs  # noqa: E402  (RPC map + _rpc)
import threat as T  # noqa: E402  (last_activity_days + _erc20_balance)

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WATCHLIST = os.path.join(_ROOT, "monitor", "watch-targets.json")  # NB: watchlist.json is the parked-leads store
STATE = os.path.join(_ROOT, "monitor", "watch-state.json")
EVENTS = os.path.join(_ROOT, "monitor", "watch-events.json")
QUEUE = os.path.join(_ROOT, "hunts", "_radar", "QUEUE.md")

# RPCs incl. the exotic chains our fresh GameFi findings live on (X Layer / Robinhood / ApeChain / opBNB) so
# the monitor covers exactly the targets that matter, not only the mainstream chains fetch_source maps.
WATCH_RPC = dict(fs.DEFAULT_RPC)
WATCH_RPC.update({
    "196": "https://xlayerrpc.okx.com",                  # X Layer (LuXMarket)
    "4663": "https://rpc.mainnet.chain.robinhood.com",   # Robinhood Chain (HoodBet)
    "33139": "https://rpc.apechain.com",                 # ApeChain (HEAD2HEAD / monke.bet)
    "204": "https://opbnb-mainnet-rpc.bnbchain.org",     # opBNB (ClawKing)
})
_DRAIN = 0.5   # value drop >= this fraction -> DRAINED
_GROW = 2.0    # value rise >= this multiple -> GREW
_HIGH = {"FUNDED", "DRAINED", "CODE-CHANGE"}


def _load(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _save(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=1)


def _token_meta(token, chain, rpc, call):
    """(decimals, symbol) of an ERC20 via eth_call -> human-readable value formatting. Best-effort -> (None,None)."""
    dec = sym = None
    try:
        r = call(rpc, "eth_call", [{"to": token, "data": "0x313ce567"}, "latest"])  # decimals()
        if r and r != "0x":
            dec = int(r, 16)
    except Exception:
        pass
    try:
        r = call(rpc, "eth_call", [{"to": token, "data": "0x95d89b41"}, "latest"])  # symbol()
        if r and len(r) > 2:
            h = r[2:]
            if len(h) >= 128:  # dynamic string: offset(32) + length(32) + data
                ln = int(h[64:128], 16)
                sym = bytes.fromhex(h[128:128 + ln * 2]).decode("utf-8", "ignore").strip("\x00�").strip()
            if not sym:  # bytes32 fallback (older tokens)
                sym = bytes.fromhex(h[:64]).decode("utf-8", "ignore").strip("\x00�").strip()
    except Exception:
        pass
    return dec, (sym or None)


def snapshot(entry, now_iso, _rpc=None):
    """On-chain state of one watchlist target -> a comparable snapshot dict. Network; _rpc injectable for tests.
    entry = {key, chain, addr, token?}. value = tracked-token balance if `token` given, else native balance."""
    chain, addr = str(entry["chain"]), entry["addr"]
    rpc = WATCH_RPC.get(chain)
    call = _rpc or fs._rpc
    code = call(rpc, "eth_getCode", [addr, "latest"]) or "0x"
    code_hash = hashlib.sha256(code.encode()).hexdigest()[:16]
    native = int(call(rpc, "eth_getBalance", [addr, "latest"]) or "0x0", 16)
    token = entry.get("token")
    tval = tdec = tsym = None
    if token:
        try:
            tval = T._erc20_balance(addr, token, chain, rpc)
        except Exception:
            tval = None
        tdec, tsym = _token_meta(token, chain, rpc, call)
    value = tval if token else native
    try:
        last_days = T.last_activity_days(addr, chain) if chain.isdigit() else None
    except Exception:
        last_days = None
    return {"ts": now_iso, "code_hash": code_hash, "native": native, "token_val": tval,
            "token_dec": tdec, "token_sym": tsym,
            "value": int(value or 0), "has_code": len(code) > 4, "last_days": last_days}


def _fmtv(v, snap):
    """Human-readable value using the snapshot's token decimals+symbol (e.g. '50.82 USD-T0'), else raw/ETH."""
    v = int(v or 0)
    dec, sym = snap.get("token_dec"), snap.get("token_sym")
    if dec is not None:
        n = v / (10 ** dec)
        s = ("%.2f" % n) if (n >= 1000 or dec <= 2) else ("%.4f" % n).rstrip("0").rstrip(".")
        return "%s %s" % (s, sym or "tokens")
    if sym or snap.get("token_val") is not None:
        return "%d %s" % (v, sym or "units")
    return "%s ETH" % (("%.4f" % (v / 1e18)).rstrip("0").rstrip("."))


def classify(prev, cur):
    """prev/cur snapshots -> list of event dicts {type, sev, detail}. Pure -> golden-tested.
    prev None = first-ever snapshot (baseline) -> no events. HIGH events push to Telegram + browser."""
    if prev is None:
        return []
    ev = []
    if cur.get("has_code") and prev.get("code_hash") and cur.get("code_hash") != prev["code_hash"]:
        ev.append({"type": "CODE-CHANGE", "sev": "HIGH",
                   "detail": "eth_getCode hash %s -> %s (redeploy / proxy-impl swap -> re-review)"
                             % (prev["code_hash"], cur["code_hash"])})
    pv, cv = int(prev.get("value") or 0), int(cur.get("value") or 0)
    if pv == 0 and cv > 0:
        ev.append({"type": "FUNDED", "sev": "HIGH",
                   "detail": "value 0 -> %s (a dormant finding may have gone LIVE -> reassess + disclose)" % _fmtv(cv, cur)})
    elif pv > 0 and cv <= pv * _DRAIN:
        ev.append({"type": "DRAINED", "sev": "HIGH",
                   "detail": "value %s -> %s (>=%.0f%% drop -> POSSIBLE EXPLOIT / withdrawal -> INVESTIGATE)"
                             % (_fmtv(pv, prev), _fmtv(cv, cur), _DRAIN * 100)})
    elif pv > 0 and cv >= pv * _GROW:
        ev.append({"type": "GREW", "sev": "HIGH",
                   "detail": "value %s -> %s (>=%.0fx -> TVL GROWTH: a live finding's honeypot just got bigger)"
                             % (_fmtv(pv, prev), _fmtv(cv, cur), _GROW)})
    pd, cd = prev.get("last_days"), cur.get("last_days")
    if pd is not None and cd is not None and pd > 30 and cd < 7:
        ev.append({"type": "REACTIVATED", "sev": "MED",
                   "detail": "last-tx %.0fd ago -> %.1fd ago (dormant -> active again)" % (pd, cd)})
    return ev


def _notify_windows(title, msg):
    """Best-effort Windows balloon/toast for a HIGH event (mirrors the contest-watch). No-op off Windows."""
    if os.name != "nt":
        return
    ps = ("[void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');"
          "$n=New-Object System.Windows.Forms.NotifyIcon;"
          "$n.Icon=[System.Drawing.SystemIcons]::Warning;$n.BalloonTipTitle=%r;$n.BalloonTipText=%r;"
          "$n.Visible=$true;$n.ShowBalloonTip(15000);Start-Sleep -Seconds 2;$n.Dispose()" % (title, msg))
    try:
        subprocess.run(["powershell", "-NoProfile", "-Command", ps], timeout=20,
                       capture_output=True, check=False)
    except Exception:
        pass


def _notify_telegram(title, msg, _open=urllib.request.urlopen):
    """Push a HIGH event to a Telegram bot. Reads TG_BOT_TOKEN + TG_CHAT_ID from env (in ~/.seclab_env).
    Graceful no-op when unset -> the feature activates the moment the two creds are added. Returns bool sent."""
    tok, chat = os.environ.get("TG_BOT_TOKEN"), os.environ.get("TG_CHAT_ID")
    if not tok or not chat:
        return False
    try:
        data = urllib.parse.urlencode({"chat_id": chat, "text": (title + "\n" + msg)[:3900],
                                       "disable_web_page_preview": "true"}).encode()
        _open("https://api.telegram.org/bot%s/sendMessage" % tok, data=data, timeout=15)
        return True
    except Exception:
        return False


def run(notify=False, now_iso="", prio_only=False, _snap=snapshot):
    """Snapshot each watchlist target, diff vs last state, emit + persist + notify. Returns the new events.
    prio_only -> only entries flagged `prio` (the critical/live findings we check on a tighter cadence)."""
    wl = _load(WATCHLIST, [])
    if prio_only:
        wl = [e for e in wl if e.get("prio")]
    state = _load(STATE, {})
    all_events, new_state = [], dict(state)
    for e in wl:
        key = e["key"]
        try:
            cur = _snap(e, now_iso)
        except Exception as ex:
            print("  [%s] snapshot failed: %s" % (key, str(ex)[:80]))
            continue
        for ev in classify(state.get(key), cur):
            ev.update({"key": key, "chain": str(e["chain"]), "addr": e["addr"], "ts": now_iso})
            all_events.append(ev)
        new_state[key] = cur
    _save(STATE, new_state)
    if all_events:
        log = _load(EVENTS, [])
        log.extend(all_events)
        _save(EVENTS, log)
        _append_queue(all_events, now_iso)
        for ev in all_events:
            mark = ">>> " if ev["sev"] == "HIGH" else "    "
            print("%s%-11s [%s] %s @ %s -- %s" % (mark, ev["type"], ev["sev"], ev["key"], ev["chain"], ev["detail"]))
            if ev["sev"] == "HIGH":
                title = "🚨 security-lab: %s %s" % (ev["type"], ev["key"])
                _notify_telegram(title, "%s @ chain %s\n%s" % (ev["addr"], ev["chain"], ev["detail"][:600]))
                if notify:
                    _notify_windows(title, ev["detail"][:200])
    else:
        print("watch: no material change across %d target(s)." % len(wl))
    return all_events


def _append_queue(events, now_iso):
    os.makedirs(os.path.dirname(QUEUE), exist_ok=True)
    lines = ["", "## watch events %s" % now_iso]
    for ev in events:
        lines.append("- **%s** [%s] `%s` @ chain %s -- %s (`%s`)"
                     % (ev["type"], ev["sev"], ev["key"], ev["chain"], ev["detail"], ev["addr"]))
    with open(QUEUE, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main():
    ap = argparse.ArgumentParser(description="Change-event monitor over tracked targets (value/liveness delta)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add")
    a.add_argument("key"); a.add_argument("chain"); a.add_argument("addr")
    a.add_argument("--token", default=None, help="ERC20 whose balance IS the tracked value (e.g. the vault collateral)")
    a.add_argument("--note", default="")
    a.add_argument("--prio", default=None, help="frequent-check tier tag (e.g. 'critical') -> `run --only-prio`")
    r = sub.add_parser("run")
    r.add_argument("--notify", action="store_true", help="pop a Windows balloon for HIGH events (Telegram fires regardless)")
    r.add_argument("--only-prio", action="store_true", help="check only prio-tagged targets (the tight-cadence tier)")
    r.add_argument("--date", default="", help="timestamp override (tests/determinism)")
    sub.add_parser("list")
    ev = sub.add_parser("events"); ev.add_argument("--n", type=int, default=20)
    args = ap.parse_args()

    if args.cmd == "add":
        wl = _load(WATCHLIST, [])
        wl = [x for x in wl if x["key"] != args.key]  # replace same key
        entry = {"key": args.key, "chain": args.chain, "addr": args.addr, "note": args.note}
        if args.token:
            entry["token"] = args.token
        if args.prio:
            entry["prio"] = args.prio
        wl.append(entry)
        _save(WATCHLIST, wl)
        print("watchlist: %d target(s); added/updated %s (chain %s, %s%s)" % (
            len(wl), args.key, args.chain, args.addr, " token=%s" % args.token if args.token else ""))
    elif args.cmd == "run":
        import datetime
        now = args.date or datetime.datetime.now().replace(microsecond=0).isoformat()
        sys.exit(10 if run(notify=args.notify, now_iso=now, prio_only=args.only_prio) else 0)
    elif args.cmd == "list":
        for e in _load(WATCHLIST, []):
            print("  %-26s chain %-6s %s%s" % (e["key"], e["chain"], e["addr"],
                                               "  token=%s" % e["token"] if e.get("token") else ""))
    elif args.cmd == "events":
        for ev in _load(EVENTS, [])[-args.n:]:
            print("  %s %-11s [%s] %-22s @ %s -- %s" % (ev.get("ts", "")[:19], ev["type"], ev["sev"], ev["key"],
                                                        ev["chain"], ev["detail"][:90]))


if __name__ == "__main__":
    main()
