#!/usr/bin/env python3
"""watch.py - CHANGE-EVENT monitor over our tracked targets (real findings + key live targets).

Snapshots each watchlist target's on-chain state (code-hash + native/tracked-token value + activity) and
emits EVENTS on MATERIAL change, so a dormant finding that goes LIVE -- or a funded target that gets DRAINED
(possible exploit) -- surfaces automatically instead of us re-checking by hand. Complements radar.py, which
already covers IMPL-UPGRADE (proxy-impl swap) + BOUNTY-OPEN; watch.py adds the VALUE/LIVENESS delta.

  FUNDED   - value appeared where there was none  -> a finding may have gone LIVE (reassess + disclose)
  GREW     - tracked value rose >=2x              -> TVL growth -> a bounded finding is now worth more
  DRAINED  - tracked value dropped >=50%          -> POSSIBLE EXPLOIT / mass-withdrawal -> INVESTIGATE
             (+ where it went: each recipient since the last check vs what it had put in -- payout or drain?)
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
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import tlsfix  # noqa: F401,E402  -- current CA bundle on stale-CA Windows hosts (see tlsfix.py)
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import explorer as ex  # noqa: E402  (txlist / txlistinternal / tokentx behind one port; a miss says why)
import fetch_source as fs  # noqa: E402  (RPC map + _rpc + native_symbol)
import threat as T  # noqa: E402  (last_activity_days + _erc20_balance + token_meta + fmt_units)

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WATCHLIST = os.path.join(_ROOT, "monitor", "watch-targets.json")  # NB: watchlist.json is the parked-leads store
STATE = os.path.join(_ROOT, "monitor", "watch-state.json")
EVENTS = os.path.join(_ROOT, "monitor", "watch-events.json")
QUEUE = os.path.join(_ROOT, "hunts", "_radar", "QUEUE.md")

WATCH_RPC = fs.DEFAULT_RPC  # one RPC map for the whole toolkit (the exotic GameFi chains live there too)
_DRAIN = 0.5   # value drop >= this fraction -> DRAINED
_GROW = 2.0    # value rise >= this multiple -> GREW
_HIGH = {"FUNDED", "DRAINED", "CODE-CHANGE"}
_FLOW_LOOKBACK_S = 7 * 86400  # DRAINED with no usable baseline timestamp -> look this far back for the outflows
_FLOW_SLACK_S = 3600          # host clock vs block time
_FLOW_TOP = 4                 # recipients named in the alert; the rest are summed
_FLOW_PAGE = 1000             # explorer rows per request
_FLOW_PAGES = 5               # pages per action (Etherscan serves page*offset <= 10000); beyond -> the note says capped


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


def snapshot(entry, now_iso, _rpc=None):
    """On-chain state of one watchlist target -> a comparable snapshot dict. Network; _rpc injectable for tests.
    entry = {key, chain, addr, token?}. value = tracked-token balance if `token` given, else native balance."""
    chain, addr = str(entry["chain"]), entry["addr"]
    rpc = WATCH_RPC.get(chain)
    call = _rpc or fs._rpc
    code = call(rpc, "eth_getCode", [addr, "latest"]) or "0x"
    code_hash = hashlib.sha256(code.encode()).hexdigest()[:16]
    braw = call(rpc, "eth_getBalance", [addr, "latest"])
    native = int(braw, 16) if braw else None  # None = the RPC gave no answer -> unknown, NOT a 0 (false DRAINED)
    token = entry.get("token")
    tval = tdec = tsym = None
    if token:
        try:
            tval = T._erc20_balance(addr, token, chain, rpc)
        except Exception:
            tval = None
        tdec, tsym = T.token_meta(token, rpc, call)
    value = tval if token else native
    try:
        last_days = T.last_activity_days(addr, chain) if chain.isdigit() else None
    except Exception:
        last_days = None
    return {"ts": now_iso, "code_hash": code_hash, "native": native, "native_sym": fs.native_symbol(chain),
            "token_val": tval, "token_dec": tdec, "token_sym": tsym,
            "value": None if value is None else int(value), "has_code": len(code) > 4, "last_days": last_days}


def _fmtv(v, snap):
    """Human-readable value using the snapshot's token decimals+symbol (e.g. '50.82 USD-T0'), else the chain's
    native symbol ('111 APE'; 'native' when unknown -- the old hard-coded ETH turned 111 APE into a 111-ETH alarm)."""
    v = int(v or 0)
    dec, sym = snap.get("token_dec"), snap.get("token_sym")
    if dec is not None:
        return "%s %s" % (T.fmt_units(v, dec), sym or "tokens")
    if sym or snap.get("token_val") is not None:
        return "%d %s" % (v, sym or "units")
    return "%s %s" % (("%.4f" % (v / 1e18)).rstrip("0").rstrip("."), snap.get("native_sym") or "native")


def classify(prev, cur):
    """prev/cur snapshots -> list of event dicts {type, sev, detail}. Pure -> golden-tested.
    prev None = first-ever snapshot (baseline) -> no events. HIGH events push to Telegram + browser."""
    if prev is None:
        return []
    prev = dict(prev, native_sym=prev.get("native_sym") or cur.get("native_sym"))  # baselines from before the field
    ev = []
    if cur.get("has_code") and prev.get("code_hash") and cur.get("code_hash") != prev["code_hash"]:
        ev.append({"type": "CODE-CHANGE", "sev": "HIGH",
                   "detail": "eth_getCode hash %s -> %s (redeploy / proxy-impl swap -> re-review)"
                             % (prev["code_hash"], cur["code_hash"])})
    pv, cv = prev.get("value"), cur.get("value")
    if pv is None or cv is None:  # a value this cycle (or the baseline) was unread -> no value event, no guess
        pass
    elif pv == 0 and cv > 0:
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


def _iso_ts(iso):
    """A snapshot's ISO stamp -> unix seconds (naive = this host's local time, as run() writes it); None if unusable."""
    try:
        return datetime.datetime.fromisoformat(iso).timestamp()
    except (TypeError, ValueError, OSError, OverflowError):  # Windows: pre-1970 local stamps raise OSError
        return None


def fetch_flows(entry, since, _query=None):
    """Explorer rows of one target -> (out_rows, in_rows, why, capped). Network; _query injectable (explorer.query's
    shape). Native value: txlist + txlistinternal; a tracked token: its tokentx. out = value that LEFT the target
    at/after `since`; in = everything ever paid IN (the recipients' stakes). Reverted rows dropped. Paged newest-first
    up to _FLOW_PAGES; capped = the history went further (or a later page failed) -> the sums are lower bounds.
    First page refused -> (None, None, why, False)."""
    q = _query or ex.query
    me, tok = entry["addr"].lower(), entry.get("token")
    base = {"module": "account", "address": entry["addr"], "sort": "desc", "offset": _FLOW_PAGE}
    actions = [("tokentx", {"contractaddress": tok})] if tok else [("txlist", {}), ("txlistinternal", {})]
    rows, capped = [], False
    for action, extra in actions:
        for page in range(1, _FLOW_PAGES + 1):
            got, _src, why = q(str(entry["chain"]), dict(base, action=action, page=page, **extra))
            if got is None:
                if page == 1:
                    return None, None, why, False
                capped = True
                break
            rows += got
            if len(got) < _FLOW_PAGE:
                break
        else:
            capped = True
    rows = [r for r in rows if str(r.get("isError") or "0") != "1"]
    out = [r for r in rows if (r.get("from") or "").lower() == me and ex.row_ts(r) >= since]
    inn = [r for r in rows if (r.get("to") or "").lower() == me]
    return out, inn, None, capped


def summarize_flows(out_rows, in_rows, fmt, capped=False):
    """Where the value went, one line: each recipient's take vs what it had put in. PURE. fmt: raw int -> label.
    An outsider drain = value to never-depositors; a game payout / withdrawal = value back to the addresses that paid
    in. States facts, never downgrades the event: an inflate-then-redeem attacker is a depositor too, which is why
    'put in' is printed next to 'got' instead of a payout/exploit verdict. capped -> says the sums are lower bounds.
    A CREATE row carries its recipient in contractAddress (to is empty)."""
    def amt(r):
        try:
            return int(r.get("value") or 0)
        except (TypeError, ValueError):
            return 0
    got, put = {}, {}
    for r in out_rows:
        if amt(r):
            to = (r.get("to") or r.get("contractAddress") or "?").lower()
            got[to] = got.get(to, 0) + amt(r)
    for r in in_rows:
        frm = (r.get("from") or "?").lower()
        put[frm] = put.get(frm, 0) + amt(r)
    total = sum(got.values())
    cap = "; explorer history capped at %d rows/action -> sums are lower bounds" % (_FLOW_PAGE * _FLOW_PAGES)
    if not total:
        return ("flows: no outflow on record since the last check (explorer lag, or value left without a transfer?)"
                + (cap if capped else ""))
    ranked = sorted(got.items(), key=lambda kv: -kv[1])
    parts = ["%s -> %s.. (put in %s)" % (fmt(v), a[:10], fmt(put.get(a, 0))) for a, v in ranked[:_FLOW_TOP]]
    if len(ranked) > _FLOW_TOP:
        parts.append("+%d more: %s" % (len(ranked) - _FLOW_TOP, fmt(sum(v for _, v in ranked[_FLOW_TOP:]))))
    back = sum(v for a, v in got.items() if put.get(a))
    return "flows: %s out to %d addr: %s; %.0f%% to addresses that had paid in%s" % (
        fmt(total), len(ranked), ", ".join(parts), 100.0 * back / total, cap if capped else "")


def flow_note(entry, prev, cur, _fetch=None):
    """DRAINED -> the summarize_flows line for the window since the baseline value was READ (value_ts: an unread
    cycle keeps the old value but must not slide the window past the drain). Never raises: a lookup the explorer
    can't answer says UNKNOWN and why (free tier refuses Base/BSC/OP), never a silent 'no outflow'."""
    try:
        since = _iso_ts(prev.get("value_ts") or prev.get("ts")) or (time.time() - _FLOW_LOOKBACK_S)
        out, inn, why, capped = (_fetch or fetch_flows)(entry, since - _FLOW_SLACK_S)
    except Exception as e:
        out, inn, why, capped = None, None, ex._why(e), False
    if out is None:
        return "flows: UNKNOWN (%s)" % re.sub(r"apikey=[^&\s]+", "apikey=***", str(why))
    return summarize_flows(out, inn, lambda v: _fmtv(v, cur), capped)


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


def run(notify=False, now_iso="", prio_only=False, _snap=snapshot, _flows=None):
    """Snapshot each watchlist target, diff vs last state, emit + persist + notify. Returns the new events.
    prio_only -> only entries flagged `prio` (the critical/live findings we check on a tighter cadence).
    A DRAINED event carries flow_note() (where the value went); _flows is fetch_flows' injectable stand-in."""
    wl = _load(WATCHLIST, [])
    if prio_only:
        wl = [e for e in wl if e.get("prio")]
    state = _load(STATE, {})
    all_events, new_state = [], dict(state)
    for e in wl:
        key = e["key"]
        try:
            cur = _snap(e, now_iso)
        except Exception as err:
            print("  [%s] snapshot failed: %s" % (key, str(err)[:80]))
            continue
        prev = state.get(key)
        for ev in classify(prev, cur):
            ev.update({"key": key, "chain": str(e["chain"]), "addr": e["addr"], "ts": now_iso})
            if ev["type"] == "DRAINED":
                ev["detail"] += " | " + flow_note(e, prev, cur, _flows)
            all_events.append(ev)
        if prev:  # an unread field keeps the last good baseline, else the next good read diffs against nothing
            for f in ("value", "last_days"):
                if cur.get(f) is None and prev.get(f) is not None:
                    cur = dict(cur, **{f: prev[f], f + "_unread": True})
            if cur.get("value_unread"):  # the carried value was read back then -> a DRAINED flows window starts there
                cur["value_ts"] = prev.get("value_ts") or prev.get("ts")
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
                _notify_telegram(title, "%s @ chain %s\n%s" % (ev["addr"], ev["chain"], ev["detail"][:1200]))
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
