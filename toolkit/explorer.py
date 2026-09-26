"""explorer.py - the one port to block-explorer ACCOUNT data (txlist / tokentx) behind the liveness + value checks.

Backends, in order:
  1. Etherscan-v2 (ETHERSCAN_API_KEY; 60+ chains by chainid). The FREE tier refuses some chains outright --
     "Free API access is not supported for this chain" for Base / BSC / OP (checked 2026-09-26) -- and X Layer (196)
     is not an Etherscan-v2 chain at all.
  2. A keyless Blockscout instance (the same Etherscan-style module=account API), trusted only while CURRENT: its
     head block must be within MAX_LAG_S of the chain head, both timestamps read from OUR RPC. A lagging index would
     silently turn a live contract DORMANT. Base's Blockscout answers keyless calls with 429 -> not listed.

A miss returns every backend's own reason, so callers print "UNKNOWN (why)" instead of a silent 0 / EMPTY / "no
key?" -- threat.py read Base/BSC contracts as EMPTY with unknown recency until the 2026-09-25 recheck caught it.
Read-only, stdlib only.
"""

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request

import fetch_source as fs  # RPC map + _rpc (the freshness check reads block timestamps from our own node)
import tlsfix  # noqa: F401  -- current CA bundle on stale-CA Windows hosts (see tlsfix.py)

ETHERSCAN_V2 = "https://api.etherscan.io/v2/api"
# chain id -> keyless Etherscan-compatible Blockscout API, for chains the Etherscan free tier refuses
BLOCKSCOUT = {
    "10": "https://optimism.blockscout.com/api",   # OP: Etherscan free tier refuses it; index current (lag ~3s)
}
MAX_LAG_S = 3600
_fresh = {}  # chain -> (ok, why), once per process
_memo = {}   # (chain, query) -> (rows, source): threat + activity ask the same question once per process


def reset():
    """Forget cached freshness verdicts + answers (tests; a long-lived caller between rounds)."""
    _fresh.clear()
    _memo.clear()


def _get_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "security-lab/1.0"})
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def _why(e):
    """Exception -> a short reason. Never echoes a request URL: Etherscan URLs carry the API key."""
    s = "HTTP %s %s" % (e.code, e.reason) if isinstance(e, urllib.error.HTTPError) else str(getattr(e, "reason", e))
    return re.sub(r"apikey=[^&\s]+", "apikey=***", s)[:100] or type(e).__name__


def parse(d):
    """Etherscan-style {status, message, result} -> (rows, error). PURE.
    A list result -- even [] ('No transactions found') -- is an ANSWER. A string result (free-tier refusal,
    unsupported chainid, rate limit, query timeout) is an ERROR in the explorer's own words (first sentence)."""
    if not isinstance(d, dict):
        return None, "malformed reply"
    res = d.get("result")
    if isinstance(res, list):
        return res, None
    msg = res if isinstance(res, str) and res.strip() else (d.get("message") or "empty reply")
    return None, str(msg).split(". ")[0].strip()[:120]


def _rate_limited(err):
    e = (err or "").lower()
    return "429" in e or "rate limit" in e or "too many" in e


def _ask(get, url, sleep, parser=parse):
    """One backend call -> (answer, err). A rate-limit answer (HTTP 429 / 'Max rate limit reached') is retried twice
    with a short backoff: keyless Blockscout throttles even the 4-5 calls of a single threat.py run."""
    for attempt in range(3):
        try:
            ans, err = parser(get(url))
        except Exception as e:
            ans, err = None, _why(e)
        if ans is not None or not _rate_limited(err) or attempt == 2:
            return ans, err
        sleep(1.5 * (attempt + 1))
    return None, "unreachable"


def _head_block(d):
    """Blockscout eth_block_number reply ({"result": "0x.."}) -> (int, None) | (None, why). PURE."""
    try:
        return int(d["result"], 16), None
    except Exception:
        return None, parse(d)[1] if isinstance(d, dict) else "malformed reply"


def blockscout_fresh(chain, get=None, rpc_call=None, sleep=None):
    """(ok, why): is this chain's Blockscout index current? Compares the explorer's head block with the chain head,
    timestamps from our RPC (no trust in the explorer's clock or ours). A verdict is cached per process; a failed
    CHECK (rate limit, network) is not, so one throttled call can't blind the rest of the run."""
    chain = str(chain)
    if chain in _fresh:
        return _fresh[chain]
    get, rpc_call, sleep = get or _get_json, rpc_call or fs._rpc, sleep or time.sleep
    rpc = fs.DEFAULT_RPC.get(chain)
    if not rpc:
        return False, "no RPC for chain %s to verify the index against" % chain
    head, err = _ask(get, BLOCKSCOUT[chain] + "?module=block&action=eth_block_number", sleep, parser=_head_block)
    if head is None:
        return False, "freshness check failed (%s)" % err
    try:
        latest = rpc_call(rpc, "eth_getBlockByNumber", ["latest", False])
        lag = 0
        if head < int(latest["number"], 16):
            blk = rpc_call(rpc, "eth_getBlockByNumber", [hex(head), False])
            lag = int(latest["timestamp"], 16) - int(blk["timestamp"], 16)
    except Exception as e:
        return False, "freshness check failed (%s)" % _why(e)
    _fresh[chain] = (True, None) if lag <= MAX_LAG_S else (
        False, "index %.1fh behind the chain head -> not trusted for recency/holdings" % (lag / 3600.0))
    return _fresh[chain]


def query(chain, params, key=None, get=None, rpc_call=None, sleep=None):
    """module=account query -> (rows, source, why). rows None = no backend could answer; `why` then carries each
    backend's refusal so the caller can say WHY the answer is unknown. rows [] = answered: nothing on record."""
    get, sleep = get or _get_json, sleep or time.sleep
    key = os.environ.get("ETHERSCAN_API_KEY", "") if key is None else key
    chain, qs, whys = str(chain), urllib.parse.urlencode(params), []
    if (chain, qs) in _memo:
        return _memo[(chain, qs)] + (None,)
    if key:
        rows, err = _ask(get, "%s?chainid=%s&%s&apikey=%s" % (ETHERSCAN_V2, chain, qs, key), sleep)
        if rows is not None:
            _memo[(chain, qs)] = (rows, "etherscan")
            return rows, "etherscan", None
        whys.append("etherscan: %s" % err)
    else:
        whys.append("etherscan: no ETHERSCAN_API_KEY")
    base = BLOCKSCOUT.get(chain)
    if not base:
        whys.append("no keyless explorer fallback for chain %s" % chain)
        return None, None, "; ".join(whys)
    ok, fwhy = blockscout_fresh(chain, get=get, rpc_call=rpc_call, sleep=sleep)
    if not ok:
        whys.append("blockscout: %s" % fwhy)
        return None, None, "; ".join(whys)
    rows, err = _ask(get, "%s?%s" % (base, qs), sleep)
    if rows is not None:
        _memo[(chain, qs)] = (rows, "blockscout")
        return rows, "blockscout", None
    whys.append("blockscout: %s" % err)
    return None, None, "; ".join(whys)


def row_ts(r):
    """A txlist/tokentx row's unix timeStamp; 0 when absent or malformed. PURE."""
    try:
        return int(r.get("timeStamp") or 0)
    except (AttributeError, TypeError, ValueError):
        return 0


def tokens_moved(rows, addr, limit=15):
    """tokentx rows of `addr` -> the distinct ERC20s it moved, newest first:
    [(token, symbol, decimals, sent, n_senders)]. PURE. sent = `addr` transferred it out at least once;
    n_senders = distinct addresses that sent it in (a one-sender, inbound-only token is the airdrop-spam shape).
    decimals None when the explorer didn't say (balances then print raw, never mis-scaled by a guessed 1e18)."""
    me, order, meta, sent, senders = (addr or "").lower(), [], {}, set(), {}
    for r in rows or []:
        tok = (r.get("contractAddress") or "").lower()
        if not tok:
            continue
        if tok not in meta:
            dec = str(r.get("tokenDecimal") or "")
            meta[tok] = (r.get("tokenSymbol") or None, int(dec) if dec.isdigit() else None)
            order.append(tok)
        frm = (r.get("from") or "").lower()
        if frm == me:
            sent.add(tok)
        elif frm:
            senders.setdefault(tok, set()).add(frm)
    return [(t, meta[t][0], meta[t][1], t in sent, len(senders.get(t, ()))) for t in order[:limit]]
