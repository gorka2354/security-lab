#!/usr/bin/env python3
"""lab_http.py - Layer 1.5 of the platform: a localhost HTTP bridge over labcore
(research/platform/DESIGN-platform.md).

The web dashboard (Inc 2) is read-only because stdio MCP can't reach a browser. This bridge gives it a way
to call labcore: GET /api/<read> (state/pipeline/next_dig/targets/findings/parked/radars/metrics/repos) and
POST /api/record_verdict (the one mutation). Same labcore as the MCP server, so the two frontends never drift.
This same bridge is also the path to remote/phone later (Inc 5: + auth, sensitivity-sanitized projection).

    python toolkit/lab_http.py [--port 8787] [--no-open]      # serve + open the dashboard

Binds 127.0.0.1 ONLY (never network-exposed). Mutations write to OUR ledger (verdict triage), no external
effect. The routing is factored into pure api_get/api_post so it is golden-tested without sockets. Stdlib only.
"""
import argparse
import functools
import http.server
import json
import os
import socketserver
import sys
import urllib.parse
import webbrowser

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import labcore as C
import labstate

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

_READS = {
    "state": lambda q: C.state(),
    "pipeline": lambda q: C.pipeline(),
    "next_dig": lambda q: C.next_dig(),
    "findings": lambda q: C.findings(),
    "finding_detail": lambda q: C.finding_detail(q.get("key")),
    "watch_events": lambda q: C.watch_events(q.get("n", 30)),
    "parked": lambda q: C.parked(),
    "radars": lambda q: C.radars(),
    "metrics": lambda q: C.metrics(),
    "repos": lambda q: C.repos(),
    "targets": lambda q: C.targets(status=q.get("status"), zone=q.get("zone"), fork=q.get("fork"),
                                   chain=q.get("chain"), sensitivity=q.get("sensitivity")),
}


# in PUBLIC mode only these aggregate-safe reads are served, and `state` is sensitivity-sanitized
_PUBLIC_READS = {"state", "pipeline", "metrics", "radars"}


def api_get(path, public=False):
    """Pure: '/api/<name>?q=..' -> (http_status, jsonable). No sockets. In public mode only the aggregate-safe
    reads are allowed and `state` is sanitized (parked->count, verdict reasons dropped)."""
    raw = path[len("/api/"):]
    name, _, qs = raw.partition("?")
    q = {k: v[0] for k, v in urllib.parse.parse_qs(qs).items()}
    if public and name not in _PUBLIC_READS:
        return 403, {"error": f"'{name}' not available in public mode (sanitized aggregate only)"}
    fn = _READS.get(name)
    if not fn:
        return 404, {"error": f"unknown read api: {name}"}
    try:
        res = fn(q)
        if public and name == "state":
            res = labstate.sanitize(res)
        return 200, res
    except Exception as e:
        return 500, {"error": str(e)}


def api_post(path, body):
    """Pure: '/api/record_verdict' or '/api/record_finding' + parsed body -> (http_status, jsonable)."""
    name = path[len("/api/"):]
    try:
        if name == "record_verdict":
            return 200, C.record_verdict(body.get("target"), body.get("verdict"), body.get("reason"),
                                         detector=body.get("detector", "manual"),
                                         file=body.get("file", "(dashboard)"), line=int(body.get("line", 0) or 0))
        if name == "record_finding":                 # ONE-STEP finding log -> calibration + ledger + registry
            return 200, C.record_finding(body.get("target"), body.get("title"), sev=body.get("sev", "?"),
                                         file=body.get("file", ""), line=int(body.get("line", 0) or 0),
                                         status=body.get("status", "drafted"), kind=body.get("kind", "live"),
                                         channel=body.get("channel", "direct"), notes=body.get("notes", ""))
        if name == "discover_contact":                # find a disclosure channel for a target (read-only)
            return 200, C.discover_contact(body.get("target"))
        if name == "save_draft":                      # persist a composed disclosure letter (DRAFT, never sent)
            return 200, C.save_draft(body.get("target"), body.get("subject", ""), body.get("body", ""))
        return 404, {"error": f"unknown write api: {name}"}
    except ValueError as e:                           # validation -> 400 (caller's fault)
        return 400, {"error": str(e)}
    except Exception as e:
        return 500, {"error": str(e)}


class Handler(http.server.SimpleHTTPRequestHandler):
    public = False      # set by serve(): sanitized aggregate-only + no mutations
    token = None        # set by serve(): required bearer/query token when public

    def _send(self, code, obj):
        data = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _authed(self):
        """Token gate (public mode only). Token via `Authorization: Bearer <t>` or `?token=<t>`. Static
        files (the view code, non-sensitive) are NOT gated — only /api/ data is."""
        if not self.public or not self.token:
            return True
        got = self.headers.get("Authorization", "").replace("Bearer ", "").strip()
        if not got:
            got = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("token", [""])[0]
        return got == self.token

    def end_headers(self):
        # the dashboard is a single static HTML file that changes on every sync -> tell browsers to revalidate
        # so a UI update is never masked by a stale cached page (API responses are already fetched no-store).
        if not self.path.startswith("/api/") and (self.path.rstrip("/") == "" or ".html" in self.path):
            self.send_header("Cache-Control", "no-cache, must-revalidate")
        super().end_headers()

    def do_GET(self):
        if self.path.startswith("/api/"):
            if not self._authed():
                return self._send(401, {"error": "unauthorized (token required in public mode)"})
            # A TOKEN-authed request is trusted (private tailnet + secret) -> serve FULL data. Only sanitize
            # when public AND token-less (truly open on the LAN). _authed() already blocked unauthed /api above.
            return self._send(*api_get(self.path, public=(self.public and not self.token)))
        return super().do_GET()                      # static files from ROOT (not gated)

    def do_POST(self):
        if self.public:
            return self._send(403, {"error": "read-only in public mode (no remote mutations)"})
        if not self.path.startswith("/api/"):
            return self._send(404, {"error": "not found"})
        try:
            n = int(self.headers.get("Content-Length", 0) or 0)
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return self._send(400, {"error": "bad json body"})
        self._send(*api_post(self.path, body))

    def log_message(self, *a):
        pass


def serve(port=8787, open_browser=True, host="127.0.0.1", public=False, token=None):
    state = labstate.build()                          # regenerate the contract before serving
    p = os.path.join(ROOT, "monitor", "lab-state.json")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    json.dump(state, open(p, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print(f"[lab-http] contract regenerated ({len(state['targets'])} targets)")

    Handler.public, Handler.token = public, token
    socketserver.TCPServer.allow_reuse_address = True
    handler = functools.partial(Handler, directory=ROOT)
    tq = f"?token={token}" if (public and token) else ""
    url = f"http://{host}:{port}/web/index.html{tq}"
    with socketserver.TCPServer((host, port), handler) as httpd:
        if public:
            print("[lab-http] *** PUBLIC mode: sanitized aggregate only, no mutations, token-gated ***")
            print(f"[lab-http] bound {host}:{port}  (LAN/phone) -- private boundary: never publish this snapshot")
            if not token:
                print("[lab-http] WARNING: --public with NO --token = open on the LAN. Set --token <secret>.")
        else:
            print(f"[lab-http] serving {ROOT}  (localhost, full + mutations)")
        print(f"[lab-http] open -> {url}   (Ctrl-C to stop)")
        if open_browser:
            try:
                webbrowser.open(url)
            except Exception:
                pass
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[lab-http] stopped")


def main():
    ap = argparse.ArgumentParser(description="localhost HTTP bridge + dashboard (static + labcore /api/*)")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--no-open", action="store_true")
    ap.add_argument("--public", action="store_true",
                    help="remote/phone mode: sanitized aggregate only, no mutations, token-gated")
    ap.add_argument("--host", default=None, help="bind host (default 127.0.0.1; use 0.0.0.0 with --public for LAN)")
    ap.add_argument("--token", default=os.environ.get("LAB_TOKEN"), help="required token in --public mode")
    a = ap.parse_args()
    host = a.host or ("0.0.0.0" if a.public else "127.0.0.1")
    serve(a.port, not a.no_open, host=host, public=a.public, token=a.token)


if __name__ == "__main__":
    main()
