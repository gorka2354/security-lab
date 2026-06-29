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
    "parked": lambda q: C.parked(),
    "radars": lambda q: C.radars(),
    "metrics": lambda q: C.metrics(),
    "repos": lambda q: C.repos(),
    "targets": lambda q: C.targets(status=q.get("status"), zone=q.get("zone"), fork=q.get("fork"),
                                   chain=q.get("chain"), sensitivity=q.get("sensitivity")),
}


def api_get(path):
    """Pure: '/api/<name>?q=..' -> (http_status, jsonable). No sockets."""
    raw = path[len("/api/"):]
    name, _, qs = raw.partition("?")
    q = {k: v[0] for k, v in urllib.parse.parse_qs(qs).items()}
    fn = _READS.get(name)
    if not fn:
        return 404, {"error": f"unknown read api: {name}"}
    try:
        return 200, fn(q)
    except Exception as e:
        return 500, {"error": str(e)}


def api_post(path, body):
    """Pure: '/api/record_verdict' + parsed body -> (http_status, jsonable). No sockets."""
    name = path[len("/api/"):]
    if name != "record_verdict":
        return 404, {"error": f"unknown write api: {name}"}
    try:
        res = C.record_verdict(body.get("target"), body.get("verdict"), body.get("reason"),
                               detector=body.get("detector", "manual"),
                               file=body.get("file", "(dashboard)"), line=int(body.get("line", 0) or 0))
        return 200, res
    except ValueError as e:                          # validation -> 400 (caller's fault)
        return 400, {"error": str(e)}
    except Exception as e:
        return 500, {"error": str(e)}


class Handler(http.server.SimpleHTTPRequestHandler):
    def _send(self, code, obj):
        data = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.startswith("/api/"):
            return self._send(*api_get(self.path))
        return super().do_GET()                      # static files from ROOT

    def do_POST(self):
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


def serve(port=8787, open_browser=True):
    state = labstate.build()                          # regenerate the contract before serving
    p = os.path.join(ROOT, "monitor", "lab-state.json")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    json.dump(state, open(p, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print(f"[lab-http] contract regenerated ({len(state['targets'])} targets); bridge GET/POST /api/* live")

    socketserver.TCPServer.allow_reuse_address = True
    handler = functools.partial(Handler, directory=ROOT)
    url = f"http://127.0.0.1:{port}/web/index.html"
    with socketserver.TCPServer(("127.0.0.1", port), handler) as httpd:   # 127.0.0.1 only -> never network-exposed
        print(f"[lab-http] serving {ROOT}\n[lab-http] open -> {url}   (Ctrl-C to stop)")
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
    a = ap.parse_args()
    serve(a.port, not a.no_open)


if __name__ == "__main__":
    main()
