#!/usr/bin/env python3
"""dashboard.py - serve the read-only platform dashboard (Inc 2 of research/platform/DESIGN-platform.md).

Regenerates the lab-state contract, serves the repo ROOT on localhost (so web/index.html can fetch
/monitor/lab-state.json without CORS/file:// issues), and opens the page.

    python toolkit/dashboard.py [--port 8787] [--no-open]

Read-only by design: stdio MCP can't reach a browser, so mutations land in Inc 3/4 (MCP + HTTP bridge).
Stdlib only.
"""
import argparse
import functools
import http.server
import json
import os
import socketserver
import sys
import webbrowser

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import labstate

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


class _Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass  # quiet: don't spam the console with every asset request


def regenerate():
    state = labstate.build()
    p = os.path.join(ROOT, "monitor", "lab-state.json")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    json.dump(state, open(p, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    return state


def main():
    ap = argparse.ArgumentParser(description="Serve the read-only lab dashboard")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--no-open", action="store_true", help="don't auto-open the browser")
    a = ap.parse_args()

    state = regenerate()
    n = len(state["targets"])
    print(f"[dashboard] lab-state regenerated ({n} targets, {len(state['findings'])} findings)")

    handler = functools.partial(_Handler, directory=ROOT)
    socketserver.TCPServer.allow_reuse_address = True
    url = f"http://127.0.0.1:{a.port}/web/index.html"
    with socketserver.TCPServer(("127.0.0.1", a.port), handler) as httpd:
        print(f"[dashboard] serving {ROOT}")
        print(f"[dashboard] open -> {url}   (Ctrl-C to stop)")
        if not a.no_open:
            try:
                webbrowser.open(url)
            except Exception:
                pass
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[dashboard] stopped")


if __name__ == "__main__":
    main()
