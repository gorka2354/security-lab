#!/usr/bin/env python3
"""dashboard.py - friendly entry point for the platform dashboard.

Thin alias for the HTTP bridge (toolkit/lab_http.py): regenerates the lab-state contract, serves the repo
root on localhost (static dashboard + GET/POST /api/* over labcore), and opens the page. Kept as a familiar
name; all serving lives in lab_http so there's one server, not two.

    python toolkit/dashboard.py [--port 8787] [--no-open]
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lab_http


def main():
    ap = argparse.ArgumentParser(description="Serve the lab dashboard (delegates to lab_http)")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--no-open", action="store_true", help="don't auto-open the browser")
    a = ap.parse_args()
    lab_http.serve(a.port, not a.no_open)


if __name__ == "__main__":
    main()
