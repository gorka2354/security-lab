#!/usr/bin/env python3
"""lab_mcp.py - Layer 2a of the platform: an MCP server over labcore (research/platform/DESIGN-platform.md).

Lets Claude (this CLI, claude.ai, phone) drive the lab as TOOLS instead of reading files: pipeline, targets,
next-DIG, findings, parked, radars, metrics, and the one mutation record_verdict. Hand-rolled stdlib JSON-RPC
2.0 over stdio (newline-delimited) - NO pip dependency, keeps the lab stdlib-first and install-free.

Register in Claude Code (project .mcp.json already does this):
    { "mcpServers": { "security-lab": { "command": "python3", "args": ["toolkit/lab_mcp.py"] } } }
Then call e.g. the `lab_next_dig` / `lab_pipeline` / `lab_record_verdict` tools.

`handle(req, tools)` is pure (request dict -> response dict | None) so the protocol is golden-tested without
real stdio. main() is the stdin/stdout loop.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import labcore as C

PROTOCOL = "2025-06-18"
SERVER = {"name": "security-lab", "version": "1"}


def _ok(mid, result):
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _err(mid, code, msg):
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": msg}}


# --- tool registry: (name, description, JSON-Schema, fn(args)->jsonable) ---
def build_tools():
    def schema(**props):
        return {"type": "object", "properties": props, "required": [k for k, v in props.items() if v.get("_req")]}
    def opt(desc):  # optional string param
        return {"type": "string", "description": desc}
    def req(desc):  # required string param
        return {"type": "string", "description": desc, "_req": True}

    return [
        ("lab_pipeline", "Pipeline rollup: target counts by stage (REAL/DIG/PARK/SKIP/CLEAN), findings, "
         "parked, repos, precision/recall.", schema(), lambda a: C.pipeline()),
        ("lab_next_dig", "The actionable backlog ranked for work (REAL before DIG, oldest-touched first): "
         "the next target + the top of the queue.", schema(), lambda a: C.next_dig()),
        ("lab_targets", "Filtered targets. All filters optional and AND together.",
         schema(status=opt("REAL|DIG|CLEAN"), zone=opt("e.g. lending/dex/bridge"), fork=opt("fork_base"),
                chain=opt("e.g. eth"), sensitivity=opt("high|normal")),
         lambda a: [{"id": t["id"], "name": t["name"], "status": t["status"], "zones": t.get("zones"),
                     "fork_base": t.get("fork_base"), "chains": t.get("chains"),
                     "verdicts": len(t.get("verdicts", []))}
                    for t in C.targets(a.get("status"), a.get("zone"), a.get("fork"), a.get("chain"),
                                       a.get("sensitivity"))]),
        ("lab_target", "Full detail for one target by id or name (incl. verdict history).",
         schema(id=req("target id or name")), lambda a: C.target(a.get("id"))),
        ("lab_findings", "Tracked findings with the calibration lifecycle (sev claimed->awarded, status, "
         "bounty).", schema(), lambda a: C.findings()),
        ("lab_parked", "Parked leads watching for a bounty/contest launch.", schema(), lambda a: C.parked()),
        ("lab_radars", "Radar state: change/fresh-deploy/fresh-feed/secrets counts + fresh items.",
         schema(), lambda a: C.radars()),
        ("lab_metrics", "Calibration metrics: precision + recall.", schema(), lambda a: C.metrics()),
        ("lab_record_verdict", "MUTATION: record a triage verdict to the ledger (re-derives into the target). "
         "verdict in {fp,known,wontfix,real,todo}.",
         schema(target=req("target name"), verdict=req("fp|known|wontfix|real|todo"), reason=req("why"),
                detector=opt("detector key (default manual)"), file=opt("file"), line=opt("line")),
         lambda a: C.record_verdict(a.get("target"), a.get("verdict"), a.get("reason"),
                                    detector=a.get("detector", "manual"), file=a.get("file", "(labcore)"),
                                    line=int(a.get("line", 0) or 0))),
    ]


def handle(req, tools):
    """Pure JSON-RPC dispatch. Returns the response dict, or None for notifications (no reply)."""
    mid = req.get("id")
    method = req.get("method")
    is_notification = "id" not in req
    if method == "initialize":
        ver = (req.get("params") or {}).get("protocolVersion") or PROTOCOL
        return _ok(mid, {"protocolVersion": ver, "capabilities": {"tools": {}}, "serverInfo": SERVER})
    if method in ("notifications/initialized", "initialized") or is_notification:
        return None
    if method == "ping":
        return _ok(mid, {})
    if method == "tools/list":
        return _ok(mid, {"tools": [{"name": n, "description": d, "inputSchema": _clean(s)}
                                   for (n, d, s, _f) in tools]})
    if method == "tools/call":
        p = req.get("params") or {}
        name, args = p.get("name"), (p.get("arguments") or {})
        t = next((t for t in tools if t[0] == name), None)
        if not t:
            return _err(mid, -32602, f"unknown tool: {name}")
        try:
            res = t[3](args)
            text = json.dumps(res, ensure_ascii=False, indent=1, default=str)
            return _ok(mid, {"content": [{"type": "text", "text": text}]})
        except Exception as e:                       # tool errors are results (isError), not protocol errors
            return _ok(mid, {"content": [{"type": "text", "text": f"error: {e}"}], "isError": True})
    return _err(mid, -32601, f"method not found: {method}")


def _clean(schema):
    """Strip our internal `_req` markers from property schemas before sending."""
    props = {k: {kk: vv for kk, vv in v.items() if kk != "_req"} for k, v in schema.get("properties", {}).items()}
    return {"type": "object", "properties": props, "required": schema.get("required", [])}


def main():
    tools = build_tools()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        resp = handle(req, tools)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
