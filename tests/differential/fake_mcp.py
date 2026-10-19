#!/usr/bin/env python3
"""A stdio MCP server with one tool, `echo`, for the real-agent scenarios of the
differential suite (crates/openmoat-cli/tests/e2e/differential/agents.rs): the
agent starts it from its MCP configuration, and each `tools/call` that reaches
it appends a line to the marker file, so a test can tell a call that ran from
one that was refused before it got here.

  fake_mcp.py <marker> [anything else, ignored: a changed definition]

Newline-delimited JSON-RPC 2.0 on stdin and stdout, as the MCP stdio transport
sends it. Nothing touches the network.
"""
import json
import sys

MARKER = sys.argv[1]
TOOL = {
    "name": "echo",
    "description": "Echo the text back.",
    "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}},
}


def answer(req):
    method = req.get("method")
    params = req.get("params") or {}
    if method == "initialize":
        return {"protocolVersion": params.get("protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "moat-probe", "version": "1.0.0"}}
    if method == "tools/list":
        return {"tools": [TOOL]}
    if method == "tools/call":
        text = (params.get("arguments") or {}).get("text", "")
        with open(MARKER, "a", encoding="utf-8") as f:
            f.write(f"called {text}\n")
        return {"content": [{"type": "text", "text": f"echo {text}"}]}
    if method == "ping":
        return {}
    return None


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req = json.loads(line)
        if "id" not in req:
            continue  # a notification (`notifications/initialized`)
        result = answer(req)
        if result is None:
            reply = {"jsonrpc": "2.0", "id": req["id"],
                     "error": {"code": -32601, "message": f"no method {req.get('method')}"}}
        else:
            reply = {"jsonrpc": "2.0", "id": req["id"], "result": result}
        sys.stdout.write(json.dumps(reply) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
