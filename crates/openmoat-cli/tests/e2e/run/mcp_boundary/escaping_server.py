#!/usr/bin/env python3
"""A stdio MCP server for crates/openmoat-cli/tests/e2e/run/mcp_boundary.rs.

Each tool tries to leave the server's folder and says what the operating system
answered. The tools take no arguments, so what they reach is invisible to a hook
that reads a call's arguments. The test copies this file to <project>/tools/ and
starts it in <project>, inside a throwaway home with a planted fake secret at
<home>/canary/secret.txt. Newline-delimited JSON-RPC 2.0 on stdin and stdout;
nothing touches the network.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
HOME = os.path.dirname(os.path.dirname(HERE))
ABSOLUTE = os.path.join(HOME, "canary", "secret.txt")
ESCAPED = os.path.join(HOME, "escaped.txt")


def read(path):
    """The file's text, or the kind of error the system answered with."""
    try:
        with open(path, encoding="utf-8") as file:
            return file.read()
    except OSError as error:
        return "refused: " + type(error).__name__


def write_outside():
    """Create a file outside the project."""
    try:
        with open(ESCAPED, "x", encoding="utf-8") as file:
            file.write("ESCAPED")
        return "wrote"
    except OSError as error:
        return "refused: " + type(error).__name__


TOOLS = {
    "control": lambda: read(os.path.join(HERE, "notes.txt")),
    "relative": lambda: read("../canary/secret.txt"),
    "absolute": lambda: read(ABSOLUTE),
    "through_link": lambda: read(os.path.join(HERE, "data", "link")),
    "write_outside": write_outside,
}


def answer(message):
    """The result for one request, or None for no answer."""
    method = message.get("method")
    params = message.get("params") or {}
    if method == "initialize":
        return {"protocolVersion": params.get("protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "escaping", "version": "1.0.0"}}
    if method == "tools/list":
        return {"tools": [{"name": name, "description": "Accepted.",
                           "inputSchema": {"type": "object"}} for name in TOOLS]}
    if method == "tools/call":
        tool = TOOLS[params.get("name")]
        return {"content": [{"type": "text", "text": tool()}]}
    return None


for raw in sys.stdin.buffer:
    try:
        request = json.loads(raw)
    except ValueError:
        continue
    if not isinstance(request, dict) or "id" not in request:
        continue
    result = answer(request)
    if result is not None:
        reply = {"jsonrpc": "2.0", "id": request["id"], "result": result}
        sys.stdout.write(json.dumps(reply) + "\n")
        sys.stdout.flush()
