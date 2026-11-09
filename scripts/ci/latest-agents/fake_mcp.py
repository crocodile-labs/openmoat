#!/usr/bin/env python3
"""A local MCP server over stdio for the weekly latest-agent job
(scripts/ci/latest-agents.sh): one tool, `slow_job`, and a log of every request
it receives, so `check.py background-mcp` can tell whether a call reached the
server and whether it came as a background task.

    fake_mcp.py --log <file>

A task follows Claude Code's MCP documentation ("MCP tasks"): a `tools/call`
that carries the extension in `params._meta["io.modelcontextprotocol/
clientCapabilities"].extensions` is answered with a task, and `tasks/get`
completes it. The documentation does not say how a server advertises task
support; `initialize` names the same extension, which a client that reads
something else ignores. Log lines are JSON; nothing here reaches the network.
"""

import argparse
import json
import sys

TOOL = "slow_job"
TASKS = "io.modelcontextprotocol/tasks"
CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
TASK_ID = "moat-ci-task-1"


def asks_for_a_task(params):
    """Whether a request carries the tasks extension of the client's capabilities."""
    meta = params.get("_meta")
    client = meta.get(CAPABILITIES) if isinstance(meta, dict) else None
    extensions = client.get("extensions") if isinstance(client, dict) else None
    return isinstance(extensions, dict) and TASKS in extensions


def task(status, extra=None):
    now = "2026-01-01T00:00:00Z"
    return {"taskId": TASK_ID, "status": status, "createdAt": now, "lastUpdatedAt": now,
            "ttlMs": None, "pollIntervalMs": 500, **(extra or {})}


def answer(method, params):
    """The JSON-RPC result of one request, or None for a method not served."""
    if method == "initialize":
        return {"protocolVersion": params.get("protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {}, "extensions": {TASKS: {}}},
                "serverInfo": {"name": "moatprobe", "version": "0"}}
    if method == "tools/list":
        return {"tools": [{"name": TOOL, "description": "A long job.",
                           "inputSchema": {"type": "object", "properties": {}}}]}
    if method == "tools/call":
        if asks_for_a_task(params):
            return task("working", {"resultType": "task"})
        return {"content": [{"type": "text", "text": "job finished"}]}
    if method == "tasks/get":
        return task("completed", {"resultType": "complete", "result": {
            "content": [{"type": "text", "text": "job finished"}]}})
    if method == "ping":
        return {}
    return None


def serve(log):
    for line in sys.stdin:
        try:
            message = json.loads(line)
        except ValueError:
            continue
        if not isinstance(message, dict):
            continue
        method = message.get("method")
        params = message.get("params") if isinstance(message.get("params"), dict) else {}
        print(json.dumps({"method": method, "name": params.get("name"),
                          "task": asks_for_a_task(params)}), file=log, flush=True)
        if message.get("id") is None or method is None:
            continue
        result = answer(method, params)
        reply = {"jsonrpc": "2.0", "id": message["id"]}
        if result is None:
            reply["error"] = {"code": -32601, "message": f"no method {method}"}
        else:
            reply["result"] = result
        print(json.dumps(reply), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--log", required=True)
    args = parser.parse_args()
    with open(args.log, "a", encoding="utf-8") as log:
        serve(log)


if __name__ == "__main__":
    main()
