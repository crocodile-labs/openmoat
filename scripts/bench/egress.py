"""agent-egress-bench cases as the tool calls a coding agent sends OpenMoat.

agent-egress-bench (pipelab-org/agent-egress-bench, `cases/`) describes wire
inputs to an egress control (a proxy, an MCP wrapper) with an expected verdict:
`block` for an attack, `allow` (or `warn`, which the corpus scores as `allow`)
for a benign control. OpenMoat's decision engine judges the call an agent asks
to make, so each case is turned into the call that would carry it:

- `url`, `header`, `request_body`: the `curl` command an agent's shell tool
  would run with the method, headers, body and URL the case gives (form `curl`);
  a plain `GET` with no headers is also the URL handed to the agent's own fetch
  tool (form `fetch`, `WebFetch`, which cannot carry a body or headers).
- `mcp_tool_call`, `mcp_tool_sequence`: every `tools/call` in the case, two ways.
  Form `native`: as the agent's own tool where one does the same job (a read or
  write of the path, a fetch of the URL, a shell command). Form `mcp`: as the MCP
  tool `mcp__bench__<tool>`; `policy check --kind mcp` takes the tool name only,
  so the paths and URLs a host adapter would find in the arguments are not part
  of that form. A sequence is decided call by call, without a session: what
  OpenMoat keeps across calls (taint, cross-server flow) is not measured.

Every other input is content an agent receives (a response, a tool list, an
agent card, a WebSocket frame) or a temporal pair; the decision engine has no
input for it, and the case is reported as skipped with that reason.
The cases are read as JSON only; nothing in them is executed.
"""

import json
import re
import shlex
from pathlib import Path

SKIPPED = {
    "response_content": "content the agent receives (a fetched page or proxied "
    "response); the decision engine judges calls, not what they return",
    "mcp_tool_definition": "an MCP server's tool list; OpenMoat pins MCP servers "
    "(`openmoat mcp proxy`, the policy lock) rather than scanning descriptions",
    "mcp_tool_result": "what an MCP tool returned; read by the session features "
    "(ADR-057, ADR-058), which `policy check` does not run",
    "mcp_initialize_response": "an MCP server's initialize reply; no input for it",
    "a2a_agent_card": "an A2A agent card; OpenMoat has no A2A input",
    "a2a_message": "an A2A message; OpenMoat has no A2A input",
    "websocket_frame": "WebSocket frame contents; the engine sees only the URL a "
    "tool connects to, not the frames sent over it",
    "mcp_tool_sequence_temporal": "a before/after tool list (rug pull); covered by "
    "MCP pinning in the hook and gateway, which `policy check` does not run",
}
NATIVE = {
    "read_file": "fs-read",
    "list_dir": "fs-read",
    "list_directory": "fs-read",
    "write_file": "fs-write",
    "fetch": "fetch",
    "fetch_url": "fetch",
    "exec": "shell",
    "run_command": "shell",
}
TOOL_NAME = re.compile(r"[^A-Za-z0-9_-]")


def cases(dataset):
    """Yield one case per corpus file (and per multi-file drift case)."""
    root = Path(dataset) / "cases"
    if not root.is_dir():
        raise SystemExit(f"{root} is not an agent-egress-bench folder")
    for path in sorted(root.glob("*/*.json")):
        yield _case(json.loads(path.read_text(encoding="utf-8")))
    for meta in sorted(root.glob("*/*/case.yaml")):
        yield _drift(meta)


def _case(data):
    payload = data.get("payload", {})
    kind = data["input_type"]
    case = {
        "id": data["id"],
        "category": data["category"],
        "summary": data.get("title", ""),
        "attack": data["expected_verdict"] == "block",
        "input_type": kind,
        "forms": {},
    }
    if kind in ("url", "header", "request_body"):
        case["forms"] = _http_forms(payload)
    elif kind in ("mcp_tool_call", "mcp_tool_sequence"):
        case["forms"] = _mcp_forms(payload)
    if not case["forms"]:
        case["skipped"] = SKIPPED.get(kind, f"no OpenMoat input for `{kind}`")
    return case


def _drift(meta):
    # case.yaml is read for its two scored fields only, line by line: the
    # harness takes no YAML dependency and needs nothing else from it.
    fields = {}
    for line in meta.read_text(encoding="utf-8").splitlines():
        key, sep, value = line.partition(":")
        if sep and key in ("id", "category", "expected_verdict", "title"):
            fields[key] = value.strip().strip("'\"")
    return {
        "id": fields.get("id", meta.parent.name),
        "category": fields.get("category", "mcp_drift"),
        "summary": fields.get("title", ""),
        "attack": fields.get("expected_verdict") == "block",
        "input_type": "mcp_tool_sequence_temporal",
        "forms": {},
        "skipped": SKIPPED["mcp_tool_sequence_temporal"],
    }


def _http_forms(payload):
    url = payload.get("url", "")
    method = str(payload.get("method", "GET")).upper()
    headers = payload.get("headers") or {}
    body = payload.get("body")
    if payload.get("content_type") and body is not None:
        headers = {"Content-Type": payload["content_type"], **headers}
    words = ["curl", "-sS"]
    if method != "GET" or body is not None:
        words += ["-X", method]
    for name, value in headers.items():
        words += ["-H", f"{name}: {value}"]
    if body is not None:
        words += ["--data-binary", str(body)]
    words.append(url)
    forms = {"curl": [("shell", shlex.join(words))]}
    if method == "GET" and not headers and body is None:
        forms["fetch"] = [("fetch", url)]
    return forms


def _mcp_forms(payload):
    calls = [
        m.get("params", {})
        for m in payload.get("jsonrpc_messages", [])
        if m.get("method") == "tools/call"
    ]
    if not calls:
        return {}
    native, mcp = [], []
    for call in calls:
        name = str(call.get("name", ""))
        mcp.append(("mcp", "mcp__bench__" + TOOL_NAME.sub("_", name)))
        native.append(_native(name, call.get("arguments") or {}) or mcp[-1])
    return {"native": native, "mcp": mcp}


def _native(name, args):
    kind = NATIVE.get(name)
    if kind in ("fs-read", "fs-write") and isinstance(args.get("path"), str):
        return (kind, args["path"])
    if kind == "fetch" and isinstance(args.get("url"), str):
        return (kind, args["url"])
    if kind == "shell" and isinstance(args.get("command"), str):
        extra = [str(a) for a in args.get("args") or []]
        return (kind, " ".join([args["command"], *map(shlex.quote, extra)]))
    return None
