#!/usr/bin/env python3
"""A local stand-in for the Anthropic Messages API, so `claude -p` runs end to
end inside its own sandbox without real credentials and without traffic leaving
the machine. A request that offers the Bash tool first gets a tool_use running
the command passed in --bash; the next reply quotes the tool result and stops.

Used by the differential suite's Claude Code layer (crates/openmoat-cli/tests/e2e/
differential/claude.rs) and scripts/ci/differential.sh. Trimmed from the
#119 sandbox spike.

  fake_api.py --bash 'cat ~/.ssh/id_rsa'
  fake_api.py --calls '[{"name": "WebFetch", "input": {...}}, {"name": "Write", ...}]'

--calls serves a sequence instead (crates/openmoat-cli/tests/e2e/differential/
agents.rs): the Nth call once the conversation holds N tool results, then a
text reply quoting the last result. A call whose tool the request does not offer
becomes a text reply naming the tools it did offer, so a test sees why. The
conversation itself carries the step, so the server keeps no state.

With no --port (or --port 0) the OS picks a free loopback port. Either way the
bound port is printed as the first stdout line, once the socket is listening,
so a caller reads it instead of guessing a port and racing for it.
"""
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MSG = {"id": "msg_fake", "type": "message", "role": "assistant", "model": "fake",
       "stop_reason": "end_turn", "stop_sequence": None,
       "usage": {"input_tokens": 1, "output_tokens": 1}}
BASH = None
CALLS = None


def tool_results(content):
    if not isinstance(content, list):
        return []
    return [b for b in content if isinstance(b, dict) and b.get("type") == "tool_result"]


def result_text(result):
    out = result.get("content")
    if not isinstance(out, str):
        out = " ".join(c.get("text", "") for c in out or [])
    return out


def reply_content(req):
    if CALLS is not None:
        return scripted_reply(req)
    msgs = req.get("messages", [])
    last = msgs[-1]["content"] if msgs else ""
    results = tool_results(last)
    if BASH and results:
        return {"type": "text", "text": f"tool result: {result_text(results[0])}"}
    if BASH and any(t.get("name") == "Bash" for t in req.get("tools", [])):
        return {"type": "tool_use", "id": "toolu_fake", "name": "Bash",
                "input": {"command": BASH, "description": "differential probe"}}
    return {"type": "text", "text": "ok"}


def scripted_reply(req):
    msgs = req.get("messages", [])
    results = [r for m in msgs for r in tool_results(m.get("content"))]
    offered = [t.get("name") for t in req.get("tools", [])]
    if not offered:
        # a side request of the agent's own (a title, a summary): no tools
        return {"type": "text", "text": "ok"}
    step = len(results)
    if step < len(CALLS):
        call = CALLS[step]
        if call["name"] not in offered:
            return {"type": "text", "text": f"fake api: {call['name']} not offered: {offered}"}
        return {"type": "tool_use", "id": f"toolu_fake_{step}", "name": call["name"],
                "input": call["input"]}
    last = result_text(results[-1]) if results else ""
    return {"type": "text", "text": f"tool result: {last}"}


def stream_events(block):
    if block["type"] == "text":
        start, delta = {"type": "text", "text": ""}, {"type": "text_delta", "text": block["text"]}
    else:
        start = {**block, "input": {}}
        delta = {"type": "input_json_delta", "partial_json": json.dumps(block["input"])}
    stop = "tool_use" if block["type"] == "tool_use" else "end_turn"
    return [
        ("message_start", {"type": "message_start", "message": {**MSG, "content": [], "stop_reason": None}}),
        ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": start}),
        ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": delta}),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ("message_delta", {"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": None},
                           "usage": {"output_tokens": 1}}),
        ("message_stop", {"type": "message_stop"}),
    ]


class H(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def send_json(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.send_json({"data": [], "has_more": False})

    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}")
        if "count_tokens" in self.path:
            return self.send_json({"input_tokens": 1})
        if not self.path.startswith("/v1/messages"):
            return self.send_json({})
        block = reply_content(req)
        if not req.get("stream"):
            stop = "tool_use" if block["type"] == "tool_use" else "end_turn"
            return self.send_json({**MSG, "content": [block], "stop_reason": stop})
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.end_headers()
        for name, data in stream_events(block):
            self.wfile.write(f"event: {name}\ndata: {json.dumps(data)}\n\n".encode())
        self.wfile.flush()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--bash")
    ap.add_argument("--calls", type=json.loads)
    a = ap.parse_args()
    BASH = a.bash
    CALLS = a.calls
    server = ThreadingHTTPServer(("127.0.0.1", a.port), H)
    print(server.server_address[1], flush=True)
    server.serve_forever()
