#!/usr/bin/env python3
"""A local stand-in for the Anthropic Messages API, so `claude -p` runs end to
end inside its own sandbox without real credentials and without traffic leaving
the machine. A request that offers the Bash tool first gets a tool_use running
the command passed in --bash; the next reply quotes the tool result and stops.

Used by the differential suite's Claude Code layer (crates/openmoat-cli/tests/e2e/
differential/claude.rs). Trimmed from the
#119 sandbox spike.

  fake_api.py --bash 'cat ~/.ssh/id_rsa'
  fake_api.py --calls '[{"name": "WebFetch", "input": {...}}, {"name": "Write", ...}]'

--calls serves a sequence instead (crates/openmoat-cli/tests/e2e/differential/
agents.rs): the Nth call once the conversation holds N tool results, then a
text reply quoting the last result. A call whose tool the request does not offer
becomes a text reply naming the tools it did offer, so a test sees why. The
conversation itself carries the step, so the server keeps no state.

The weekly latest-agent job (scripts/ci/latest-agents.sh) also uses:

  --hold-at N             at step N, answer nothing until the client goes away, so
                          the caller can interrupt the agent at a known point;
  --resume-prompt TEXT    once a user message holds TEXT, serve --resume-calls,
  --resume-calls JSON     counting only the tool results after that message;
  --tools-log FILE        write the `tools` of the first request that offers any.

Requests held and resumed are noted on standard error, one line each.

With no --port (or --port 0) the OS picks a free loopback port. Either way the
bound port is printed as the first stdout line, once the socket is listening,
so a caller reads it instead of guessing a port and racing for it.
"""
import argparse
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MSG = {"id": "msg_fake", "type": "message", "role": "assistant", "model": "fake",
       "stop_reason": "end_turn", "stop_sequence": None,
       "usage": {"input_tokens": 1, "output_tokens": 1}}
BASH = None
CALLS = None
HOLD_AT = None
HOLD_SECONDS = 170
RESUME_PROMPT = None
RESUME_CALLS = []
TOOLS_LOG = None
TOOLS_LOGGED = threading.Event()


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


def holds_resume_prompt(message):
    content = message.get("content")
    if isinstance(content, str):
        return RESUME_PROMPT in content
    return any(isinstance(b, dict) and RESUME_PROMPT in str(b.get("text", ""))
               for b in content or [])


def resumed_at(msgs):
    """The index of the newest user message holding the resume prompt, or None."""
    if RESUME_PROMPT is None:
        return None
    found = [i for i, m in enumerate(msgs) if m.get("role") == "user" and holds_resume_prompt(m)]
    return found[-1] if found else None


def note(line):
    print(f"fake_api: {line}", file=sys.stderr, flush=True)


def log_tools(tools):
    if TOOLS_LOG and not TOOLS_LOGGED.is_set():
        TOOLS_LOGGED.set()
        with open(TOOLS_LOG, "w", encoding="utf-8") as out:
            json.dump(tools, out, indent=1)


def scripted_reply(req):
    msgs = req.get("messages", [])
    offered = [t.get("name") for t in req.get("tools", [])]
    if not offered:
        # a side request of the agent's own (a title, a summary): no tools
        return {"type": "text", "text": "ok"}
    log_tools(req.get("tools"))
    calls, id_prefix = CALLS, "toolu_fake_"
    at = resumed_at(msgs)
    if at is not None:
        earlier = sum(len(tool_results(m.get("content"))) for m in msgs[:at])
        note(f"resumed with {earlier} earlier tool results")
        calls, id_prefix, msgs = RESUME_CALLS, "toolu_fake_r", msgs[at:]
    results = [r for m in msgs for r in tool_results(m.get("content"))]
    step = len(results)
    if at is None and step == HOLD_AT:
        note(f"holding step {step}")
        threading.Event().wait(HOLD_SECONDS)
    if step < len(calls):
        call = calls[step]
        if call["name"] not in offered:
            return {"type": "text", "text": f"fake api: {call['name']} not offered: {offered}"}
        return {"type": "tool_use", "id": f"{id_prefix}{step}", "name": call["name"],
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
        try:
            if not req.get("stream"):
                stop = "tool_use" if block["type"] == "tool_use" else "end_turn"
                return self.send_json({**MSG, "content": [block], "stop_reason": stop})
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.end_headers()
            for name, data in stream_events(block):
                self.wfile.write(f"event: {name}\ndata: {json.dumps(data)}\n\n".encode())
            self.wfile.flush()
        except OSError:
            # the agent was interrupted while its request was held
            pass


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--bash")
    ap.add_argument("--calls", type=json.loads)
    ap.add_argument("--hold-at", type=int)
    ap.add_argument("--resume-prompt")
    ap.add_argument("--resume-calls", type=json.loads, default=[])
    ap.add_argument("--tools-log")
    a = ap.parse_args()
    BASH = a.bash
    CALLS = a.calls
    HOLD_AT = a.hold_at
    RESUME_PROMPT = a.resume_prompt
    RESUME_CALLS = a.resume_calls
    TOOLS_LOG = a.tools_log
    server = ThreadingHTTPServer(("127.0.0.1", a.port), H)
    print(server.server_address[1], flush=True)
    server.serve_forever()
