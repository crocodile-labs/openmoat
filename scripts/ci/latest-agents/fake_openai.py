#!/usr/bin/env python3
"""A local stand-in for an OpenAI-style model API, so an agent runs one headless
turn with no account and no traffic leaving the machine
(scripts/ci/latest-agents.sh). It speaks the two wire formats the agents use:

- `POST <base>/chat/completions` (Chat Completions; pi, OpenClaw, OpenCode,
  Copilot CLI's BYOK provider), streamed or not, as the request asks;
- `POST <base>/responses` (the Responses API; Codex), always streamed;
- `GET <base>/models`, an empty list.

The first request that offers one of the `--call` tools gets that tool call;
once the conversation holds a tool result, the reply is a text that quotes it
and ends the turn. With `--then`, one tool result gets that second call first,
and two end the turn. A request that offers none of them (a title or summary
the agent asks for on the side) gets a short text. The conversation carries the
step, so the server keeps no state.

    fake_openai.py --call bash='{"command": "cat ~/.ssh/id_rsa"}' [--call <tool>=<json>]...
                   [--then bash='{"command": "echo ok"}']...

`--call` and `--then` may be given several times: the first tool the request
offers wins (Codex names its shell tool `exec_command`, `shell_command` or
`shell` depending on the model). With no --port the OS picks a free loopback
port; the bound port is printed as the first line of standard output once the
socket listens. Every request is logged to standard error, one line each, and
each model request also with its time and the tool results it holds
(`at=<epoch seconds> results=<n>`, read by after_call.py).
"""

import argparse
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CALLS = []
THEN = []


def offered(request):
    """The tool names a Chat Completions or Responses request offers."""
    names = []
    for tool in request.get("tools") or []:
        if not isinstance(tool, dict):
            continue
        function = tool.get("function") if isinstance(tool.get("function"), dict) else tool
        if isinstance(function.get("name"), str):
            names.append(function["name"])
    return names


def chat_results(request):
    """The text of each tool result in a Chat Completions conversation, oldest first."""
    found = []
    for message in request.get("messages") or []:
        if isinstance(message, dict) and message.get("role") == "tool":
            content = message.get("content")
            if isinstance(content, list):
                content = " ".join(p.get("text", "") for p in content if isinstance(p, dict))
            found.append(str(content))
    return found


def responses_results(request):
    """The output of each function call in a Responses conversation, oldest first."""
    found = []
    items = request.get("input")
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict) and item.get("type") == "function_call_output":
            output = item.get("output")
            found.append(output if isinstance(output, str) else json.dumps(output))
    return found


def next_step(names, results):
    """("call", name, arguments) or ("text", text) for one request."""
    print(f"fake_openai: model request at={time.time():.3f} results={len(results)}",
          file=sys.stderr, flush=True)
    plan = CALLS if not results else THEN if len(results) == 1 else []
    for name, arguments in plan:
        if name in names:
            return ("call", name, arguments)
    if results:
        return ("text", f"tool result: {results[-1]}")
    return ("text", f"fake api: none of {[n for n, _ in CALLS]} offered: {names}")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print(f"fake_openai: {self.command} {self.path} " + fmt % args, file=sys.stderr, flush=True)

    def send(self, status, body, content_type="application/json"):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path.endswith("/models"):
            self.send(200, json.dumps({"object": "list", "data": [], "models": []}))
        else:
            self.send(404, json.dumps({"error": {"message": f"no {path}"}}))

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        try:
            request = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            self.send(400, json.dumps({"error": {"message": "not JSON"}}))
            return
        path = self.path.split("?", 1)[0]
        if path.endswith("/chat/completions"):
            self.chat(request)
        elif path.endswith("/responses"):
            self.responses_api(request)
        else:
            self.send(404, json.dumps({"error": {"message": f"no {path}"}}))

    def chat(self, request):
        results = chat_results(request)
        step = next_step(offered(request), results)
        model = request.get("model") or "fake-model"
        if step[0] == "call":
            call = {"index": 0, "id": f"call_fake_{len(results) + 1}", "type": "function",
                    "function": {"name": step[1], "arguments": json.dumps(step[2])}}
            delta, finish = {"role": "assistant", "content": None, "tool_calls": [call]}, "tool_calls"
        else:
            delta, finish = {"role": "assistant", "content": step[1]}, "stop"
        usage = {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
        if not request.get("stream"):
            message = dict(delta)
            if "tool_calls" in message:
                message["tool_calls"] = [{k: v for k, v in c.items() if k != "index"}
                                         for c in message["tool_calls"]]
            self.send(200, json.dumps({
                "id": "chatcmpl-fake", "object": "chat.completion", "created": 0, "model": model,
                "choices": [{"index": 0, "message": message, "finish_reason": finish}],
                "usage": usage}))
            return
        base = {"id": "chatcmpl-fake", "object": "chat.completion.chunk", "created": 0, "model": model}
        chunks = [
            dict(base, choices=[{"index": 0, "delta": delta, "finish_reason": None}]),
            dict(base, choices=[{"index": 0, "delta": {}, "finish_reason": finish}]),
            dict(base, choices=[], usage=usage),
        ]
        body = "".join(f"data: {json.dumps(c)}\n\n" for c in chunks) + "data: [DONE]\n\n"
        self.send(200, body, "text/event-stream")

    # Not `responses`: that name is `BaseHTTPRequestHandler`'s status-code table,
    # which `send_response` reads for every reply.
    def responses_api(self, request):
        results = responses_results(request)
        step = next_step(offered(request), results)
        if step[0] == "call":
            number = len(results) + 1
            item = {"type": "function_call", "id": f"fc_fake_{number}",
                    "call_id": f"call_fake_{number}", "name": step[1],
                    "arguments": json.dumps(step[2])}
        else:
            item = {"type": "message", "id": "msg_fake_1", "role": "assistant",
                    "content": [{"type": "output_text", "text": step[1], "annotations": []}]}
        usage = {"input_tokens": 1, "input_tokens_details": None, "output_tokens": 1,
                 "output_tokens_details": None, "total_tokens": 2}
        events = [
            ("response.created", {"type": "response.created", "response": {"id": "resp_fake"}}),
            ("response.output_item.done", {"type": "response.output_item.done", "output_index": 0,
                                           "item": item}),
            ("response.completed", {"type": "response.completed",
                                    "response": {"id": "resp_fake", "usage": usage}}),
        ]
        body = "".join(f"event: {name}\ndata: {json.dumps(data)}\n\n" for name, data in events)
        self.send(200, body, "text/event-stream")


def call_spec(text):
    name, sep, arguments = text.partition("=")
    if not sep or not name:
        raise argparse.ArgumentTypeError("--call takes <tool>=<json arguments>")
    return name, json.loads(arguments)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--call", type=call_spec, action="append", required=True)
    parser.add_argument("--then", type=call_spec, action="append", default=[])
    args = parser.parse_args()
    CALLS.extend(args.call)
    THEN.extend(args.then)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(server.server_address[1], flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
