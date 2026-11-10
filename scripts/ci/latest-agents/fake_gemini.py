#!/usr/bin/env python3
"""A local stand-in for the Gemini API, so Antigravity CLI runs one headless turn
with no account and no traffic leaving the machine (scripts/ci/latest-agents.sh).
It speaks `POST .../models/<model>:streamGenerateContent` (server-sent events) and
`:generateContent`, the wire format of the `GOOGLE_GEMINI_BASE_URL` Antigravity CLI
documents; this shape is unverified against a real `agy`.

The first request that offers the `--call` tool gets that tool call; once the
conversation holds a function response, the reply is a text that ends the turn.
With `--then`, one function response gets that second call first, and two end the
turn. A request that offers no such tool gets a short text. The conversation
carries the step, so the server keeps no state.

    fake_gemini.py --call run_command='{"CommandLine": "cat ~/.ssh/id_rsa"}'
                   [--then run_command='{"CommandLine": "echo ok"}']

With no --port the OS picks a free loopback port; the bound port is printed as the
first line of standard output once the socket listens. Every request is logged to
standard error, one line each, with its time and the function responses it holds
(`at=<epoch seconds> results=<n>`, read by after_call.py).
"""

import argparse
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CALL = None
THEN = None


def offered(request):
    """The function names a Gemini request declares."""
    names = []
    for tool in request.get("tools") or []:
        for function in (tool or {}).get("functionDeclarations") or []:
            if isinstance(function, dict):
                names.append(function.get("name"))
    return names


def answered(request):
    """How many function responses the conversation holds."""
    return sum(
        1
        for content in request.get("contents") or []
        for part in (content or {}).get("parts") or []
        if isinstance(part, dict) and "functionResponse" in part
    )


def reply(request):
    """The candidate for this turn."""
    results = answered(request)
    print(f"model request at={time.time():.3f} results={results}", file=sys.stderr, flush=True)
    planned = CALL if results == 0 else THEN if results == 1 else None
    if planned is not None and planned[0] in offered(request):
        part = {"functionCall": {"name": planned[0], "args": planned[1]}}
    else:
        part = {"text": "done"}
    return {
        "candidates": [
            {
                "content": {"role": "model", "parts": [part]},
                "finishReason": "STOP",
                "index": 0,
            }
        ],
        "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1, "totalTokenCount": 2},
    }


class Handler(BaseHTTPRequestHandler):
    # The job's readiness probe (`start_fake`) is a GET, which curl -f must see succeed.
    def do_GET(self):
        text = json.dumps({"models": []}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(text)))
        self.end_headers()
        self.wfile.write(text)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        try:
            request = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            request = {}
        print(f"POST {self.path}", file=sys.stderr, flush=True)
        body = reply(request)
        if "streamGenerateContent" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            self.wfile.write(f"data: {json.dumps(body)}\n\n".encode())
        else:
            text = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(text)))
            self.end_headers()
            self.wfile.write(text)

    def log_message(self, *_args):
        pass


def call_spec(text):
    name, _, raw = text.partition("=")
    return (name, json.loads(raw))


def main():
    global CALL, THEN
    parser = argparse.ArgumentParser()
    parser.add_argument("--call", required=True, type=call_spec, help="tool=json-arguments")
    parser.add_argument("--then", type=call_spec, help="tool=json-arguments, after one response")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    CALL = args.call
    THEN = args.then
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(server.server_address[1], flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
