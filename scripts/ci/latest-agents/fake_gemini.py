#!/usr/bin/env python3
"""A local stand-in for the Gemini API, so Antigravity CLI runs one headless turn
with no account and no traffic leaving the machine (scripts/ci/latest-agents.sh).
It speaks `POST .../models/<model>:streamGenerateContent` (server-sent events) and
`:generateContent`, the wire format of the `GOOGLE_GEMINI_BASE_URL` Antigravity CLI
documents; this shape is unverified against a real `agy`.

The first request that offers the `--call` tool gets that tool call; once the
conversation holds a function response, the reply is a text that ends the turn.
A request that offers no such tool gets a short text. The conversation carries the
step, so the server keeps no state.

    fake_gemini.py --call run_command='{"CommandLine": "cat ~/.ssh/id_rsa"}'

With no --port the OS picks a free loopback port; the bound port is printed as the
first line of standard output once the socket listens. Every request is logged to
standard error, one line each.
"""

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CALL = None


def offered(request):
    """The function names a Gemini request declares."""
    names = []
    for tool in request.get("tools") or []:
        for function in (tool or {}).get("functionDeclarations") or []:
            if isinstance(function, dict):
                names.append(function.get("name"))
    return names


def answered(request):
    """Whether the conversation already holds a function response."""
    for content in request.get("contents") or []:
        for part in (content or {}).get("parts") or []:
            if isinstance(part, dict) and "functionResponse" in part:
                return True
    return False


def reply(request):
    """The candidate for this turn."""
    name, args = CALL
    if name in offered(request) and not answered(request):
        part = {"functionCall": {"name": name, "args": args}}
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


def main():
    global CALL
    parser = argparse.ArgumentParser()
    parser.add_argument("--call", required=True, help="tool=json-arguments")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    name, _, raw = args.call.partition("=")
    CALL = (name, json.loads(raw))
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(server.server_address[1], flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
