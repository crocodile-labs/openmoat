#!/usr/bin/env python3
# Print `claude -p --output-format stream-json --verbose` as a person would read
# it: Claude's words, each tool call it makes, and what came back (a call
# OpenMoat denied shows its reason). Used by record-real-flow.sh. With
# DEMO_SESSIONS set, each event's session id is appended to that file.
import json
import os
import sys

BOLD, DIM, RED, GREEN, CYAN, END = "\033[1m", "\033[2m", "\033[31m", "\033[32m", "\033[36m", "\033[0m"


def short(text, lines=6):
    rows = text.strip().splitlines()
    out = "\n".join("    " + r for r in rows[:lines])
    if len(rows) > lines:
        out += f"\n    {DIM}… {len(rows) - lines} more lines{END}"
    return out


def call_text(name, args):
    if name == "Bash":
        return args.get("command", "")
    for key in ("file_path", "path", "url", "pattern"):
        if key in args:
            return args[key]
    return json.dumps(args)[:120]


def result_text(content):
    if isinstance(content, list):
        return "\n".join(c.get("text", "") for c in content if isinstance(c, dict))
    return str(content)


for line in sys.stdin:
    try:
        event = json.loads(line)
    except ValueError:
        continue
    if os.environ.get("DEMO_SESSIONS") and event.get("session_id"):
        with open(os.environ["DEMO_SESSIONS"], "a") as f:
            f.write(event["session_id"] + "\n")
    kind = event.get("type")
    blocks = (event.get("message") or {}).get("content") or []
    if kind == "assistant":
        for b in blocks:
            if b.get("type") == "text" and b.get("text", "").strip():
                print(f"{b['text'].strip()}\n", flush=True)
            elif b.get("type") == "tool_use":
                print(f"  {CYAN}▸ {b.get('name')}{END} {call_text(b.get('name'), b.get('input') or {})}", flush=True)
    elif kind == "user":
        for b in blocks:
            if b.get("type") != "tool_result":
                continue
            text = result_text(b.get("content"))
            if b.get("is_error"):
                print(f"  {RED}{BOLD}✗ blocked{END}\n{RED}{short(text)}{END}\n", flush=True)
            else:
                print(f"  {GREEN}✓ ran{END}\n{DIM}{short(text, 4)}{END}\n", flush=True)
