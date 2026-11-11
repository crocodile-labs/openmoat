#!/usr/bin/env python3
"""Tells why Antigravity CLI ran, or did not run, OpenMoat's hook in the weekly
latest-agent job (scripts/ci/latest-agents.sh). Not an adapter, never a decision
that counts: the job passes or fails on OpenMoat's own audit log alone.

    agy_probe.py install <hooks.json> <log>   adds the probe entry, before `openmoat init`
    agy_probe.py record <event> <log>         the hook: one line per call, field names only
    agy_probe.py report <log> <captured dir>  what the lines say, as job annotations

The first real run (agy 1.5.5) started neither OpenMoat's `PreToolUse` entry nor the
after-call capture's `PostToolUse` entry, both with the matcher `*`, while the fake
model API saw both tool results. The probe tells the possible causes apart: its
events need no matcher (`SessionStart`, `PreInvocation`) or use the documented
example forms (`"run_command"` for `PreToolUse`, `""` for `PostToolUse`), from
https://antigravity.google/docs/hooks?tab=cli.

- nothing at all: the file is not read, or hooks do not run in this mode (`-p`,
  `--dangerously-skip-permissions`, a `GEMINI_API_KEY` session);
- the events that need no matcher, but no tool event: the file is read and tool hooks
  do not fire in this mode;
- the probe's `PreToolUse` but not OpenMoat's: the file is read and `*` (or something
  else in OpenMoat's entry) is what agy rejects.

A line holds the event and the payload's field names, never a value.
"""

import json
import shlex
import sys
from pathlib import Path

ENTRY_NAME = "moat-ci-probe"
TIMEOUT_SECONDS = 30
# Events and the matcher each probe uses; None: an event with no matcher.
EVENTS = {
    "SessionStart": None,
    "PreInvocation": None,
    "PreToolUse": "run_command",
    "PostToolUse": "",
}
# What each event must print: PreToolUse needs a decision, and `allow` defers
# to the next hook (OpenMoat's), by the documentation.
ANSWERS = {"PreToolUse": {"decision": "allow"}}


def entry(log):
    events = {"enabled": True}
    for event, matcher in EVENTS.items():
        command = " ".join(shlex.quote(part) for part in (
            sys.executable, "-I", str(Path(__file__).resolve()), "record", event, log))
        hook = {"type": "command", "command": command, "timeout": TIMEOUT_SECONDS}
        events[event] = [hook] if matcher is None else [{"matcher": matcher, "hooks": [hook]}]
    return events


def cmd_install(hooks, log):
    path = Path(hooks)
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    doc[ENTRY_NAME] = entry(log)
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"ok    agy probe: {', '.join(EVENTS)} recorded through {path}")


def cmd_record(event, log):
    raw = sys.stdin.read()
    try:
        doc = json.loads(raw)
        fields = sorted(doc) if isinstance(doc, dict) else [f"<{type(doc).__name__}>"]
        tool = ((doc.get("toolCall") or {}).get("name") if isinstance(doc, dict) else None) or "-"
    except ValueError:
        fields, tool = ["<not json>"], "-"
    # The tool's name is the agent's own word for it, not the call's arguments.
    with open(log, "a", encoding="utf-8") as out:
        out.write(f"{event} tool={tool} fields={','.join(fields)}\n")
    print(json.dumps(ANSWERS.get(event, {})))


def seen(log):
    try:
        lines = Path(log).read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    return [line.split(" ", 1)[0] for line in lines if line]


def verdict(events, openmoat_ran):
    """What the probe's lines and OpenMoat's own captures say together."""
    if openmoat_ran:
        return "OpenMoat's PreToolUse entry ran"
    if not events:
        return ("no hook ran at all, not even SessionStart: agy did not read "
                "~/.gemini/config/hooks.json in this run, or runs no hooks in this mode "
                "(-p, --dangerously-skip-permissions, a GEMINI_API_KEY session); see "
                "agy-cli.log, agy-hooks.txt and agy-files.txt")
    if "PreToolUse" in events:
        return ("the probe's PreToolUse (matcher \"run_command\") ran and OpenMoat's "
                "(matcher \"*\") did not: agy reads the file and rejects something in "
                "OpenMoat's entry, the matcher first")
    if "PostToolUse" in events:
        return ("PostToolUse ran but no PreToolUse, not even the probe's: agy does not "
                "send PreToolUse in this mode")
    return (f"only {', '.join(sorted(set(events)))} ran: agy reads the file and "
            "fires no tool event in this mode")


def cmd_report(log, captured):
    events = seen(log)
    openmoat_ran = any(Path(captured).glob("antigravity-cli-*.json"))
    message = f"probe events: {', '.join(events) or 'none'}. {verdict(events, openmoat_ran)}"
    print(f"::notice title=agy hook probe::{message}", flush=True)
    print(f"--    agy hook probe: {message}")


COMMANDS = {"install": (cmd_install, 2), "record": (cmd_record, 2), "report": (cmd_report, 2)}


def main(argv):
    if not argv or argv[0] not in COMMANDS or len(argv) - 1 != COMMANDS[argv[0]][1]:
        print(__doc__, file=sys.stderr)
        return 64
    try:
        COMMANDS[argv[0]][0](*argv[1:])
    except Exception as error:  # A probe never fails the job or the agent's call.
        if argv[0] == "record":
            print("{}")
        else:
            print(f"::notice title=agy hook probe::{argv[0]} failed: {type(error).__name__}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
