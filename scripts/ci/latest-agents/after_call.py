#!/usr/bin/env python3
"""Records what an agent's after-call event sends, in the weekly latest-agent job
(scripts/ci/latest-agents.sh; why: "After-call payloads" in the README beside this
file). Nothing here is an adapter or a policy, and nothing here can fail the job.

    after_call.py install <agent> <dir> <root> <home> <project>
                                  adds the recording hook to the agent's hook file,
                                  before `openmoat init` pins it
    after_call.py record <agent> <event> <dir> <root> <home> <project>
                                  the hook: stores one payload in <dir>, then sleeps
                                  so that the report can see whether the agent waited
    after_call.py report <agent> <dir> <fake api log, or -> <last step of the job>
                                  one `::notice` per event: the field names and the
                                  type of each value, or NOT CAPTURED and why

A stored payload has the throwaway paths made the fixtures' made-up ones, and every
value under a key naming a token, key or authorisation replaced. A notice holds field
names and types, never a value: the job's logs cannot be read where it is reviewed,
its annotations can.
"""

import json
import os
import re
import shlex
import sys
import time
from pathlib import Path

ENTRY_NAME = "moat-ci-capture"
WAIT_SECONDS = 1.5
TIMEOUT_SECONDS = 30
MAX_NOTICE = 3000

SENSITIVE = re.compile(r"token|key|auth|secret|passw|credential|cookie", re.IGNORECASE)
REDACTED = re.compile(r"\[redacted (\w+)\]")
# A map keyed by data (a path, say) must not print that data as a "field name".
FIELD = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,63}")
REQUEST = re.compile(r"\bat=([0-9.]+) results=([0-9]+)")


def nested(doc, event, command):
    """Codex: `hooks.<event>[].hooks[]`, every tool (no matcher)."""
    entry = {"hooks": [{"type": "command", "command": command, "timeout": TIMEOUT_SECONDS}]}
    doc.setdefault("hooks", {}).setdefault(event, []).append(entry)


def gemini(doc, event, command):
    """Gemini CLI's settings.json: a named hook, its timeout in milliseconds."""
    hook = {"name": ENTRY_NAME, "type": "command", "command": command,
            "timeout": TIMEOUT_SECONDS * 1000}
    doc.setdefault("hooks", {}).setdefault(event, []).append({"matcher": "*", "hooks": [hook]})


def copilot(doc, event, command):
    """GitHub Copilot CLI: a file of its own in `hooks/`, one command per shell."""
    doc["version"] = 1
    entry = {"type": "command", "bash": command, "timeoutSec": TIMEOUT_SECONDS}
    doc.setdefault("hooks", {}).setdefault(event, []).append(entry)


def named(doc, event, command):
    """Antigravity CLI: one named top-level entry beside OpenMoat's."""
    hook = {"type": "command", "command": command, "timeout": TIMEOUT_SECONDS}
    doc[ENTRY_NAME] = {"enabled": True, event: [{"matcher": "*", "hooks": [hook]}]}


# The agents the job runs with no account whose after-call event has no real
# payload yet (ADR-063). `file` is expanded from the environment.
AGENTS = {
    "codex": {"event": "PostToolUse", "file": "{CODEX_HOME}/hooks.json", "layout": nested},
    "gemini-cli": {"event": "AfterTool", "file": "{GEMINI_CLI_HOME}/.gemini/settings.json",
                   "layout": gemini},
    "copilot-cli": {"event": "postToolUse", "file": "{COPILOT_HOME}/hooks/moat-ci-capture.json",
                    "layout": copilot},
    "antigravity-cli": {"event": "PostToolUse", "file": "{HOME}/.gemini/config/hooks.json",
                        "layout": named},
}


def type_of(value):
    if isinstance(value, bool):
        return "boolean"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    return "array" if isinstance(value, list) else "object"


def embedded(text):
    """The object or array a string holds as JSON (Copilot's `toolArgs`), or None."""
    if not text.lstrip().startswith(("{", "[")):
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


def clean(value, places):
    """`value` with secrets' values replaced and the throwaway paths made up."""
    if isinstance(value, dict):
        return {key: f"[redacted {type_of(item)}]" if SENSITIVE.search(key) else clean(item, places)
                for key, item in value.items()}
    if isinstance(value, list):
        return [clean(item, places) for item in value]
    if isinstance(value, str):
        inner = embedded(value)
        if inner is not None:
            return json.dumps(clean(inner, places))
        for real, fake in places:
            value = value.replace(real, fake)
    return value


def walk(value, path, found):
    """Every field's dotted path in `found`, with the types seen there."""
    if isinstance(value, dict) and value:
        for key, item in value.items():
            name = key if FIELD.fullmatch(key) else "<key>"
            walk(item, f"{path}.{name}" if path else name, found)
    elif isinstance(value, list) and value:
        for item in value:
            walk(item, f"{path}[]", found)
    elif isinstance(value, str) and REDACTED.fullmatch(value):
        found.setdefault(path, set()).add(f"redacted {REDACTED.fullmatch(value).group(1)}")
    elif isinstance(value, str) and embedded(value) is not None:
        found.setdefault(path, set()).add("string holding JSON")
        walk(embedded(value), f"{path}(json)", found)
    else:
        kind = type_of(value)
        empty = isinstance(value, (dict, list))
        found.setdefault(path or "(payload)", set()).add(f"empty {kind}" if empty else kind)


def fields(payloads):
    found = {}
    for payload in payloads:
        walk(payload, "", found)
    parts = [f"{path}={'|'.join(sorted(kinds))}" for path, kinds in sorted(found.items())]
    shown, used = [], 0
    for part in parts:
        if used + len(part) > MAX_NOTICE:
            shown.append(f"(and {len(parts) - len(shown)} more, in the artefact)")
            break
        shown.append(part)
        used += len(part) + 2
    return "; ".join(shown)


def requests_of(log):
    """(time, tool results in the conversation) of each model request, or None."""
    try:
        text = Path(log).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    return [(float(at), int(results)) for at, results in REQUEST.findall(text)]


def waited(timings, requests):
    """Whether the agent held its next model request until the hook had finished."""
    if requests is None:
        return "not observable: the model is the agent's own test double in this job"
    verdicts = set()
    for timing in timings:
        after = [at for at, results in requests if results >= 1 and at >= timing["started"]]
        if after:
            verdicts.add("yes" if min(after) >= timing["finished"] else "no")
    if not verdicts:
        return "not observable: no model request followed the hook"
    if len(verdicts) > 1:
        return "mixed: it waited for some calls and not for others"
    if verdicts == {"yes"}:
        return f"yes, its next model request came after the hook's {WAIT_SECONDS} s"
    return f"no, its next model request came during the hook's {WAIT_SECONDS} s"


def not_captured(agent, spec, requests, step):
    """Why no payload arrived, as far as the job can tell."""
    reasons = []
    if step != "done":
        reasons.append(f"the job stopped in step `{step}`")
    try:
        entry = "after_call.py" in Path(spec["file"].format(**os.environ)).read_text(encoding="utf-8")
    except (OSError, KeyError):
        entry = False
    if not entry:
        reasons.append("the recording hook is not in the agent's hook file")
    elif requests is None:
        reasons.append("the hook never started; whether the harmless call ran is unknown, "
                       "the model is the agent's own test double")
    else:
        seen = max((results for _, results in requests), default=0)
        if seen < 2:
            reasons.append(f"the harmless call did not come back: the fake API saw {seen} tool "
                           "result(s), the denied call and the harmless one would be 2")
        else:
            reasons.append("the harmless call ran and the hook never started: the agent does not "
                           "send this event for it, or did not load the entry")
    return f"NOT CAPTURED ({agent}): {'; '.join(reasons)}"


def escape(text, title=False):
    text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return text.replace(":", "%3A").replace(",", "%2C") if title else text


def notice(title, message):
    print(f"::notice title={escape(title, title=True)}::{escape(message)}", flush=True)


def cmd_install(agent, directory, root, home, project):
    spec = AGENTS.get(agent)
    if spec is None:
        return
    # The agent may clear the hook's environment: everything is in the command.
    command = " ".join(shlex.quote(part) for part in (
        sys.executable, "-I", str(Path(__file__).resolve()), "record", agent, spec["event"],
        directory, root, home, project))
    Path(directory).mkdir(parents=True, exist_ok=True)
    path = Path(spec["file"].format(**os.environ))
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    spec["layout"](doc, spec["event"], command)
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"ok    after-call capture: {spec['event']} recorded through {path}")


def cmd_record(agent, event, directory, root, home, project):
    started = time.time()
    raw = sys.stdin.buffer.read().decode("utf-8", "replace")
    places = sorted([(project, "/p"), (home, "/Users/me"), (root, "/tmp/scratch")],
                    key=lambda place: -len(place[0]))
    try:
        doc = clean(json.loads(raw), places)
    except ValueError:
        # Nothing of a payload that cannot be redacted is kept.
        doc = {"_not_json": True, "_bytes": len(raw)}
    stem = Path(directory) / f"{agent}-{event}-{os.getpid()}"
    with open(f"{stem}.json", "x", encoding="utf-8") as out:
        json.dump(doc, out, indent=2)
    time.sleep(WAIT_SECONDS)
    with open(f"{stem}.timing", "x", encoding="utf-8") as out:
        json.dump({"started": started, "finished": time.time()}, out)


def cmd_report(agent, directory, fake_log, step):
    spec = AGENTS.get(agent)
    if spec is None:
        return
    title = f"after-call {agent} {spec['event']}"
    requests = requests_of(fake_log) if fake_log != "-" else None
    files = sorted(Path(directory).glob(f"{agent}-{spec['event']}-*.json"))
    if not files:
        notice(title, not_captured(agent, spec, requests, step))
        return
    payloads = [json.loads(path.read_text(encoding="utf-8")) for path in files]
    timings = [json.loads(path.with_suffix(".timing").read_text(encoding="utf-8"))
               for path in files if path.with_suffix(".timing").exists()]
    notice(title, f"{len(payloads)} payload(s). Agent waited for the hook: "
                  f"{waited(timings, requests)}. Fields: {fields(payloads)}")


COMMANDS = {"install": (cmd_install, 5), "record": (cmd_record, 6), "report": (cmd_report, 4)}


def main(argv):
    if not argv or argv[0] not in COMMANDS or len(argv) - 1 != COMMANDS[argv[0]][1]:
        print(__doc__, file=sys.stderr)
        return 64
    try:
        COMMANDS[argv[0]][0](*argv[1:])
    except Exception as error:  # A capture never fails the job or the agent's call.
        if argv[0] != "record":
            notice(f"after-call {argv[1]}",
                   f"NOT CAPTURED: {argv[0]} failed with {type(error).__name__}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
