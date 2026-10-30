#!/usr/bin/env python3
"""The checks of the weekly latest-agent job (scripts/ci/latest-agents.sh) that
read JSON, and the agent records they come from (agents.json beside this file).

    check.py records                         every record is consistent (quality gate)
    check.py matrix                          the workflow's job matrix, as JSON
    check.py get <agent> <key>               one field of a record (`checked.version`)
    check.py version <agent> <installed>     the installed version against the checked one
    check.py configs <agent>                 "<path>\\t<format>" of each config file, env expanded
    check.py json <file>                     the file parses as JSON
    check.py payload <agent> allow|deny <home> <project>
                                             the host's golden shell payload, made one
                                             allowed (`git status`) or denied (`cat ~/.ssh/id_rsa`) call
    check.py reply <agent> allow|deny <exit code> <reply file>
                                             `openmoat guard`'s reply is that verdict in the host's format
    check.py protected <agent> <status.json> <doctor.json>
                                             `status` and `doctor` say the agent is protected by its hook
    check.py denied <host> <before.json> <after.json> [<marker file>...]
                                             a new audit row: <host> denied a read under ~/.ssh by
                                             secrets-paths; no marker file's text is in the logs given
    check.py openclaw-valid <config> <report.json>
    check.py openclaw-inspect <report.json>  OpenClaw's own validator and plugin inspector agree
    check.py opencode-settled <report.json>  OpenCode 2's plugin inventory is applied (exit 0/1, silent)
    check.py opencode-active <report.json>   OpenCode 2 reports OpenMoat's plugin active

Every failure prints why and exits 1; usage errors exit 64.
"""

import json
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
HOSTS = ROOT / "crates" / "openmoat-hosts" / "src" / "host"
ALLOWED = "git status"
DENIED = "cat ~/.ssh/id_rsa"
VERSION = re.compile(r"\d+(?:\.\d+)+(?:-[0-9A-Za-z.]+)?")


def fail(message):
    print(f"FAIL  {message}", flush=True)
    sys.exit(1)


def records():
    data = json.loads((HERE / "agents.json").read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if not k.startswith("_")}


def record(agent):
    found = records().get(agent)
    if found is None:
        print(f"check.py: no agent {agent!r} in agents.json", file=sys.stderr)
        sys.exit(64)
    return found


def expand(text):
    """{VARIABLE} from the environment; an unset one is an error, never empty."""
    def one(match):
        value = os.environ.get(match.group(1))
        if not value:
            fail(f"{match.group(1)} is not set, needed for {text}")
        return value
    return re.sub(r"\{([A-Z_]+)\}", one, text)


def pointer(doc, path, value=None, set_value=False):
    """Read (or set) a JSON pointer; a string that holds a JSON object is entered
    as that object (Copilot CLI's `toolArgs`) and written back as a string."""
    parts = [p.replace("~1", "/").replace("~0", "~") for p in path.split("/")[1:]]
    if not parts:
        return doc
    head, rest = parts[0], "/" + "/".join(parts[1:]) if len(parts) > 1 else ""
    if not isinstance(doc, dict) or head not in doc:
        if set_value and isinstance(doc, dict) and not rest:
            doc[head] = value
            return value
        raise KeyError(path)
    child = doc[head]
    if rest and isinstance(child, str):
        inner = json.loads(child)
        got = pointer(inner, rest, value, set_value)
        if set_value:
            doc[head] = json.dumps(inner)
        return got
    if not rest:
        if set_value:
            doc[head] = value
            return value
        return child
    return pointer(child, rest, value, set_value)


def cmd_records():
    problems = []
    for agent, rec in records().items():
        checked = rec.get("checked") or {}
        source = ROOT / checked.get("source", "")
        if not source.is_file():
            problems.append(f"{agent}: checked.source {checked.get('source')!r} is not a file")
        elif checked.get("version"):
            text = source.read_text(encoding="utf-8")
            if not re.search(r"(?<![\w.])v?" + re.escape(checked["version"]) + r"(?![\w])", text):
                problems.append(f"{agent}: {checked['source']} does not name {checked['version']}")
        elif not checked.get("note"):
            problems.append(f"{agent}: no checked.version and no note saying why")
        payload = rec.get("payload")
        if payload:
            fixture = HOSTS / payload["fixture"]
            try:
                doc = json.loads(fixture.read_text(encoding="utf-8"))
                pointer(doc, payload["command"])
            except (OSError, ValueError, KeyError) as error:
                problems.append(f"{agent}: payload {payload['fixture']} {payload['command']}: {error!r}")
        for runner in rec.get("runners", []):
            if runner not in ("ubuntu-latest", "macos-15"):
                problems.append(f"{agent}: unknown runner {runner}")
    for line in problems:
        print(f"agents.json: {line}")
    if problems:
        return 1
    print(f"agents.json: {len(records())} agent records consistent")
    return 0


def cmd_matrix():
    include = [{"agent": agent, "os": runner}
               for agent, rec in records().items() for runner in rec["runners"]]
    print(json.dumps({"include": include}, separators=(",", ":")))
    return 0


def cmd_get(agent, key):
    value = record(agent)
    for part in key.split("."):
        value = value.get(part) if isinstance(value, dict) else None
    if value is None:
        return 1
    print(value)
    return 0


def numeric(version):
    return tuple(int(p) for p in version.split("-")[0].split("."))


def cmd_version(agent, installed):
    checked = record(agent).get("checked") or {}
    want = checked.get("version")
    match = VERSION.search(installed)
    if not match:
        fail(f"{agent}: no version in {installed!r}")
    got = match.group(0)
    if not want:
        relation = f"no checked version recorded ({checked.get('note')})"
    elif got == want:
        relation = "the version the adapter was checked against"
    else:
        try:
            newer = numeric(got) > numeric(want)
        except ValueError:
            newer = got != want
        relation = (f"newer than the {want} the adapter was checked against: read its changes"
                    if newer else f"older than the checked {want}")
    print(f"{got}\t{relation}")
    return 0


def cmd_configs(agent):
    for path, fmt in record(agent).get("config", []):
        print(f"{expand(path)}\t{fmt}")
    return 0


def cmd_json(path):
    try:
        json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        fail(f"{path} does not parse as JSON: {error}")
    print(f"ok    {path} parses as JSON")
    return 0


def localise(value, home, project):
    """The fixture's made-up paths moved into the throwaway home and project."""
    if isinstance(value, dict):
        return {k: localise(v, home, project) for k, v in value.items()}
    if isinstance(value, list):
        return [localise(v, home, project) for v in value]
    if isinstance(value, str):
        if value == "/p" or value.startswith("/p/"):
            return project + value[2:]
        for fake in ("/Users/me", "/home/dev"):
            if value == fake or value.startswith(fake + "/"):
                return home + value[len(fake):]
    return value


def cmd_payload(agent, which, home, project):
    payload = record(agent)["payload"]
    doc = json.loads((HOSTS / payload["fixture"]).read_text(encoding="utf-8"))
    doc = localise(doc, home, project)
    pointer(doc, payload["command"], ALLOWED if which == "allow" else DENIED, set_value=True)
    print(json.dumps(doc))
    return 0


def verdict_of(agent, reply):
    at = record(agent)["payload"]["verdict"]
    if at == "hermes":
        # Hermes Agent: `block` (as `decision` or `action`) denies, `{}` allows.
        if not isinstance(reply, dict):
            return ""
        if "block" in (reply.get("decision"), reply.get("action")):
            return "deny"
        return "ask" if reply.get("action") == "approve" else "allow"
    try:
        return pointer(reply, at)
    except KeyError:
        return ""


def cmd_reply(agent, which, code, path):
    text = Path(path).read_text(encoding="utf-8").strip()
    try:
        reply = json.loads(text) if text else None
    except ValueError:
        fail(f"{agent}: guard's reply is not JSON: {text[:300]!r}")
    got = verdict_of(agent, reply) if reply is not None else ""
    want_code = 2 if which == "deny" else 0
    if int(code) != want_code or got != which:
        fail(f"{agent}: the {which} payload got exit {code} and verdict {got!r}, "
             f"expected exit {want_code} and {which!r}: {text[:300]}")
    if which == "deny" and "secrets-paths" not in text:
        fail(f"{agent}: the deny reply does not name secrets-paths: {text[:300]}")
    print(f"ok    guard, {which} payload in {agent}'s format: exit {code}, verdict {got}")
    return 0


def cmd_protected(agent, status_path, doctor_path):
    rec = record(agent)
    host, name = rec["host"], rec["name"]
    try:
        status = json.loads(Path(status_path).read_text(encoding="utf-8"))
        doctor = json.loads(Path(doctor_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        fail(f"status or doctor JSON unreadable: {error}")
    mine = [a for a in status.get("agents", []) if a.get("host") == host]
    level = mine[0].get("level") if mine else "missing"
    if level not in ("hook-only", "hook-and-os-sandbox"):
        reason = mine[0].get("reason") if mine else None
        fail(f"openmoat status: {name} is {level} ({reason}), not protected by its hook")
    lines = [c for c in doctor.get("checks", []) if c.get("name") == name
             and str(c.get("detail", "")).startswith("protection: hook")]
    if not lines:
        fail(f"openmoat doctor has no `{name}  protection: hook…` line")
    problems = [f"{c.get('name')} {c.get('detail')}" for c in doctor.get("checks", [])
                if c.get("status") == "problem"]
    if problems or not doctor.get("healthy"):
        fail(f"openmoat doctor is not healthy: {problems}")
    print(f"ok    status: {name} {level}; doctor: {lines[0]['detail']}; healthy")
    return 0


def rows(path):
    text = Path(path).read_text(encoding="utf-8").strip()
    value = json.loads(text) if text else []
    return value if isinstance(value, list) else []


def cmd_denied(host, before, after, markers):
    seen = {json.dumps(r, sort_keys=True) for r in rows(before)}
    new = [r for r in rows(after) if json.dumps(r, sort_keys=True) not in seen]
    hits = [r for r in new if r.get("host") == host and r.get("verdict") == "deny"
            and "secrets-paths" in (r.get("rules") or [])]
    if not hits:
        fail(f"no new {host} deny [secrets-paths] in the audit log: the agent never ran "
             f"OpenMoat's hook for the call. New rows: {json.dumps(new)[:1500]}")
    for marker in markers:
        path, _, secret = marker.partition("=")
        if secret and secret in Path(path).read_text(encoding="utf-8", errors="replace"):
            fail(f"the fake key's text is in {path}: the read ran")
    print(f"ok    the real agent ran OpenMoat's hook: {host} {hits[0].get('tool')} "
          f"deny [secrets-paths]")
    return 0


def load_json(path, what):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        fail(f"{what}: {path} is not JSON: {error}")


def cmd_openclaw_valid(config, report):
    """`openclaw config validate --json` calls the file valid."""
    doc = load_json(report, "openclaw config validate")
    if not isinstance(doc, dict) or doc.get("valid") is not True:
        fail(f"openclaw config validate does not call {config} valid: {json.dumps(doc)[:1500]}")
    print(f"ok    openclaw config validate: {config} is valid")
    return 0


def cmd_openclaw_inspect(report):
    """`openclaw plugins inspect openmoat --runtime --json`: the module was
    imported and registered its `before_tool_call` hook."""
    doc = load_json(report, "openclaw plugins inspect")
    plugin = doc.get("plugin") if isinstance(doc, dict) else None
    hooks = doc.get("typedHooks") if isinstance(doc, dict) else None
    if not isinstance(plugin, dict) or not isinstance(hooks, list):
        fail(f"openclaw plugins inspect: no plugin or typedHooks: {json.dumps(doc)[:1500]}")
    names = [h.get("name") for h in hooks if isinstance(h, dict)]
    if (plugin.get("id") != "openmoat" or plugin.get("status") != "loaded"
            or plugin.get("imported") is not True or "before_tool_call" not in names):
        fail(f"openclaw plugins inspect: OpenMoat's plugin is not loaded with its "
             f"before_tool_call hook: plugin {plugin}, hooks {names}")
    print("ok    openclaw loaded OpenMoat's plugin and its before_tool_call hook")
    return 0


def opencode_settled(doc):
    """True once OpenCode 2 has applied a location's first plugin activation.

    `GET /api/plugin` returns the location's inventory as it stands: `[]` until
    the activation, which a new location starts in the background, has applied
    (v2.2.0 `core/src/plugin.ts:44,51-53`; `core/src/plugin/supervisor.ts`,
    the initial `activate` is forked). Built-in plugins are always in an
    applied inventory, and local plugin files are applied in the same first
    step, before any package install, so a non-empty list is a settled one."""
    return isinstance(doc, dict) and isinstance(doc.get("data"), list) and bool(doc["data"])


def cmd_opencode_settled(report):
    """Exit 0, silently, once the `GET /api/plugin` report is a settled
    inventory; 1 while it is not (the caller polls)."""
    try:
        with open(report, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return 1
    return 0 if opencode_settled(doc) else 1


def cmd_opencode_active(report):
    """OpenCode 2's `GET /api/plugin`: an `openmoat` plugin from the local file
    whose state is `active`, which OpenCode sets only once `setup` succeeded."""
    doc = load_json(report, "opencode serve GET /api/plugin")
    if not opencode_settled(doc):
        fail("OpenCode 2's plugin inventory is empty: the location's plugins had not "
             f"finished activating, so this proves nothing either way: {json.dumps(doc)[:1500]}")
    found = []

    def walk(value):
        if isinstance(value, dict):
            if value.get("id") == "openmoat":
                found.append(value)
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(doc)
    active = [p for p in found if isinstance(p.get("state"), dict)
              and p["state"].get("status") == "active"
              and str((p.get("source") or {}).get("path", "")).endswith("plugins/openmoat.js")]
    if not active:
        fail(f"OpenCode 2 does not report OpenMoat's plugin active: {json.dumps(found or doc)[:1500]}")
    print("ok    OpenCode 2 ran OpenMoat's plugin's setup: state active")
    return 0


COMMANDS = {
    "opencode-active": (cmd_opencode_active, 1), "opencode-settled": (cmd_opencode_settled, 1),
    "openclaw-valid": (cmd_openclaw_valid, 2), "openclaw-inspect": (cmd_openclaw_inspect, 1),
    "records": (cmd_records, 0), "matrix": (cmd_matrix, 0), "get": (cmd_get, 2),
    "version": (cmd_version, 2), "configs": (cmd_configs, 1), "json": (cmd_json, 1),
    "payload": (cmd_payload, 4), "reply": (cmd_reply, 4), "protected": (cmd_protected, 3),
}


def main(argv):
    if argv and argv[0] == "denied" and len(argv) >= 4:
        return cmd_denied(argv[1], argv[2], argv[3], argv[4:])
    if not argv or argv[0] not in COMMANDS or len(argv) - 1 != COMMANDS[argv[0]][1]:
        print(__doc__, file=sys.stderr)
        return 64
    if argv[0] in ("payload", "reply") and argv[2] not in ("allow", "deny"):
        print(__doc__, file=sys.stderr)
        return 64
    return COMMANDS[argv[0]][0](*argv[1:])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
