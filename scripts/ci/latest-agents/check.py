#!/usr/bin/env python3
"""The checks of the weekly latest-agent job (scripts/ci/latest-agents.sh) that
read JSON, and the agent records they come from (agents.json beside this file).

    check.py records                         every record is consistent
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
    check.py session-start <host> <before.json> <after.json>
                                             a new audit row: <host>'s SessionStart hook ran
    check.py injected <host> <before.json> <after.json> <text>
                                             a new audit row naming <text> held by injected-input
    check.py resumed <fake api log>          the resumed session carried its earlier tool results
    check.py background-mcp <host> <before.json> <after.json> <server log> <tool>
                                             the MCP call was decided by PreToolUse; a call the
                                             server saw with no decision fails, whether or not
                                             it ran as a background task
    check.py capture-event <host> <event>    a hook: copies its payload to OPENMOAT_CAPTURE_DIR
    check.py event-captured <dir> <host> <event>
                                             says whether that event sent a payload (never fails)
    check.py scrub <host> <version> <captured dir> <root> <home> <project> <out dir>
                                             each payload `openmoat guard` copied for <host> written
                                             as `captured-<version>-<n>.json`, with the throwaway
                                             paths made the fixtures' made-up ones
    check.py openclaw-valid <config> <report.json>
    check.py openclaw-inspect <report.json>  OpenClaw's own validator and plugin inspector agree
    check.py opencode-settled <report.json>  OpenCode 2's plugin inventory is applied (exit 0/1, silent)
    check.py opencode-active <report.json>   OpenCode 2 reports OpenMoat's plugin active
    check.py hook-failure-fact <host> <status.json> fails|times_out|timeout_s
                                             one hook-failure fact of the host (ADR-079)
    check.py hook-failure <agent> <mode> <fact> <marker> <ran file> <calls log> <agent output>
                          <api log> <out.json>
                                             what the agent did with the probe while the hook
                                             failed, against the fact; fails only when a call
                                             ran where the fact says the agent blocks
    check.py hook-failure-skip <agent> <mode> <fact> <why> <out.json>
                                             records a case not run, and why

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
    as that object (Copilot CLI's `toolArgs`) and written back as a string, and a
    list is entered by index (Cline's `commands/0`)."""
    parts = [p.replace("~1", "/").replace("~0", "~") for p in path.split("/")[1:]]
    if not parts:
        return doc
    head, rest = parts[0], "/" + "/".join(parts[1:]) if len(parts) > 1 else ""
    if isinstance(doc, list) and head.isdigit() and int(head) < len(doc):
        if not rest:
            if set_value:
                doc[int(head)] = value
                return value
            return doc[int(head)]
        return pointer(doc[int(head)], rest, value, set_value)
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


# What a record's `proves` may name: the claims a passing run of this job
# asserts against the real agent, which docs/PROTECTION.md shows as evidence
# (ADR-079 decision 5; crates/openmoat-hosts/tests/docs/weekly.rs reads them).
PROVES = ("hook", "hook-failure", "mcp")


def proves_problems(rec):
    """Why a record's `proves` and `why` are wrong: a list of known claims,
    each once, and a reason whenever the hook is not among them."""
    proves = rec.get("proves")
    if not isinstance(proves, list) or not all(isinstance(p, str) for p in proves):
        return ["`proves` is not a list of claims"]
    problems = [f"`proves` names unknown claim {p!r}" for p in proves if p not in PROVES]
    if len(set(proves)) != len(proves):
        problems.append("`proves` names a claim twice")
    if "hook" not in proves and not rec.get("why"):
        problems.append("proves no hook call and gives no `why`")
    if rec.get("why") and "hook" in proves:
        problems.append("`why` is for a record that proves no hook call")
    return problems


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
        problems.extend(f"{agent}: {p}" for p in proves_problems(rec))
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
    if at == "cline":
        # Cline: `cancel: true` stops the call; `{}` is no decision, its allow.
        if not isinstance(reply, dict):
            return ""
        return "deny" if reply.get("cancel") is True else "allow"
    if at == "goose":
        # goose: `decision: block` denies, `decision: allow` (or no output) allows.
        if not isinstance(reply, dict):
            return ""
        return {"block": "deny", "allow": "allow"}.get(reply.get("decision"), "")
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
    # Codex rejects a bare `permissionDecision: allow`, so its allow is no output.
    if which == "allow" and reply is None and record(agent)["payload"].get("allow_is_silent"):
        got = "allow"
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


def new_rows(host, before, after):
    seen = {json.dumps(r, sort_keys=True) for r in rows(before)}
    return [r for r in rows(after)
            if r.get("host") == host and json.dumps(r, sort_keys=True) not in seen]


def cmd_session_start(host, before, after):
    """Claude Code ran OpenMoat's SessionStart hook: it records the session's
    start (`session-start`), or the proxy credential it issued."""
    new = new_rows(host, before, after)
    hits = [r for r in new
            if {"session-start", "proxy-credential"} & set(r.get("rules") or [])]
    if not hits:
        fail(f"no new {host} SessionStart row in the audit log: the agent never ran "
             f"OpenMoat's SessionStart hook. New rows: {json.dumps(new)[:1500]}")
    print(f"ok    the real agent ran OpenMoat's SessionStart hook: {hits[0].get('rules')}")
    return 0


def cmd_injected(host, before, after, text):
    """A call using what an earlier call's output named was held as injected
    input: OpenMoat's PostToolUse hook kept that output (ADR-057)."""
    new = new_rows(host, before, after)
    hits = [r for r in new if "injected-input" in (r.get("rules") or [])
            and r.get("verdict") in ("review", "deny") and text in json.dumps(r)]
    if not hits:
        fail(f"no new {host} row naming {text} held by injected-input: the agent never ran "
             f"OpenMoat's PostToolUse hook, or it kept nothing. New rows: {json.dumps(new)[:1500]}")
    print(f"ok    the real agent ran OpenMoat's PostToolUse hook: {text} "
          f"{hits[0].get('verdict')} [injected-input]")
    return 0


def cmd_resumed(log):
    """The fake API saw the resumed prompt with the earlier tool results in the
    conversation: this is the same session, not a new one."""
    text = Path(log).read_text(encoding="utf-8", errors="replace")
    earlier = [int(n) for n in re.findall(r"resumed with (\d+) earlier tool results", text)]
    if not earlier:
        fail(f"the resumed run never asked the fake API for the resumed conversation: {log}")
    if max(earlier) == 0:
        fail("the resumed session holds no earlier tool result: it is a new conversation, "
             "so the denied call was not asked for again after a resume")
    print(f"ok    the resumed session carried {max(earlier)} earlier tool results")
    return 0


def server_calls(log, tool):
    """The `tools/call` requests for `tool`'s short name in the fake MCP server's log."""
    short = tool.rsplit("__", 1)[-1]
    try:
        lines = Path(log).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    entries = [json.loads(line) for line in lines if line.startswith("{")]
    return [e for e in entries if e.get("method") == "tools/call" and e.get("name") == short]


def cmd_background_mcp(host, before, after, log, tool):
    """An MCP tool call is decided by PreToolUse however it runs. Claude Code runs
    an MCP task only with feature flags and an interactive or stream-json session
    (its documentation, "MCP tasks"), so a one-shot `claude -p` with no account
    cannot make one: that case passes, and says so plainly in the job summary."""
    decided = [r for r in new_rows(host, before, after) if tool in json.dumps(r)]
    calls = server_calls(log, tool)
    tasks = [c for c in calls if c.get("task")]
    if calls and not decided:
        kind = "a BACKGROUND TASK" if tasks else "a foreground call"
        fail(f"{tool} reached its server as {kind} with NO PreToolUse decision in the audit "
             f"log: OpenMoat never saw a call that ran")
    if not decided:
        fail(f"{tool} was never decided and never reached its server: the agent did not make "
             f"the call (see the fake API's log and agent-resume.txt), so this proves nothing")
    verdicts = sorted({str(r.get("verdict")) for r in decided})
    print(f"ok    {tool} reached PreToolUse and was decided: {verdicts}")
    if tasks:
        print(f"ok    {tool} ran as a background MCP task and PreToolUse decided it")
    else:
        print(f"warn  background MCP NOT EXERCISED: {tool} was not run as a task in this job "
              f"(server calls: {len(calls)}, none with the tasks extension). A one-shot "
              f"`claude -p` with no account cannot make one, so whether PreToolUse fires for a "
              f"background MCP task is NOT proven here")
    return 0


def cmd_capture_event(host, event):
    """A hook command: the payload of `event`, as it arrived, in the capture
    directory. It never fails the call it reports."""
    target = os.environ.get("OPENMOAT_CAPTURE_DIR")
    try:
        payload = sys.stdin.read()
        if target:
            name = f"{host}-event-{event}-{os.getpid()}.json"
            with open(Path(target) / name, "x", encoding="utf-8") as out:
                out.write(payload)
    except (OSError, ValueError):
        pass
    return 0


def cmd_event_captured(captured, host, event):
    found = sorted(Path(captured).glob(f"{host}-event-{event}-*.json"))
    if found:
        print(f"ok    {host} sent {event}: {len(found)} payload(s) captured "
              f"({found[0].name}); no adapter is written from it yet")
    else:
        print(f"warn  no {event} payload captured for {host}: the event did not fire in this run")
    return 0


def unlocalise(value, places):
    """`value` with each throwaway path of `places` (longest first) made the
    fixtures' made-up one."""
    if isinstance(value, dict):
        return {k: unlocalise(v, places) for k, v in value.items()}
    if isinstance(value, list):
        return [unlocalise(v, places) for v in value]
    if isinstance(value, str):
        for real, fake in places:
            value = value.replace(real, fake)
    return value


def cmd_scrub(host, version, captured, root, home, project, out):
    """The payloads `openmoat guard` copied for `host` (`OPENMOAT_CAPTURE_DIR`,
    a capture build only), ready for host/<module>/fixtures/."""
    # A capture never fails the job: an odd version string names no file.
    if not VERSION.fullmatch(version):
        version = "unknown"
    places = sorted([(project, "/p"), (home, "/Users/me"), (root, "/tmp/scratch")],
                    key=lambda p: -len(p[0]))
    files = sorted(Path(captured).glob(f"{host}-*.json")) if Path(captured).is_dir() else []
    Path(out).mkdir(parents=True, exist_ok=True)
    for n, path in enumerate(files, start=1):
        doc = unlocalise(json.loads(path.read_text(encoding="utf-8")), places)
        target = Path(out) / f"captured-{version}-{n}.json"
        target.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        print(f"ok    {path.name} -> {target.name}")
    if not files:
        print(f"warn  no payload captured for {host} (a build without capture-payloads, or "
              f"an agent that clears the hook's environment)")
    return 0


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


FACT_KEYS = ("fails", "times_out", "timeout_s")


def cmd_hook_failure_fact(host, status_path, key):
    """One hook-failure fact of <host> as `openmoat status --format json` gives it
    (ADR-079): `blocks`, `runs` or `not-documented`, or the time limit in seconds;
    `none` for a limit the host does not document."""
    if key not in FACT_KEYS:
        print(f"check.py: hook-failure-fact takes one of {FACT_KEYS}", file=sys.stderr)
        return 64
    status = load_json(status_path, "openmoat status")
    mine = [a for a in status.get("agents", []) if a.get("host") == host]
    facts = mine[0].get("hook_failure") if mine else None
    if not isinstance(facts, dict) or key not in facts:
        fail(f"openmoat status has no hook_failure.{key} for {host}: {json.dumps(mine)[:800]}")
    value = facts[key]
    print("none" if value is None else value)
    return 0


def record_outcome(path, entry):
    """Append one outcome to the job's hook-failure.json (one JSON object a line)."""
    with open(path, "a", encoding="utf-8") as out:
        out.write(json.dumps(entry, sort_keys=True) + "\n")


def annotate(level, title, message):
    """A workflow annotation, which GitHub reads from standard output."""
    clean = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(f"::{level} title={title}::{clean}", flush=True)


def cmd_hook_failure_skip(agent, mode, fact, why, out):
    record_outcome(out, {"agent": agent, "mode": mode, "fact": fact, "observed": "not run",
                         "why": why})
    print(f"skip  hook fails ({mode}): {why}")
    return 0


def text_of(path):
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def observed(marker, ran_file, calls_log, agent_out, api_log):
    """What the agent did with the probe while the hook failed: `ran` when the
    probe's marker reached its output, the fake API or the copy in the project;
    `blocked` when the hook ran (its stand-in logged the call) or the agent
    reported a result of the call to the model, and the marker is nowhere;
    `no evidence` otherwise (the agent may never have made the call)."""
    seen = [text_of(p) for p in (ran_file, agent_out, api_log)]
    if any(marker in text for text in seen):
        return "ran"
    hook_ran = bool(text_of(calls_log).strip())
    api = text_of(api_log)
    reported = bool(re.search(r"results=[1-9]", api)) or "tool result:" in seen[1]
    return "blocked" if hook_ran or reported else "no evidence"


def cmd_hook_failure(agent, mode, fact, marker, ran_file, calls_log, agent_out, api_log, out):
    """The probe's outcome against the host fact. A call that ran where the
    fact says the agent blocks fails: OpenMoat would be telling people a
    failed hook stops the call when it does not. A call blocked where the fact
    says it runs (or the fact is not documented), and no evidence, are reported
    for a person to read; the fact stays as it is until the vendor says so."""
    seen = observed(marker, ran_file, calls_log, agent_out, api_log)
    entry = {"agent": agent, "mode": mode, "fact": fact, "observed": seen,
             "hook_called": bool(text_of(calls_log).strip())}
    record_outcome(out, entry)
    words = f"{agent}, hook {mode}: the fact says the agent {fact}; observed: {seen}"
    if fact == "blocks" and seen == "ran":
        annotate("error", f"{agent}: a failed hook let the call run", words)
        fail(words)
    if seen == "no evidence":
        annotate("warning", f"{agent}: hook {mode} proved nothing", words)
    elif (fact == "blocks") != (seen == "blocked"):
        annotate("notice", f"{agent}: hook {mode} differs from the fact", words)
    print(f"ok    {words}")
    return 0


COMMANDS = {
    "hook-failure-fact": (cmd_hook_failure_fact, 3), "hook-failure-skip": (cmd_hook_failure_skip, 5),
    "hook-failure": (cmd_hook_failure, 9),
    "opencode-active": (cmd_opencode_active, 1), "opencode-settled": (cmd_opencode_settled, 1),
    "openclaw-valid": (cmd_openclaw_valid, 2), "openclaw-inspect": (cmd_openclaw_inspect, 1),
    "records": (cmd_records, 0), "matrix": (cmd_matrix, 0), "get": (cmd_get, 2),
    "version": (cmd_version, 2), "configs": (cmd_configs, 1), "json": (cmd_json, 1),
    "payload": (cmd_payload, 4), "reply": (cmd_reply, 4), "protected": (cmd_protected, 3),
    "session-start": (cmd_session_start, 3), "injected": (cmd_injected, 4),
    "scrub": (cmd_scrub, 7), "resumed": (cmd_resumed, 1),
    "background-mcp": (cmd_background_mcp, 5), "capture-event": (cmd_capture_event, 2),
    "event-captured": (cmd_event_captured, 3),
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
