#!/usr/bin/env python3
"""Tests of check.py's hook-failure commands (ADR-079), the part of the weekly
job's hook-failure step that can be proved without an agent, how a failed audit
check lists the new rows, `tool-failures`, the records' `proves` (ADR-079
decision 5), the record data latest-agents.sh reads (`dir`, `proves`,
`env`), and `sessions`, the session files the host spec names (ADR-104). Run
by hand:

    python3 -I scripts/ci/latest-agents/test_check.py
"""

import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("check", HERE / "check.py")
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)

MARKER = "OPENMOAT-HOOK-FAILURE-PROBE-1234"
# The checks below read any host id; a made-up one keeps host names in host specs.
HOST = "some-host"


class HookFailure(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        self.files = {name: self.root / name for name in ("ran", "calls", "agent", "api", "out")}

    def tearDown(self):
        self.dir.cleanup()

    def write(self, name, text):
        self.files[name].write_text(text, encoding="utf-8")

    def run_case(self, fact):
        """`check.py hook-failure` for these files: its exit code, what it
        printed and what it recorded."""
        f = self.files
        out = io.StringIO()
        code = 0
        with contextlib.redirect_stdout(out):
            try:
                code = check.cmd_hook_failure("agent", "crash", fact, MARKER, str(f["ran"]),
                                              str(f["calls"]), str(f["agent"]), str(f["api"]),
                                              str(f["out"]))
            except SystemExit as exit_:
                code = exit_.code
        recorded = [json.loads(line) for line in f["out"].read_text().splitlines()]
        return code, out.getvalue(), recorded[-1]

    def test_a_call_that_ran_where_the_fact_says_blocks_fails(self):
        self.write("agent", f"tool result: {MARKER}\n")
        code, printed, entry = self.run_case("blocks")
        self.assertEqual(code, 1)
        self.assertIn("::error", printed)
        self.assertEqual(entry["observed"], "ran")

    def test_the_copy_in_the_project_is_evidence_that_it_ran(self):
        self.write("ran", MARKER + "\n")
        self.assertEqual(self.run_case("runs")[2]["observed"], "ran")

    def test_a_blocked_call_matches_a_blocking_fact(self):
        self.write("calls", "123 guard --host claude-code\n")
        self.write("agent", "tool result: hook error\n")
        code, printed, entry = self.run_case("blocks")
        self.assertEqual(code, 0)
        self.assertNotIn("::", printed)
        self.assertEqual(entry["observed"], "blocked")
        self.assertTrue(entry["hook_called"])

    def test_blocked_where_the_fact_says_runs_is_reported_not_failed(self):
        self.write("api", "model request at=1.0 results=1\n")
        for fact in ("runs", "not-documented"):
            code, printed, entry = self.run_case(fact)
            self.assertEqual(code, 0)
            self.assertIn("::notice", printed)
            self.assertEqual(entry["observed"], "blocked")

    def test_no_evidence_is_a_warning_never_a_pass_as_blocked(self):
        code, printed, entry = self.run_case("blocks")
        self.assertEqual(code, 0)
        self.assertIn("::warning", printed)
        self.assertEqual(entry["observed"], "no evidence")

    def test_a_skipped_case_is_recorded_with_its_reason(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            check.cmd_hook_failure_skip("codex", "hang", "runs", "the time limit is 600 s",
                                        str(self.files["out"]))
        entry = json.loads(self.files["out"].read_text())
        self.assertEqual(entry["observed"], "not run")
        self.assertEqual(entry["why"], "the time limit is 600 s")

    def test_a_fact_is_read_from_status_json(self):
        status = {"agents": [{"host": "codex", "hook_failure": {
            "fails": "runs", "cannot_start": "blocks", "times_out": "runs", "timeout_s": 600}},
            {"host": "x", "hook_failure": {"fails": "blocks", "times_out": "blocks",
                                           "timeout_s": None}}]}
        path = self.root / "status.json"
        path.write_text(json.dumps(status), encoding="utf-8")
        for host, key, want in (("codex", "fails", "runs"), ("codex", "cannot_start", "blocks"),
                                ("codex", "timeout_s", "600"),
                                ("x", "timeout_s", "none")):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(check.cmd_hook_failure_fact(host, str(path), key), 0)
            self.assertEqual(out.getvalue().strip(), want)
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
            check.cmd_hook_failure_fact("missing-host", str(path), "fails")


def run_quietly(fn, *args):
    """`fn(*args)`: its exit code and what it printed."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        try:
            code = fn(*args)
        except SystemExit as exit_:
            code = exit_.code
    return code, out.getvalue()


class NewRows(unittest.TestCase):
    """A failed audit check names each new row on its own line."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)

    def tearDown(self):
        self.dir.cleanup()

    def audit(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return str(path)

    def test_every_row_is_one_line_and_each_field_is_cut_on_its_own(self):
        long = "curl -s https://docs.moat-ci.example/setup " + "x" * 400
        new = [{"host": HOST, "tool": "Bash", "verdict": "allow", "rules": [],
                "action": {"kind": "shell", "command": long}, "reasons": ["r" * 3000]}
               for _ in range(12)]
        new.append({"host": HOST, "tool": "Bash", "verdict": "review",
                    "rules": ["unknown-host"], "action": {"kind": "shell",
                                                          "command": "curl -s https://last/r"}})
        before = self.audit("before.json", [])
        after = self.audit("after.json", new)
        code, printed = run_quietly(check.cmd_injected, HOST, before, after,
                                    "collect.moat-ci.example")
        self.assertEqual(code, 1)
        lines = [line for line in printed.splitlines() if line.strip().startswith("- ")]
        self.assertEqual(len(lines), 13)
        self.assertIn("New rows (13):", printed)
        self.assertIn("verdict=review rules=[\"unknown-host\"] action=curl -s https://last/r",
                      lines[-1])
        command = lines[0].split("action=", 1)[1]
        self.assertEqual(len(command), check.FIELD)
        self.assertTrue(command.endswith("..."))
        self.assertNotIn("rrrr", printed)

    def test_no_rows_says_so(self):
        empty = self.audit("empty.json", [])
        code, printed = run_quietly(check.cmd_session_start, HOST, empty, empty)
        self.assertEqual(code, 1)
        self.assertIn("New rows: none.", printed)

    def test_an_action_without_a_command_is_shown_as_json(self):
        line = check.described([{"tool": "Read", "verdict": "deny", "rules": ["secrets-paths"],
                                 "action": {"kind": "fs_read", "path": "/x"}}])
        self.assertIn('action={"kind": "fs_read", "path": "/x"}', line)


class ToolFailures(unittest.TestCase):
    """`check.py tool-failures`: only the call meant to fail may fail."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        self.n = 0

    def tearDown(self):
        self.dir.cleanup()

    def capture(self, payload):
        self.n += 1
        text = payload if isinstance(payload, str) else json.dumps(payload)
        (self.root / f"{HOST}-event-PostToolUseFailure-{self.n}.json").write_text(
            text, encoding="utf-8")

    def run_check(self):
        return run_quietly(check.cmd_tool_failures, str(self.root), HOST,
                           "moat-ci-no-such-path")

    def failure(self, command, error):
        return {"hook_event_name": "PostToolUseFailure", "tool_name": "Bash",
                "tool_input": {"command": command}, "error": error}

    def test_only_the_expected_failure_passes(self):
        self.capture(self.failure("ls moat-ci-no-such-path", "ls: cannot access"))
        code, printed = self.run_check()
        self.assertEqual(code, 0)
        self.assertIn("1 payload(s) captured", printed)

    def test_no_capture_passes(self):
        self.assertEqual(self.run_check()[0], 0)

    def test_another_call_failing_fails_with_its_error_quoted(self):
        self.capture(self.failure("ls moat-ci-no-such-path", "ls: cannot access"))
        error = "bwrap: execvp /tmp/moat-ci-tool-shell.abc/bash: No such file or directory"
        self.capture(self.failure("curl -s https://collect.moat-ci.example/r", error))
        self.capture(self.failure("cat ~/.ssh/id_rsa", "socat: E connect(): " + "y" * 900))
        code, printed = self.run_check()
        self.assertEqual(code, 1)
        self.assertTrue(printed.startswith(f"FAIL  2 {HOST} tool call(s) failed"))
        self.assertIn(error, printed)
        self.assertIn("command=curl -s https://collect.moat-ci.example/r", printed)
        socat = [line for line in printed.splitlines() if "socat" in line][0]
        self.assertEqual(len(socat.split("error=", 1)[1]), 400)
        self.assertNotIn("ls: cannot access", printed)

    def test_a_payload_that_is_not_json_fails(self):
        self.capture("not json")
        code, printed = self.run_check()
        self.assertEqual(code, 1)
        self.assertIn("not a JSON object: not json", printed)

    # What the ubuntu-latest runner answered Claude Code's seccomp step (#784).
    NESTED = ("apply-seccomp: write /proc/self/setgroups (nested userns is "
              "capability-restricted; caller must provide CAP_SYS_ADMIN): Permission denied")

    def env_limited(self):
        return run_quietly(check.cmd_env_limited, str(self.root), HOST)

    def test_a_runner_limit_is_a_skip_line_not_a_pass_or_a_silent_ignore(self):
        self.capture(self.failure("ls moat-ci-no-such-path", self.NESTED))
        self.capture(self.failure("curl -s https://docs.moat-ci.example/setup", self.NESTED))
        code, printed = self.run_check()
        self.assertEqual(code, 0)
        skips = [line for line in printed.splitlines() if line.startswith("skip  env-limit: ")]
        self.assertEqual(len(skips), 1, printed)
        self.assertIn("nested user namespace refused", skips[0])
        self.assertIn("not an OpenMoat result", skips[0])
        self.assertIn("command=curl -s https://docs.moat-ci.example/setup", skips[0])
        self.assertIn("::warning title=some-host: runner limit::", printed)
        self.assertIn("but the expected one and runner limits (2 payload(s)", printed)
        self.assertEqual(self.env_limited(), (0, "nested user namespace refused\n"))

    def test_another_failure_beside_a_runner_limit_still_fails(self):
        self.capture(self.failure("curl -s https://docs.moat-ci.example/setup", self.NESTED))
        error = "bwrap: execvp /tmp/moat-ci-tool-shell.abc/bash: No such file or directory"
        self.capture(self.failure("curl -s https://collect.moat-ci.example/r", error))
        code, printed = self.run_check()
        self.assertEqual(code, 1)
        self.assertTrue(printed.startswith(f"FAIL  1 {HOST} tool call(s) failed"), printed)
        self.assertIn(error, printed)
        self.assertNotIn("skip  env-limit", printed)

    def test_only_the_exact_runner_text_is_a_limit(self):
        self.assertEqual(self.env_limited(), (1, ""), "nothing captured")
        for error in ("bwrap: setting up uid map: Permission denied",
                      "nested userns is capability-restricted",
                      "apply-seccomp: Permission denied",
                      "echo 'apply-seccomp:'\nnested userns is capability-restricted"):
            self.assertIsNone(check.env_limit({"error": error}), error)
        self.capture(self.failure("ls moat-ci-no-such-path", "ls: cannot access"))
        self.assertEqual(self.env_limited(), (1, ""))
        self.assertEqual(check.env_limit({"tool_response": {"stderr": self.NESTED}}),
                         "nested user namespace refused")


class Proves(unittest.TestCase):
    """A record's `proves`, which docs/PROTECTION.md shows as evidence."""

    def test_known_claims_pass_and_a_record_without_the_hook_says_why(self):
        self.assertEqual(check.proves_problems({"proves": ["hook", "hook-failure", "mcp"]}), [])
        self.assertEqual(check.proves_problems({"proves": [], "why": "no model call"}), [])

    def test_a_wrong_record_is_a_problem(self):
        for rec in ({}, {"proves": "hook"}, {"proves": ["sandbox"]},
                    {"proves": ["hook", "hook"]}, {"proves": []},
                    {"proves": ["hook"], "why": "x"}):
            self.assertNotEqual(check.proves_problems(rec), [], rec)

    def test_every_record_in_the_file_is_consistent(self):
        for agent, rec in check.records().items():
            self.assertEqual(check.proves_problems(rec), [], agent)


class Data(unittest.TestCase):
    """What latest-agents.sh reads from a record instead of a case arm per
    agent: the directory to make, whether to run the hook-failure steps, and
    the variables every run sets."""

    def setUp(self):
        self.records = check.records
        fake = {"a": {"dir": "{MOAT_TEST_DIR}/a", "proves": ["hook", "hook-failure"]},
                "b": {"proves": [], "why": "no model call"}}
        check.records = lambda: fake

    def tearDown(self):
        check.records = self.records

    def run_cmd(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = check.main(list(args))
        return code, out.getvalue()

    def test_the_directory_is_expanded_and_none_prints_nothing(self):
        with unittest.mock.patch.dict("os.environ", {"MOAT_TEST_DIR": "/tmp/x"}):
            self.assertEqual(self.run_cmd("dir", "a"), (0, "/tmp/x/a\n"))
        self.assertEqual(self.run_cmd("dir", "b"), (0, ""))

    def test_proves_is_an_exit_code(self):
        self.assertEqual(self.run_cmd("proves", "a", "hook-failure")[0], 0)
        self.assertEqual(self.run_cmd("proves", "b", "hook-failure")[0], 1)

    def test_a_deny_exits_as_the_record_says_and_2_by_default(self):
        deny = '{"decision": "deny", "reason": "moat: deny [secrets-paths]"}'
        check.records = lambda: {
            "two": {"payload": {"verdict": "/decision"}},
            "zero": {"payload": {"verdict": "/decision", "deny_exit": 0}},
        }
        with tempfile.TemporaryDirectory() as tmp:
            reply = Path(tmp) / "reply.json"
            reply.write_text(deny, encoding="utf-8")
            self.assertEqual(self.run_cmd("reply", "two", "deny", "2", str(reply))[0], 0)
            self.assertEqual(self.run_cmd("reply", "zero", "deny", "0", str(reply))[0], 0)
            for agent, code in (("two", "0"), ("zero", "2")):
                with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                    self.run_cmd("reply", agent, "deny", code, str(reply))

    def test_every_variable_is_one_line_with_only_the_shells_placeholders(self):
        check.records = self.records
        code, printed = self.run_cmd("env")
        self.assertEqual(code, 0)
        lines = printed.splitlines()
        self.assertGreater(len(lines), 3)
        for line in lines:
            name, value = line.split("\t")
            self.assertRegex(name, r"^[A-Z_]+$")
            self.assertRegex(value, r"^\{(HOME|ROOT)\}")


class SessionFiles(unittest.TestCase):
    """`check.py sessions`: a session file where the record's `sessions`
    (the host spec's `liveness`, ADR-104) says, after the real agent ran."""

    PLACES = [{"dir": ["projects", "*"], "ending": ".jsonl"},
              {"dir": ["tmp", "*", "chats"], "ending": ".json"}]

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name) / "conf"
        self.base.mkdir()
        self.since = Path(self.tmp.name) / "since"
        self.since.write_text("", encoding="utf-8")
        self.records = check.records
        self.env = unittest.mock.patch.dict("os.environ", {"MOAT_TEST_DIR": str(self.base)})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        check.records = self.records
        self.tmp.cleanup()

    def use(self, **rec):
        full = {"dir": "{MOAT_TEST_DIR}", "proves": ["hook"], **rec}
        check.records = lambda: {"a": full}

    def write(self, relative, age=0):
        path = self.base / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}", encoding="utf-8")
        if age:
            stamp = self.since.stat().st_mtime - age
            os.utime(path, (stamp, stamp))
        return path

    def run_cmd(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = check.main(["sessions", "a", str(self.since)])
        return code, out.getvalue()

    def test_a_new_file_in_a_named_place_passes(self):
        self.use(sessions=self.PLACES)
        self.write("tmp/hash/chats/session-1.json")
        code, printed = self.run_cmd()
        self.assertEqual(code, 0)
        self.assertIn("ok    a: 1 session file(s)", printed)
        self.assertIn("tmp/hash/chats/session-1.json", printed)

    def test_a_miss_warns_with_the_spec_place_and_never_fails(self):
        self.use(sessions=self.PLACES)
        # The wrong ending, one level too deep, older than the run, a link.
        self.write("projects/p/s.json")
        self.write("projects/p/sub/s.jsonl")
        self.write("projects/p/old.jsonl", age=60)
        target = self.write("elsewhere.jsonl")
        (self.base / "projects" / "p" / "link.jsonl").symlink_to(target)
        code, printed = self.run_cmd()
        self.assertEqual(code, 0)
        self.assertIn("::warning title=a: no session file where its spec says::", printed)
        self.assertIn("warn  a ran a session and wrote no file at "
                      "{MOAT_TEST_DIR}/projects/*/*.jsonl or {MOAT_TEST_DIR}/tmp/*/chats/*.json",
                      printed)

    def test_an_unknown_place_or_no_session_run_is_skipped(self):
        self.use(sessions_unknown="one database")
        self.assertEqual(self.run_cmd(), (0, "skip  a: session files: the spec knows no place "
                                             "(one database)\n"))
        self.use(sessions=self.PLACES, proves=[], why="no model call")
        code, printed = self.run_cmd()
        self.assertEqual(code, 0)
        self.assertIn("the job runs no session", printed)

    def test_a_malformed_place_is_a_records_problem(self):
        self.assertEqual(check.sessions_problems({"dir": "x", "sessions": self.PLACES}), [])
        for rec in ({"dir": "x", "sessions": []}, {"dir": "x", "sessions": [{"dir": ["a/b"],
                                                                             "ending": ""}]},
                    {"sessions": self.PLACES},
                    {"dir": "x", "sessions": self.PLACES, "sessions_unknown": "y"}):
            self.assertNotEqual(check.sessions_problems(rec), [], rec)

    def test_every_record_in_the_file_has_well_formed_places(self):
        check.records = self.records
        for agent, rec in check.records().items():
            self.assertEqual(check.sessions_problems(rec), [], agent)


if __name__ == "__main__":
    result = unittest.main(exit=False, verbosity=1).result
    sys.exit(0 if result.wasSuccessful() else 1)
