#!/usr/bin/env python3
"""Tests of check.py's hook-failure commands (ADR-079), the part of the weekly
job's hook-failure step that can be proved without an agent, how a failed audit
check lists the new rows, `tool-failures`, and the records' `proves` (ADR-079
decision 5). Run by hand:

    python3 -I scripts/ci/latest-agents/test_check.py
"""

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
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


if __name__ == "__main__":
    result = unittest.main(exit=False, verbosity=1).result
    sys.exit(0 if result.wasSuccessful() else 1)
