#!/usr/bin/env python3
"""Tests of check.py's hook-failure commands (ADR-079), the part of the weekly
job's hook-failure step that can be proved without an agent, and the records'
`proves` (ADR-079 decision 5). Run by hand:

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
