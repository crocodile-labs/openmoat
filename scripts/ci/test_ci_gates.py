#!/usr/bin/env python3
"""Tests of CI's own decisions: what a run needs (changes.py), whether it
passed (ci_ok.py), and whether a commit may be released (main_ci_green.py).
Run by scripts/ci/quality-gate.sh and CI's `scripts` job.

    python3 -I scripts/ci/test_ci_gates.py
"""

import contextlib
import importlib.util
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


changes = load("changes", "changes.py")
ci_ok = load("ci_ok", "ci_ok.py")
main_ci_green = load("main_ci_green", "main_ci_green.py")


def no_readers(_path):
    return []


def run_decide(paths, labels=(), readers=no_readers, event="pull_request", pr="7"):
    return changes.decide(event, pr, "base", "head", list_changed=lambda b, h: list(paths),
                          find_readers=readers, labels=lambda _pr: list(labels))[0]


class Changes(unittest.TestCase):
    def test_docs_only_pr_skips_code_and_slow_legs(self):
        self.assertEqual(run_decide(["docs/USAGE.md", "changelog.d/1-x.md", "README.md"]),
                         {"code": False, "full": False, "long_fuzz": False})

    def test_named_document_is_code(self):
        out = run_decide(["docs/EVIDENCE.md"], readers=lambda p: ["crates/x/tests/doc.rs"])
        self.assertTrue(out["code"])

    def test_ordinary_code_pr_runs_the_fast_subset(self):
        self.assertEqual(run_decide(["crates/openmoat-core/src/engine.rs"]),
                         {"code": True, "full": False, "long_fuzz": False})

    def test_sandbox_paths_run_the_slow_legs(self):
        for path in ("crates/openmoat-cli/src/commands/run/macos.rs",
                     "crates/openmoat-cli/src/commands/run/linux/netns.rs",
                     "crates/openmoat-cli/src/sandbox/seatbelt/filter.rs",
                     "crates/openmoat-cli/src/sandbox/bwrap.rs",
                     "crates/openmoat-cli/src/sandbox/landlock/tests.rs",
                     "crates/openmoat-cli/src/sandbox/seccomp.rs",
                     "crates/openmoat-core/policies/default-v1.yaml",
                     "tests/fixtures/sandbox/seatbelt-default.sb",
                     "crates/openmoat-cli/tests/e2e/run/stock_linux.rs",
                     ".github/workflows/ci.yml",
                     ".github/CODEOWNERS",
                     "rust-toolchain.toml",
                     "scripts/ci/changes.py",
                     "scripts/ci/ci_ok.py"):
            with self.subTest(path=path):
                out = run_decide(["crates/openmoat-core/src/lib.rs", path])
                self.assertTrue(out["full"])
                self.assertFalse(out["long_fuzz"], "sandbox paths do not order long fuzz")

    def test_near_misses_are_not_sandbox_paths(self):
        for path in ("crates/openmoat-cli/src/commands/run.rs",
                     "crates/openmoat-cli/src/commands/run/env.rs",
                     "crates/openmoat-core/src/policy.rs",
                     "scripts/ci/sdk-js.sh"):
            with self.subTest(path=path):
                self.assertFalse(run_decide([path])["full"])

    def test_label_runs_everything_slow(self):
        self.assertEqual(run_decide(["crates/a.rs"], labels=["type: ci", "ci:full"]),
                         {"code": True, "full": True, "long_fuzz": True})

    def test_other_labels_do_not(self):
        self.assertFalse(run_decide(["crates/a.rs"], labels=["ci:fullish", "breaking"])["full"])

    def test_every_other_event_runs_everything(self):
        for event in ("push", "schedule", "workflow_dispatch", "merge_group"):
            with self.subTest(event=event):
                out = changes.decide(event, "", "b", "h",
                                     list_changed=lambda b, h: self.fail("diff read"),
                                     labels=lambda _p: self.fail("labels read"))[0]
                self.assertEqual(out, {"code": True, "full": True, "long_fuzz": True})

    def test_empty_diff_fails_open(self):
        out = run_decide([])
        self.assertTrue(out["code"])
        self.assertTrue(out["full"])

    def test_unreadable_diff_fails_open(self):
        def broken(_b, _h):
            raise subprocess.CalledProcessError(128, ["git"])
        out = changes.decide("pull_request", "7", "b", "h", list_changed=broken,
                             labels=lambda _p: [])[0]
        self.assertTrue(out["code"])
        self.assertTrue(out["full"])

    def test_unreadable_labels_fail_open(self):
        def broken(_pr):
            raise OSError("gh not found")
        out = changes.decide("pull_request", "7", "b", "h",
                             list_changed=lambda b, h: ["docs/USAGE.md"],
                             find_readers=no_readers, labels=broken)[0]
        self.assertEqual(out, {"code": False, "full": True, "long_fuzz": True})

    def test_missing_pr_number_fails_open(self):
        out = changes.decide("pull_request", "", "b", "h",
                             list_changed=lambda b, h: ["crates/a.rs"],
                             find_readers=no_readers, labels=lambda _p: [])[0]
        self.assertTrue(out["full"])
        self.assertTrue(out["long_fuzz"])

    def test_main_prints_every_key(self):
        buf = io.StringIO()
        with mock.patch.object(changes, "decide",
                               return_value=({"code": False, "full": True, "long_fuzz": False}, [])), \
                contextlib.redirect_stdout(buf):
            changes.main(["--event", "pull_request", "--pr", "7", "b", "h"])
        self.assertEqual(buf.getvalue().split(), ["code=false", "full=true", "long_fuzz=false"])


WORKFLOW = """\
name: ci
on:
  pull_request:
jobs:
  # the first job
  changes:
    name: changes
    runs-on: ubuntu-latest
  gate:
    name: ${{ matrix.os }}
    needs: changes
    if: ${{ !cancelled() }}
    steps:
      - name: x
        if: env.RUN_LEG == 'true'
        run: |
          jobs:
            fake:
  deny:
    needs: changes
    if: ${{ !cancelled() && needs.changes.outputs.code != 'false' }}
  typos:
    runs-on: ubuntu-latest
  ci-ok:
    needs: [changes, gate, deny, typos]
    if: always()
"""


def needs_of(code="true", **results):
    base = {"changes": {"result": "success", "outputs": {"code": code, "full": "false"}},
            "gate": {"result": "success", "outputs": {}},
            "deny": {"result": "success", "outputs": {}},
            "typos": {"result": "success", "outputs": {}}}
    for job, result in results.items():
        if result is None:
            del base[job]
        else:
            base[job] = {**base.get(job, {"outputs": {}}), "result": result}
    return base


class CiOk(unittest.TestCase):
    def setUp(self):
        self.jobs = ci_ok.workflow_jobs(WORKFLOW)

    def test_reads_jobs_and_their_conditions(self):
        self.assertEqual(list(self.jobs), ["changes", "gate", "deny", "typos", "ci-ok"])
        self.assertIn(ci_ok.DOCS_ONLY_TEST, self.jobs["deny"])
        self.assertEqual(self.jobs["typos"], "")
        self.assertEqual(self.jobs["gate"], "${{ !cancelled() }}", "a step's if is not the job's")

    def test_all_green_passes(self):
        self.assertEqual(ci_ok.verdict(needs_of(), self.jobs), [])

    def test_failure_and_cancellation_fail(self):
        for result in ("failure", "cancelled"):
            with self.subTest(result=result):
                self.assertEqual(ci_ok.verdict(needs_of(gate=result), self.jobs),
                                 [f"gate: {result}"])

    def test_failed_changes_job_fails(self):
        self.assertTrue(ci_ok.verdict(needs_of(changes="failure"), self.jobs))

    def test_ordered_docs_only_skip_passes(self):
        self.assertEqual(ci_ok.verdict(needs_of(code="false", deny="skipped"), self.jobs), [])

    def test_skip_without_the_order_fails(self):
        self.assertTrue(ci_ok.verdict(needs_of(code="true", deny="skipped"), self.jobs))

    def test_skip_of_a_job_the_order_does_not_cover_fails(self):
        for job in ("gate", "typos"):
            with self.subTest(job=job):
                self.assertTrue(ci_ok.verdict(needs_of(code="false", **{job: "skipped"}),
                                              self.jobs))

    def test_docs_only_answer_from_a_failed_changes_job_orders_nothing(self):
        needs = needs_of(code="false", deny="skipped", changes="failure")
        self.assertIn("deny: skipped, and the changes job did not order it",
                      ci_ok.verdict(needs, self.jobs))

    def test_job_missing_from_needs_fails(self):
        self.assertEqual(ci_ok.verdict(needs_of(typos=None), self.jobs),
                         ["typos: not in ci-ok's needs, so its result is not checked"])

    def test_unknown_need_fails(self):
        needs = {**needs_of(), "ghost": {"result": "success"}}
        self.assertTrue(ci_ok.verdict(needs, self.jobs))

    def test_empty_needs_fails(self):
        self.assertTrue(ci_ok.verdict({}, {"ci-ok": "always()"}))

    def run_main(self, needs, workflow=WORKFLOW):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "ci.yml"
            path.write_text(workflow, encoding="utf-8")
            env = {"NEEDS": needs if isinstance(needs, str) else json.dumps(needs)}
            with mock.patch.dict(os.environ, env), contextlib.redirect_stdout(io.StringIO()):
                return ci_ok.main([str(path)])

    def test_main_exit_codes(self):
        self.assertEqual(self.run_main(needs_of()), 0)
        self.assertEqual(self.run_main(needs_of(deny="failure")), 1)
        self.assertEqual(self.run_main("not json"), 1)
        self.assertEqual(self.run_main('["a list"]'), 1)
        self.assertEqual(self.run_main(needs_of(), WORKFLOW.replace("  ci-ok:", "  other:")), 1)


SHA = "a" * 40


def run(**fields):
    base = {"head_sha": SHA, "event": "push", "head_branch": "main", "status": "completed",
            "conclusion": "success", "created_at": "2026-11-11T10:00:00Z", "run_attempt": 1,
            "html_url": "https://example.invalid/run"}
    return {**base, **fields}


class MainCiGreen(unittest.TestCase):
    def test_green_run_releases(self):
        self.assertIsNone(main_ci_green.verdict([run()], SHA))

    def test_no_run_refuses(self):
        self.assertIn("no `ci` run", main_ci_green.verdict([], SHA))

    def test_runs_elsewhere_do_not_count(self):
        for other in (run(head_sha="b" * 40), run(event="pull_request"),
                      run(head_branch="feature"), run(event="schedule")):
            with self.subTest(run=other):
                self.assertIsNotNone(main_ci_green.verdict([other], SHA))

    def test_running_failed_and_cancelled_refuse(self):
        for fields in ({"status": "in_progress", "conclusion": None},
                       {"conclusion": "failure"}, {"conclusion": "cancelled"},
                       {"conclusion": "skipped"}):
            with self.subTest(**{k: str(v) for k, v in fields.items()}):
                self.assertIsNotNone(main_ci_green.verdict([run(**fields)], SHA))

    def test_newest_run_decides(self):
        old_green = run(created_at="2026-11-11T09:00:00Z")
        new_red = run(created_at="2026-11-11T11:00:00Z", conclusion="failure")
        self.assertIsNotNone(main_ci_green.verdict([old_green, new_red], SHA))
        old_red = run(created_at="2026-11-11T09:00:00Z", conclusion="failure")
        self.assertIsNone(main_ci_green.verdict([old_red, run()], SHA))

    def test_unreadable_runs_refuse(self):
        with mock.patch.object(main_ci_green, "fetch_runs", side_effect=OSError("no gh")), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main_ci_green.main(["o/r", SHA]), 1)
        with mock.patch.object(main_ci_green, "fetch_runs", return_value=[run()]), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main_ci_green.main(["o/r", SHA]), 0)


if __name__ == "__main__":
    unittest.main()
