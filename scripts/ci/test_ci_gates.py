#!/usr/bin/env python3
"""Tests of CI's own decisions: what a run needs (changes.py), whether it
passed (ci_ok.py), whether a commit may be released (main_ci_green.py),
which tests are quarantined (quarantine.py), what a test report says
(junit_summary.py), whether a failure is re-run as infrastructure
(infra_retry.py), which issues main's runs open (main_watch.py), the time
budget (budget.sh), and the workflows themselves: ci-ok's `needs`, the time
budgets against the time limits, the jobs and their parts.
Run by scripts/ci/quality-gate.sh and CI's `lint` job.

    python3 -I scripts/ci/test_ci_gates.py

CI_WORKFLOW_DIR names another directory of workflows to check (one written
for a change, before it is in `.github/workflows`).
"""

import contextlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
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
quarantine = load("quarantine", "quarantine.py")
junit_summary = load("junit_summary", "junit_summary.py")
infra_retry = load("infra_retry", "infra_retry.py")
main_watch = load("main_watch", "main_watch.py")
ROOT = HERE.parents[1]


def no_readers(_path):
    return []


def run_decide(paths, labels=(), readers=no_readers, event="pull_request", pr="7", texts=None):
    """`texts`: {path: content at head}; a path missing from it has no platform code."""
    texts = texts or {}
    return changes.decide(event, pr, "base", "head", list_changed=lambda b, h: list(paths),
                          find_readers=readers, labels=lambda _pr: list(labels),
                          read_file=lambda _rev, p: texts.get(p, "fn f() {}\n"))[0]


FAST = {"code": True, "full": False, "long_fuzz": False, "proxy": False}


class Changes(unittest.TestCase):
    def test_docs_only_pr_skips_code_and_slow_legs(self):
        self.assertEqual(run_decide(["docs/USAGE.md", "changelog.d/1-x.md", "README.md"]),
                         {"code": False, "full": False, "long_fuzz": False, "proxy": False})

    def test_named_document_is_code(self):
        out = run_decide(["docs/EVIDENCE.md"], readers=lambda p: ["crates/x/tests/doc.rs"])
        self.assertTrue(out["code"])

    def test_ordinary_code_pr_runs_the_fast_subset(self):
        self.assertEqual(run_decide(["crates/openmoat-core/src/engine.rs"]), FAST)

    def test_sandbox_paths_run_the_slow_legs(self):
        for path in ("crates/openmoat-cli/src/commands/run.rs",
                     "crates/openmoat-cli/src/commands/run/macos.rs",
                     "crates/openmoat-cli/src/commands/run/env.rs",
                     "crates/openmoat-cli/src/commands/run/linux/netns.rs",
                     "crates/openmoat-cli/src/sandbox.rs",
                     "crates/openmoat-cli/src/sandbox/claude/mask.rs",
                     "crates/openmoat-cli/src/sandbox/seatbelt/filter.rs",
                     "crates/openmoat-cli/src/sandbox/bwrap.rs",
                     "crates/openmoat-cli/src/sandbox/landlock/tests.rs",
                     "crates/openmoat-cli/src/sandbox/seccomp.rs",
                     "crates/openmoat-cli/src/protection/os_sandbox.rs",
                     "crates/openmoat-core/policies/default-v1.yaml",
                     "tests/fixtures/sandbox/seatbelt-default.sb",
                     "crates/openmoat-cli/tests/e2e/run.rs",
                     "crates/openmoat-cli/tests/e2e/run_guard.rs",
                     "crates/openmoat-cli/tests/e2e/run/stock_linux.rs",
                     "crates/openmoat-cli/tests/e2e/sandbox.rs",
                     "crates/openmoat-cli/tests/e2e/sandbox_exec.rs",
                     "crates/openmoat-cli/tests/e2e/cursor_sandbox.rs",
                     ".github/workflows/ci.yml",
                     ".github/CODEOWNERS",
                     "Cargo.lock",
                     "rust-toolchain.toml",
                     "scripts/ci/changes.py",
                     "scripts/ci/ci_ok.py",
                     "scripts/ci/main_ci_green.py",
                     "scripts/ci/quality-gate.sh"):
            with self.subTest(path=path):
                out = run_decide(["crates/openmoat-core/src/lib.rs", path])
                self.assertTrue(out["full"])
                self.assertTrue(out["proxy"], "full runs ADR-062 step 0 too")
                self.assertFalse(out["long_fuzz"], "sandbox paths do not order long fuzz")

    def test_near_misses_are_not_sandbox_paths(self):
        for path in ("crates/openmoat-cli/src/commands/guard.rs",
                     "crates/openmoat-cli/src/protection/hook_failure.rs",
                     "crates/openmoat-cli/tests/e2e/guard.rs",
                     "crates/openmoat-core/src/policy.rs",
                     "crates/openmoat-core/Cargo.toml",
                     "scripts/ci/sdk-js.sh"):
            with self.subTest(path=path):
                self.assertEqual(run_decide([path]), FAST)

    def test_platform_specific_rust_runs_the_slow_legs(self):
        for text in ("#[cfg(target_os = \"macos\")]\nfn f() {}\n",
                     "#[cfg(unix)]\nmod unix;\n",
                     "#[cfg(windows)]\nmod windows;\n",
                     "#[cfg(not(windows))]\nfn f() {}\n",
                     "#[cfg(any(target_os = \"linux\", target_os = \"android\"))]\n",
                     "if cfg!(windows) { return; }\n",
                     "#[cfg(target_arch = \"x86_64\")]\n"):
            with self.subTest(text=text):
                out = run_decide(["crates/openmoat-core/src/engine.rs"],
                                 texts={"crates/openmoat-core/src/engine.rs": text})
                self.assertTrue(out["full"])
                self.assertFalse(out["long_fuzz"])

    def test_platform_words_elsewhere_do_not(self):
        text = "// works on unix and windows alike\nlet target_os_name = \"x\";\n"
        self.assertEqual(run_decide(["crates/a.rs"], texts={"crates/a.rs": text}), FAST)
        # Only `.rs` files are read.
        self.assertEqual(run_decide(["scripts/x.sh"], texts={"scripts/x.sh": "cfg(unix)"}),
                         FAST)

    def test_platform_check_reads_head_then_base(self):
        reads = []

        def read(rev, path):
            reads.append(rev)
            if rev == "head":
                raise subprocess.CalledProcessError(128, ["git", "show"])
            return "#[cfg(unix)]\n"
        out = changes.decide("pull_request", "7", "base", "head",
                             list_changed=lambda b, h: ["crates/gone.rs"],
                             find_readers=no_readers, labels=lambda _p: [], read_file=read)[0]
        self.assertEqual(reads, ["head", "base"], "a deleted file is read at the base")
        self.assertTrue(out["full"])

    def test_unreadable_file_fails_open(self):
        def read(_rev, _path):
            raise subprocess.CalledProcessError(128, ["git", "show"])
        for error in (OSError("no git"), UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad")):
            def broken(_rev, _path, error=error):
                raise error
            for reader in (read, broken):
                with self.subTest(error=repr(error), reader=reader.__name__):
                    out = changes.decide("pull_request", "7", "b", "h",
                                         list_changed=lambda b, h: ["crates/a.rs"],
                                         find_readers=no_readers, labels=lambda _p: [],
                                         read_file=reader)[0]
                    self.assertTrue(out["full"])
                    self.assertTrue(out["proxy"])

    def test_proxy_paths_run_adr062_only(self):
        for path in ("crates/openmoat-proxy/src/server.rs",
                     "crates/openmoat-proxy/Cargo.toml",
                     "crates/openmoat-proxy/tests/proxy/tls.rs",
                     "crates/openmoat-cli/src/commands/proxy.rs",
                     "crates/openmoat-cli/src/commands/proxy/ca.rs",
                     "crates/openmoat-cli/src/proxy_ca.rs",
                     "crates/openmoat-cli/src/proxy_ca/request_poc.rs",
                     "scripts/ci/adr062-poc.py",
                     "scripts/ci/latency_ab.py"):
            with self.subTest(path=path):
                self.assertEqual(run_decide([path]), {**FAST, "proxy": True})
        # commands/run.rs is both: platform code and measured by step 0.
        out = run_decide(["crates/openmoat-cli/src/commands/run.rs"])
        self.assertTrue(out["full"])
        self.assertTrue(out["proxy"])

    def test_proxy_near_misses(self):
        for path in ("crates/openmoat-cli/src/proxy_session.rs",
                     "crates/openmoat-proxy-other/src/lib.rs",
                     "scripts/ci/guard-latency.py"):
            with self.subTest(path=path):
                self.assertEqual(run_decide([path]), FAST)

    def test_label_runs_everything_slow(self):
        self.assertEqual(run_decide(["crates/a.rs"], labels=["type: ci", "ci:full"]),
                         {"code": True, "full": True, "long_fuzz": True, "proxy": True})

    def test_other_labels_do_not(self):
        self.assertFalse(run_decide(["crates/a.rs"], labels=["ci:fullish", "breaking"])["full"])

    def test_every_other_event_runs_everything(self):
        for event in ("push", "schedule", "workflow_dispatch", "merge_group"):
            with self.subTest(event=event):
                out = changes.decide(event, "", "b", "h",
                                     list_changed=lambda b, h: self.fail("diff read"),
                                     labels=lambda _p: self.fail("labels read"),
                                     read_file=lambda _r, _p: self.fail("file read"))[0]
                self.assertEqual(out, {"code": True, "full": True, "long_fuzz": True,
                                       "proxy": True})

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
        self.assertTrue(out["proxy"])

    def test_unreadable_labels_fail_open(self):
        def broken(_pr):
            raise OSError("gh not found")
        out = changes.decide("pull_request", "7", "b", "h",
                             list_changed=lambda b, h: ["docs/USAGE.md"],
                             find_readers=no_readers, labels=broken)[0]
        self.assertEqual(out, {"code": False, "full": True, "long_fuzz": True, "proxy": True})

    def test_missing_pr_number_fails_open(self):
        out = changes.decide("pull_request", "", "b", "h",
                             list_changed=lambda b, h: ["crates/a.rs"],
                             find_readers=no_readers, labels=lambda _p: [],
                             read_file=lambda _r, _p: "")[0]
        self.assertTrue(out["full"])
        self.assertTrue(out["long_fuzz"])

    def test_main_prints_every_key(self):
        buf = io.StringIO()
        with mock.patch.object(changes, "decide",
                               return_value=({"code": False, "full": True, "long_fuzz": False,
                                              "proxy": True}, [])), \
                contextlib.redirect_stdout(buf):
            changes.main(["--event", "pull_request", "--pr", "7", "b", "h"])
        self.assertEqual(buf.getvalue().split(),
                         ["code=false", "full=true", "long_fuzz=false", "proxy=true"])

    def test_platform_files_read_through_git(self):
        """The real `git diff` and `git show`, in a throwaway repository."""
        def git(*args):
            subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t.invalid",
                            "-c", "commit.gpgsign=false", *args],
                           check=True, capture_output=True, cwd=repo)
        with tempfile.TemporaryDirectory() as repo:
            try:
                git("init", "-q")
            except subprocess.CalledProcessError as e:
                # A sandbox that forbids writing `.git/` (an agent's); CI can.
                self.skipTest(f"cannot create a git repository here ({e.stderr!r})")
            (Path(repo) / "gone.rs").write_text("#[cfg(windows)]\nfn f() {}\n")
            (Path(repo) / "kept.rs").write_text("fn f() {}\n")
            git("add", "-A")
            git("commit", "-q", "-m", "base")
            git("tag", "base")
            (Path(repo) / "gone.rs").unlink()
            (Path(repo) / "kept.rs").write_text("fn g() {}\n")
            (Path(repo) / "new.rs").write_text("#[cfg(target_os = \"macos\")]\nfn f() {}\n")
            git("add", "-A")
            git("commit", "-q", "-m", "head")
            old = os.getcwd()
            os.chdir(repo)
            try:
                found = changes.platform_files(changes.changed_paths("base", "HEAD"),
                                               "base", "HEAD")
            finally:
                os.chdir(old)
        self.assertEqual(sorted(found), ["gone.rs", "new.rs"])


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


def problems_of(needs, jobs, event="push"):
    return ci_ok.verdict(needs, jobs, event)[0]


class CiOk(unittest.TestCase):
    def setUp(self):
        self.jobs = ci_ok.workflow_jobs(WORKFLOW)

    def test_latency_is_reported_on_a_pull_request_and_blocks_elsewhere(self):
        jobs = {**self.jobs, "latency": "${{ !cancelled() }}"}
        for result in ("failure", "cancelled"):
            needs = {**needs_of(), "latency": {"result": result, "outputs": {}}}
            with self.subTest(result=result):
                problems, warnings = ci_ok.verdict(needs, jobs, "pull_request")
                self.assertEqual(problems, [])
                self.assertEqual(len(warnings), 1)
                for event in ("push", "schedule", "workflow_dispatch", ""):
                    self.assertEqual(problems_of(needs, jobs, event), [f"latency: {result}"])

    def test_only_latency_is_reported_on_a_pull_request(self):
        self.assertEqual(problems_of(needs_of(gate="failure"), self.jobs, "pull_request"),
                         ["gate: failure"])

    def test_reads_jobs_and_their_conditions(self):
        self.assertEqual(list(self.jobs), ["changes", "gate", "deny", "typos", "ci-ok"])
        self.assertIn(ci_ok.DOCS_ONLY_TEST, self.jobs["deny"])
        self.assertEqual(self.jobs["typos"], "")
        self.assertEqual(self.jobs["gate"], "${{ !cancelled() }}", "a step's if is not the job's")

    def test_all_green_passes(self):
        self.assertEqual(problems_of(needs_of(), self.jobs), [])

    def test_failure_and_cancellation_fail(self):
        for result in ("failure", "cancelled"):
            with self.subTest(result=result):
                self.assertEqual(problems_of(needs_of(gate=result), self.jobs),
                                 [f"gate: {result}"])

    def test_failed_changes_job_fails(self):
        self.assertTrue(problems_of(needs_of(changes="failure"), self.jobs))

    def test_ordered_docs_only_skip_passes(self):
        self.assertEqual(problems_of(needs_of(code="false", deny="skipped"), self.jobs), [])

    def test_skip_without_the_order_fails(self):
        self.assertTrue(problems_of(needs_of(code="true", deny="skipped"), self.jobs))

    def test_skip_of_a_job_the_order_does_not_cover_fails(self):
        for job in ("gate", "typos"):
            with self.subTest(job=job):
                self.assertTrue(problems_of(needs_of(code="false", **{job: "skipped"}),
                                            self.jobs))

    def test_docs_only_answer_from_a_failed_changes_job_orders_nothing(self):
        needs = needs_of(code="false", deny="skipped", changes="failure")
        self.assertIn("deny: skipped, and the changes job did not order it",
                      problems_of(needs, self.jobs))

    def test_job_missing_from_needs_fails(self):
        self.assertEqual(problems_of(needs_of(typos=None), self.jobs),
                         ["typos: not in ci-ok's needs, so its result is not checked"])

    def test_unknown_need_fails(self):
        needs = {**needs_of(), "ghost": {"result": "success"}}
        self.assertTrue(problems_of(needs, self.jobs))

    def test_empty_needs_fails(self):
        self.assertTrue(problems_of({}, {"ci-ok": "always()"}))

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


def state(runs, on_main=True):
    return main_ci_green.verdict(runs, SHA, lambda: on_main)


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds

    def clock(self):
        return self.now


def run_gate(polls, wait_minutes=150, on_main=True):
    """gate() over `polls` (the runs each read returns, the last one repeated)."""
    clock = FakeClock()
    reads = []

    def fetch(_repo, _sha):
        reads.append(1)
        return polls[min(len(reads), len(polls)) - 1]
    with contextlib.redirect_stdout(io.StringIO()):
        passed, why = main_ci_green.gate("o/r", SHA, wait_minutes, 60, fetch=fetch,
                                         on_main=lambda _r, _s: on_main,
                                         sleep=clock.sleep, clock=clock.clock)
    return passed, why, clock.sleeps


class MainCiGreen(unittest.TestCase):
    def test_green_run_releases(self):
        self.assertEqual(state([run()])[0], main_ci_green.PASS)

    def test_no_run_on_main_waits_and_says_so(self):
        self.assertEqual(state([]), (main_ci_green.WAIT,
                                     f"no ci run has started for this commit yet ({SHA})"))

    def test_no_run_off_main_refuses(self):
        verdict, why = state([], on_main=False)
        self.assertEqual(verdict, main_ci_green.REFUSE)
        self.assertIn("this commit is not on main", why)

    def test_runs_elsewhere_do_not_count(self):
        for other in (run(head_sha="b" * 40), run(event="pull_request"),
                      run(head_branch="feature"), run(event="schedule")):
            with self.subTest(run=other):
                self.assertEqual(state([other], on_main=False)[0], main_ci_green.REFUSE)

    def test_running_waits(self):
        for status in ("queued", "in_progress", "waiting", "pending"):
            with self.subTest(status=status):
                self.assertEqual(state([run(status=status, conclusion=None)])[0],
                                 main_ci_green.WAIT)

    def test_failed_and_cancelled_refuse(self):
        for conclusion in ("failure", "cancelled", "skipped", "timed_out", None):
            with self.subTest(conclusion=conclusion):
                self.assertEqual(state([run(conclusion=conclusion)])[0], main_ci_green.REFUSE)

    def test_newest_run_decides(self):
        old_green = run(created_at="2026-11-11T09:00:00Z")
        new_red = run(created_at="2026-11-11T11:00:00Z", conclusion="failure")
        self.assertEqual(state([old_green, new_red])[0], main_ci_green.REFUSE)
        old_red = run(created_at="2026-11-11T09:00:00Z", conclusion="failure")
        self.assertEqual(state([old_red, run()])[0], main_ci_green.PASS)
        rerun = run(created_at="2026-11-11T09:00:00Z", run_attempt=2,
                    status="in_progress", conclusion=None)
        self.assertEqual(state([old_red, rerun])[0], main_ci_green.WAIT)

    def test_gate_waits_for_a_run_in_progress(self):
        going = [run(status="in_progress", conclusion=None)]
        passed, _why, sleeps = run_gate([[], going, going, [run()]])
        self.assertTrue(passed)
        self.assertEqual(sleeps, [60, 60, 60])

    def test_gate_stops_waiting_on_a_failure(self):
        going = [run(status="in_progress", conclusion=None)]
        passed, why, sleeps = run_gate([going, [run(conclusion="failure")]])
        self.assertFalse(passed)
        self.assertIn("ended `failure`", why)
        self.assertEqual(sleeps, [60])

    def test_gate_gives_up_at_the_bound(self):
        passed, why, sleeps = run_gate([[run(status="queued", conclusion=None)]],
                                       wait_minutes=150)
        self.assertFalse(passed)
        self.assertIn("gave up after 150 minutes", why)
        self.assertEqual(len(sleeps), 150)
        self.assertLessEqual(sum(sleeps), 150 * 60)

    def test_gate_off_main_refuses_without_waiting(self):
        passed, why, sleeps = run_gate([[]], on_main=False)
        self.assertFalse(passed)
        self.assertIn("this commit is not on main", why)
        self.assertEqual(sleeps, [])

    def test_commit_on_main_reads_the_compare_status(self):
        for status, on_main in (("identical", True), ("behind", True),
                                ("ahead", False), ("diverged", False), (None, False)):
            with self.subTest(status=status), \
                    mock.patch.object(main_ci_green, "gh_json", return_value={"status": status}):
                self.assertEqual(main_ci_green.commit_on_main("o/r", SHA), on_main)

    def test_main_exit_codes(self):
        def main(*argv):
            with contextlib.redirect_stdout(io.StringIO()):
                return main_ci_green.main(["--wait-minutes", "0", *argv, "o/r", SHA])
        with mock.patch.object(main_ci_green, "fetch_runs", side_effect=OSError("no gh")):
            self.assertEqual(main(), 1)
        with mock.patch.object(main_ci_green, "fetch_runs", return_value=[]), \
                mock.patch.object(main_ci_green, "commit_on_main",
                                  side_effect=subprocess.CalledProcessError(1, ["gh"])):
            self.assertEqual(main(), 1)
        with mock.patch.object(main_ci_green, "fetch_runs",
                               return_value=[run(status="queued", conclusion=None)]):
            self.assertEqual(main(), 1, "still running when the wait is over")
        with mock.patch.object(main_ci_green, "fetch_runs", return_value=[run()]):
            self.assertEqual(main(), 0)


TABLE_HEAD = """\
# Quarantined tests

Rules in prose, with `profile.ci` and a | pipe | in a sentence is not a row.

| binary id | test | failure signature | first red | owner | issue |
|---|---|---|---|---|---|
"""


class Quarantine(unittest.TestCase):
    TODAY = quarantine.datetime.date(2026, 11, 12)

    def rows(self, *lines):
        return quarantine.rows(TABLE_HEAD + "".join(f"{line}\n" for line in lines))

    def test_the_repository_table_reads(self):
        found = quarantine.rows((ROOT / ".config/nextest-quarantine.md").read_text("utf-8"))
        quarantine.check(found, self.TODAY)

    def test_an_empty_table_runs_everything(self):
        self.assertEqual(quarantine.held(self.rows()), "")
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "q.md"
            path.write_text(TABLE_HEAD, encoding="utf-8")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(quarantine.main(["--file", str(path), "exclude"]), 0)
            self.assertEqual(out.getvalue().strip(), "all()")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(quarantine.main(["--file", str(path), "only"]), 0)
            self.assertEqual(out.getvalue(), "")

    def test_rows_become_an_exact_filter(self):
        found = self.rows("| `openmoat::e2e` | `alias::a_test` | timeout | 2026-11-10 | me | #1 |",
                          "| openmoat-audit | store::tests::b | panic | 2026-11-11 | me | #2 |")
        self.assertEqual(quarantine.held(found),
                         "(binary_id(=openmoat::e2e) & test(=alias::a_test)) | "
                         "(binary_id(=openmoat-audit) & test(=store::tests::b))")
        self.assertEqual(quarantine.check(found, self.TODAY), [])

    def test_a_row_past_fourteen_days_warns(self):
        found = self.rows("| openmoat::e2e | alias::a_test | timeout | 2026-10-01 | me | #1 |")
        self.assertEqual(len(quarantine.check(found, self.TODAY)), 1)

    def test_security_tests_are_never_quarantined(self):
        for binary, test in (("openmoat::e2e", "sandbox::x"), ("openmoat::e2e", "run::y"),
                             ("openmoat::e2e", "guard::z"), ("openmoat-core::conformance", "a"),
                             ("openmoat::bin/openmoat", "sandbox::seatbelt::t")):
            found = self.rows(f"| {binary} | {test} | flaky | 2026-11-10 | me | #1 |")
            with self.subTest(test=test), self.assertRaises(quarantine.Problem):
                quarantine.check(found, self.TODAY)

    def test_malformed_rows_fail(self):
        for line in ("| openmoat::e2e | a | x | 2026-11-10 | me |",
                     "| openmoat::e2e | a | x | yesterday | me | #1 |",
                     "| openmoat::e2e |  | x | 2026-11-10 | me | #1 |",
                     "| openmoat::e2e | a) | test(b | x | 2026-11-10 | me | #1 |",
                     "| openmoat::e2e | a | x | 2026-11-10 | me |  |"):
            with self.subTest(line=line), self.assertRaises(quarantine.Problem):
                self.rows(line)

    def test_the_security_list_is_the_one_nextest_never_retries(self):
        config = (ROOT / ".config/nextest.toml").read_text("utf-8")
        for profile in ("ci", "ci-intel"):
            no_retry = re.search(
                rf'\[\[profile\.{re.escape(profile)}\.overrides\]\]\nfilter = "([^"]*)"\nretries = 0',
                config)
            self.assertIsNotNone(no_retry, profile)
            text = no_retry.group(1)
            for binary in quarantine.SECURITY_BINARIES:
                self.assertIn(f"binary_id(={binary})", text)
            for binary, prefixes in quarantine.SECURITY_PREFIXES.items():
                self.assertIn(f"binary_id(={binary})", text)
                for prefix in prefixes:
                    self.assertIn(f"test(/^{prefix}/)", text, f"{profile}: {prefix}")


def junit(*cases):
    return ET.fromstring(f"<testsuites><testsuite name='s'>{''.join(cases)}</testsuite></testsuites>")


PANIC = ("thread 'allow::x' panicked at crates/openmoat-cli/tests/e2e/allow.rs:12:5:\n"
         "assertion `left == right` failed: outside the project needs review\n")


class JunitSummary(unittest.TestCase):
    def test_failed_flaky_and_passed(self):
        root = junit(
            "<testcase classname='openmoat::e2e' name='allow::x' time='3.5'>"
            f"<failure type='test failure'/><system-err>{PANIC}</system-err></testcase>",
            "<testcase classname='openmoat::e2e' name='run::y' time='2'>"
            f"<flakyFailure type='test failure'><system-err>{PANIC}</system-err></flakyFailure>"
            "</testcase>",
            "<testcase classname='openmoat-core' name='z' time='0.1'/>",
            "<testcase classname='openmoat::e2e' name='slow::t' time='130'>"
            "<failure type='test timeout' message='test timed out'/></testcase>")
        found = junit_summary.cases(root)
        self.assertEqual([c[3] for c in found], ["failed", "flaky", "passed", "failed"])
        self.assertEqual(found[0][4], "crates/openmoat-cli/tests/e2e/allow.rs:12:5: "
                                      "assertion `left == right` failed: outside the project "
                                      "needs review")
        self.assertEqual(found[3][4], "test timed out")
        markdown, notes = junit_summary.report(found)
        self.assertIn("2 failed, 1 flaky", markdown)
        self.assertIn("**Slowest 4**", markdown)
        self.assertTrue(notes[0].startswith("::error title=test failed::openmoat::e2e allow::x: "))
        self.assertTrue(notes[-1].startswith("::warning title=flaky test::openmoat::e2e run::y: "))

    def test_a_failure_retried_keeps_the_first_panic(self):
        root = junit("<testcase classname='b' name='t' time='1'><failure type='test failure'/>"
                     f"<rerunFailure><system-err>{PANIC}</system-err></rerunFailure></testcase>")
        self.assertIn("allow.rs:12:5", junit_summary.cases(root)[0][4])

    def test_annotations_escape_newlines(self):
        self.assertEqual(junit_summary.escape("a%b\nc\r"), "a%25b%0Ac%0D")

    def test_balance(self):
        self.assertIsNone(junit_summary.balance({"1": 100, "2": 120}))
        self.assertIn("partition balance", junit_summary.balance({"1": 100, "2": 130}))
        self.assertIsNone(junit_summary.balance({"1": 100}))

    def test_an_unreadable_report_is_a_warning(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(junit_summary.main(["/nonexistent/junit.xml"]), 0)
        self.assertIn("::warning", out.getvalue())


def job(name, conclusion="failure", job_id=1):
    return {"name": name, "conclusion": conclusion, "id": job_id}


def note(message, title="", level="failure"):
    return {"annotation_level": level, "title": title, "message": message}


EXIT = note("Process completed with exit code 1.")
NOT_ACQUIRED = note("The job was not acquired by Runner of type hosted even after multiple "
                    "attempts")
RESOLVING = note("apt could not install: bubblewrap socat (Temporary failure resolving "
                 "'azure.archive.ubuntu.com')")
GITHUB_503 = note("downloading https://github.com/nextest-rs/nextest/releases/download/x failed: "
                  "curl: (22) The requested URL returned error: 503")


class InfraRetry(unittest.TestCase):
    def decide(self, jobs, notes, attempt=1):
        return infra_retry.decide(attempt, jobs, lambda j: notes[j["name"]])[0]

    def test_infrastructure_signatures_retry(self):
        for signature in (NOT_ACQUIRED, RESOLVING, GITHUB_503,
                          note("The hosted runner lost communication with the server."),
                          note("Failed to download action 'https://api.github.com/repos/a/b/"
                               "tarball/c'. Error: Response status code does not indicate "
                               "success: 502 (Bad Gateway).")):
            with self.subTest(signature=signature["message"][:40]):
                jobs = [job("macos (1/2)"), job("ci-ok"), job("lint", "success")]
                self.assertTrue(self.decide(jobs, {"macos (1/2)": [signature, EXIT],
                                                   "ci-ok": [note("macos: failure")]}))

    def test_never_a_second_attempt(self):
        self.assertFalse(self.decide([job("linux (1/2)")], {"linux (1/2)": [RESOLVING]}, 2))

    def test_a_test_failure_or_timeout_is_never_retried(self):
        for notes in ([note("openmoat::e2e a::b: x", title="test failed"), RESOLVING],
                      [note("The job running on runner X has exceeded the maximum execution "
                            "time of 30 minutes."), NOT_ACQUIRED],
                      [note("thread 'x' panicked at a.rs:1:1"), GITHUB_503],
                      [EXIT],
                      []):
            with self.subTest(notes=notes):
                self.assertFalse(self.decide([job("linux (2/2)")], {"linux (2/2)": notes}))
        self.assertFalse(self.decide([job("linux (2/2)", "timed_out")],
                                     {"linux (2/2)": [NOT_ACQUIRED]}))

    def test_every_failed_job_must_be_infrastructure(self):
        jobs = [job("macos (1/2)"), job("linux (1/2)")]
        self.assertFalse(self.decide(jobs, {"macos (1/2)": [NOT_ACQUIRED],
                                            "linux (1/2)": [note("error[E0425]: cannot find")]}))
        self.assertTrue(self.decide(jobs, {"macos (1/2)": [NOT_ACQUIRED],
                                           "linux (1/2)": [RESOLVING, EXIT]}))

    def test_a_failed_verdict_alone_is_not_retried(self):
        self.assertFalse(self.decide([job("ci-ok"), job("lint", "success")],
                                     {"ci-ok": [NOT_ACQUIRED]}))

    def test_warnings_do_not_count(self):
        jobs = [job("windows (2/2)")]
        self.assertTrue(self.decide(jobs, {"windows (2/2)": [
            NOT_ACQUIRED, note("something odd", level="warning")]}))

    def test_an_unreadable_run_is_not_retried(self):
        out = io.StringIO()
        with mock.patch.object(infra_retry, "gh_api", side_effect=OSError("no gh")), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(infra_retry.main(["1", "1"]), 0)
        self.assertEqual(out.getvalue().strip(), "retry=false")


class MainWatch(unittest.TestCase):
    def test_tests_are_read_from_the_annotations(self):
        failed, flaky = main_watch.tests_in([
            note("openmoat::e2e allow::x: crates/a.rs:12:5: boom", title="test failed"),
            note("openmoat::e2e run::y: passed only on retry; a.rs:1:1: x", title="flaky test",
                 level="warning"),
            note("ci-ok: gate failed", title="ci-ok")])
        self.assertEqual(failed, {"openmoat::e2e allow::x"})
        self.assertEqual(flaky, {"openmoat::e2e run::y"})

    def test_plan(self):
        now = ({"b a::x", "b a::new"}, {"b a::flaky"})
        before = ({"b a::other"}, {"b a::x"})
        titles = [t for t, _ in main_watch.plan("failure", "url", now, before)]
        self.assertEqual(titles, ["ci: main is red", "flaky test: b a::flaky",
                                  "test failing on main: b a::x"])
        self.assertEqual([t for t, _ in main_watch.plan("success", "url", (set(), set()),
                                                        before)], [])


class Budget(unittest.TestCase):
    def run_budget(self, limit, used):
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("no bash")
        env = {"PATH": os.environ.get("PATH", ""), "JOB_STARTED": "1000",
               "BUDGET_NOW": str(1000 + used)}
        return subprocess.run([bash, str(HERE / "budget.sh"), str(limit)], env=env,
                              capture_output=True, text=True)

    def test_warns_past_sixty_percent_and_never_fails(self):
        out = self.run_budget(30, 17 * 60)
        self.assertEqual(out.returncode, 0)
        self.assertIn("56%", out.stdout)
        self.assertNotIn("::warning", out.stdout)
        out = self.run_budget(30, 19 * 60)
        self.assertEqual(out.returncode, 0)
        self.assertIn("::warning title=time budget::", out.stdout)


def workflow(name):
    directory = Path(os.environ.get("CI_WORKFLOW_DIR") or ROOT / ".github/workflows")
    return (directory / name).read_text(encoding="utf-8")


def job_blocks(text):
    """{job id: its lines} of a workflow, read as ci_ok.py reads it."""
    blocks, current, in_jobs = {}, None, False
    for line in text.splitlines():
        if line and not line.startswith(" ") and not line.startswith("#"):
            in_jobs = line.rstrip() == "jobs:"
            current = None
            continue
        m = ci_ok.JOB.match(line)
        if in_jobs and m:
            current = m.group(1)
            blocks[current] = []
        elif current:
            blocks[current].append(line)
    return blocks


class Workflows(unittest.TestCase):
    """The workflows as written: checked here, so a wrong one fails before CI."""

    def setUp(self):
        self.ci = workflow("ci.yml")
        if "install-nextest.sh" not in self.ci:
            self.skipTest("this ci.yml predates the nextest design; set CI_WORKFLOW_DIR")

    def test_ci_ok_needs_every_job(self):
        jobs = set(ci_ok.workflow_jobs(self.ci)) - {"ci-ok"}
        needs = re.search(r"  ci-ok:\n(?:    .*\n)*?    needs:\n((?:      - .*\n)+)", self.ci)
        self.assertIsNotNone(needs)
        listed = {line.strip()[2:] for line in needs.group(1).splitlines()}
        self.assertEqual(listed, jobs)

    def test_pull_requests_and_main_run_no_intel(self):
        self.assertNotIn("macos-15-intel", self.ci)

    def test_each_os_runs_the_tests_in_two_parts(self):
        test = "\n".join(job_blocks(self.ci)["test"])
        self.assertIn("os: [ubuntu-latest, macos-15, windows-latest]", test)
        self.assertIn("part: [1, 2]", test)
        self.assertIn("GATE_PARTITION: ${{ matrix.part }}/2", test)
        self.assertIn("NEXTEST_PROFILE: ci", test)

    def test_weekly_runs_intel_in_three_parts_with_its_profile(self):
        weekly = workflow("weekly.yml")
        intel = "\n".join(job_blocks(weekly)["intel"])
        self.assertIn("runs-on: macos-15-intel", intel)
        self.assertIn("part: [1, 2, 3]", intel)
        self.assertIn("GATE_PARTITION: ${{ matrix.part }}/3", intel)
        self.assertIn("NEXTEST_PROFILE: ci-intel", intel)
        self.assertIn("GATE_STEPS: test", intel)
        self.assertIn("timeout-minutes: 60", intel)

    def test_every_time_budget_is_its_job_limit(self):
        for name in ("ci.yml", "weekly.yml"):
            for job_id, lines in job_blocks(workflow(name)).items():
                text = "\n".join(lines)
                limit = re.search(r"^    timeout-minutes: (.+)$", text, re.MULTILINE)
                budgets = re.findall(r"budget\.sh", text)
                if job_id in ("changes", "ci-ok") or not limit:
                    continue
                with self.subTest(workflow=name, job=job_id):
                    self.assertTrue(budgets, "no time budget step")
                    limits = re.findall(r"^          LIMIT: (.+)$", text, re.MULTILINE)
                    self.assertEqual(limits, [limit.group(1)] * len(budgets))

    def test_retry_workflow_is_narrow(self):
        retry = workflow("ci-retry.yml")
        self.assertIn("workflows: [ci]", retry)
        self.assertIn("run_attempt == 1", retry)
        self.assertIn("permissions: {}", retry)
        self.assertEqual(retry.count("actions: write"), 1)


if __name__ == "__main__":
    unittest.main()
