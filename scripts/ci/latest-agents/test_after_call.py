#!/usr/bin/env python3
"""Tests of after_call.py, the one part of the weekly job that can be proved
without an agent. Run by hand:

    python3 -I scripts/ci/latest-agents/test_after_call.py
"""

import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "after_call.py"
SPEC = importlib.util.spec_from_file_location("after_call", SCRIPT)
after_call = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(after_call)

PLACES = [("/runner/home/project", "/p"), ("/runner/home", "/Users/me")]


def report(agent, directory, log, step="done"):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = after_call.main(["report", agent, str(directory), str(log), step])
    assert code == 0
    return out.getvalue()


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeApis(unittest.TestCase):
    def quietly(self, call, *args):
        with contextlib.redirect_stderr(io.StringIO()) as log:
            return call(*args), log.getvalue()

    def test_openai_serves_the_second_call_after_one_result_and_ends_after_two(self):
        fake = load("fake_openai")
        fake.CALLS.append(("bash", {"command": "first"}))
        fake.THEN.append(("bash", {"command": "second"}))
        for results, want in (([], ("call", "bash", {"command": "first"})),
                              (["denied"], ("call", "bash", {"command": "second"})),
                              (["denied", "out"], ("text", "tool result: out"))):
            step, log = self.quietly(fake.next_step, ["bash"], results)
            self.assertEqual(step, want)
            self.assertRegex(log, rf"at=[0-9.]+ results={len(results)}\n")

    def test_openai_without_then_ends_after_one_result_as_before(self):
        fake = load("fake_openai")
        fake.CALLS.append(("bash", {"command": "first"}))
        step, _ = self.quietly(fake.next_step, ["bash"], ["denied"])
        self.assertEqual(step, ("text", "tool result: denied"))

    def test_gemini_serves_the_second_call_after_one_response(self):
        fake = load("fake_gemini")
        fake.CALL, fake.THEN = ("run_command", {"c": 1}), ("run_command", {"c": 2})
        tools = [{"functionDeclarations": [{"name": "run_command"}]}]
        answer = {"parts": [{"functionResponse": {}}]}
        parts = [self.quietly(fake.reply, {"tools": tools, "contents": [answer] * n})[0]
                 ["candidates"][0]["content"]["parts"][0] for n in range(3)]
        self.assertEqual(parts, [{"functionCall": {"name": "run_command", "args": {"c": 1}}},
                                 {"functionCall": {"name": "run_command", "args": {"c": 2}}},
                                 {"text": "done"}])

    def test_gemini_answers_the_readiness_probe(self):
        fake = load("fake_gemini")
        handler = fake.Handler.__new__(fake.Handler)
        statuses = []
        handler.send_response = statuses.append
        handler.send_header = lambda *_: None
        handler.end_headers = lambda: None
        handler.wfile = io.BytesIO()
        handler.do_GET()
        self.assertEqual(statuses, [200])
        self.assertEqual(json.loads(handler.wfile.getvalue()), {"models": []})

    def test_gemini_logs_what_each_function_response_says(self):
        fake = load("fake_gemini")
        fake.CALL, fake.THEN = ("run_command", {"c": 1}), None
        said = {"functionResponse": {"name": "run_command", "response": {"output": "x" * 999}}}
        request = {"contents": [{"parts": [said]}]}
        _, log = self.quietly(fake.reply, request)
        self.assertIn("results=1\n", log)
        line = log.splitlines()[1]
        self.assertTrue(line.startswith('  result 1: run_command: {"output": "xxx'), line)
        self.assertLess(len(line), fake.RESPONSE_CHARS + 40)

    def test_gemini_without_then_ends_after_one_response_as_before(self):
        fake = load("fake_gemini")
        fake.CALL, fake.THEN = ("run_command", {"c": 1}), None
        tools = [{"functionDeclarations": [{"name": "run_command"}]}]
        request = {"tools": tools, "contents": [{"parts": [{"functionResponse": {}}]}]}
        got = self.quietly(fake.reply, request)[0]
        self.assertEqual(got["candidates"][0]["content"]["parts"][0], {"text": "done"})


class Clean(unittest.TestCase):
    def test_every_value_under_a_sensitive_key_is_replaced(self):
        got = after_call.clean({"api_key": "s1", "Authorization": "s2", "auth": {"a": "s3"},
                                "env": {"GITHUB_TOKEN": "s4"}, "tokens": ["s5"]}, PLACES)
        self.assertEqual(got, {"api_key": "[redacted string]", "Authorization": "[redacted string]",
                               "auth": "[redacted object]", "env": {"GITHUB_TOKEN": "[redacted string]"},
                               "tokens": "[redacted array]"})

    def test_a_secret_inside_a_string_holding_json_is_replaced(self):
        got = after_call.clean({"toolArgs": json.dumps({"token": "s1", "command": "ls"})}, PLACES)
        self.assertNotIn("s1", json.dumps(got))
        self.assertEqual(json.loads(got["toolArgs"])["command"], "ls")

    def test_throwaway_paths_are_made_up(self):
        got = after_call.clean({"cwd": "/runner/home/project", "log": "/runner/home/a"}, PLACES)
        self.assertEqual(got, {"cwd": "/p", "log": "/Users/me/a"})

    def test_a_string_that_only_looks_like_json_is_kept(self):
        self.assertEqual(after_call.clean({"o": "{not json"}, PLACES), {"o": "{not json"})


class Fields(unittest.TestCase):
    def test_names_and_types_never_values(self):
        got = after_call.fields([{"tool_name": "VALUE1", "n": 7, "ok": True, "gone": None,
                                  "tool_response": {"stdout": "VALUE2"}, "items": [{"a": "VALUE3"}],
                                  "none": [], "api_key": "[redacted string]",
                                  "toolArgs": json.dumps({"command": "VALUE4"})}])
        self.assertNotIn("VALUE", got)
        for part in ("tool_name=string", "n=number", "ok=boolean", "gone=null",
                     "tool_response.stdout=string", "items[].a=string", "none=empty array",
                     "api_key=redacted string", "toolArgs=string holding JSON",
                     "toolArgs(json).command=string"):
            self.assertIn(part, got)

    def test_a_key_that_is_data_is_not_printed(self):
        got = after_call.fields([{"files": {"/home/runner/secret.txt": 1, "a b": 2}}])
        self.assertNotIn("secret.txt", got)
        self.assertEqual(got, "files.<key>=number")

    def test_payloads_are_merged(self):
        self.assertEqual(after_call.fields([{"o": "x"}, {"o": 1}, {"p": 1}]),
                         "o=number|string; p=number")

    def test_a_long_shape_is_cut(self):
        got = after_call.fields([{f"field_{n}_{'x' * 40}": 1 for n in range(200)}])
        self.assertLess(len(got), after_call.MAX_NOTICE + 200)
        self.assertIn("more, in the artefact", got)


class Waited(unittest.TestCase):
    timing = [{"started": 10.0, "finished": 11.5}]

    def test_next_request_after_the_hook(self):
        self.assertTrue(after_call.waited(self.timing, [(5.0, 1), (12.0, 2)]).startswith("yes"))

    def test_next_request_during_the_hook(self):
        self.assertTrue(after_call.waited(self.timing, [(5.0, 1), (10.4, 2)]).startswith("no"))

    def test_a_side_request_without_a_tool_result_does_not_count(self):
        self.assertTrue(after_call.waited(self.timing, [(10.4, 0), (12.0, 2)]).startswith("yes"))

    def test_nothing_to_compare(self):
        self.assertIn("not observable", after_call.waited(self.timing, None))
        self.assertIn("not observable", after_call.waited(self.timing, [(5.0, 1)]))


class Commands(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.home = self.root / "home"
        self.dir = self.root / "after-call"
        self.home.mkdir()
        saved = dict(os.environ)
        self.addCleanup(lambda: (os.environ.clear(), os.environ.update(saved)))
        os.environ["HOME"] = str(self.home)
        # Plain directory names: nothing here writes where a real agent's files live.
        files = {agent: spec["file"] for agent, spec in after_call.AGENTS.items()}
        self.addCleanup(lambda: [after_call.AGENTS[a].update(file=f) for a, f in files.items()])
        for agent, spec in after_call.AGENTS.items():
            spec["file"] = "{HOME}/" + f"{agent}/hooks.json"
        self.args = [str(self.dir), str(self.root), str(self.home), str(self.home / "project")]

    def install(self, agent):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(after_call.main(["install", agent, *self.args]), 0)
        return Path(after_call.AGENTS[agent]["file"].format(**os.environ))

    def test_each_layout_writes_a_command_the_agent_reads(self):
        pointers = {"codex": lambda d: d["hooks"]["PostToolUse"][0]["hooks"][0]["command"],
                    "gemini-cli": lambda d: d["hooks"]["AfterTool"][0]["hooks"][0]["command"],
                    "copilot-cli": lambda d: d["hooks"]["postToolUse"][0]["bash"],
                    "antigravity-cli":
                        lambda d: d[after_call.ENTRY_NAME]["PostToolUse"][0]["hooks"][0]["command"]}
        self.assertEqual(set(pointers), set(after_call.AGENTS))
        for agent, read in pointers.items():
            command = read(json.loads(self.install(agent).read_text(encoding="utf-8")))
            self.assertIn("after_call.py", command)
            self.assertIn(f" record {agent} ", command)

    def test_install_keeps_what_the_file_holds(self):
        path = Path(after_call.AGENTS["gemini-cli"]["file"].format(**os.environ))
        path.parent.mkdir(parents=True)
        path.write_text('{"model": {"name": "x"}}', encoding="utf-8")
        self.install("gemini-cli")
        self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["model"], {"name": "x"})

    def test_an_agent_with_no_capture_is_left_alone(self):
        self.assertEqual(after_call.main(["install", "pi", *self.args]), 0)
        self.assertFalse(self.dir.exists())
        self.assertEqual(report("pi", self.dir, "-"), "")

    def record(self, payload):
        """The hook as an agent runs it: a process, the payload on stdin."""
        self.dir.mkdir(exist_ok=True)
        return subprocess.run(
            [sys.executable, "-I", str(SCRIPT), "record", "codex", "PostToolUse", *self.args],
            input=payload.encode(), capture_output=True, check=False)

    def test_the_hook_stores_a_clean_payload_and_stays_silent(self):
        done = self.record(json.dumps({"api_key": "DUMMY", "cwd": str(self.home / "project"),
                                       "tool_response": "out"}))
        self.assertEqual((done.returncode, done.stdout, done.stderr), (0, b"", b""))
        stored = list(self.dir.glob("codex-PostToolUse-*.json"))
        self.assertEqual(len(stored), 1)
        self.assertEqual(json.loads(stored[0].read_text(encoding="utf-8")),
                         {"api_key": "[redacted string]", "cwd": "/p", "tool_response": "out"})
        timing = json.loads(stored[0].with_suffix(".timing").read_text(encoding="utf-8"))
        self.assertGreaterEqual(timing["finished"] - timing["started"], after_call.WAIT_SECONDS)

    def test_a_payload_that_is_not_json_is_not_kept(self):
        self.assertEqual(self.record("SECRET-TEXT").returncode, 0)
        stored = next(self.dir.glob("codex-PostToolUse-*.json")).read_text(encoding="utf-8")
        self.assertNotIn("SECRET", stored)

    def test_a_hook_that_cannot_write_exits_zero_silently(self):
        done = subprocess.run(
            [sys.executable, "-I", str(SCRIPT), "record", "codex", "PostToolUse",
             str(self.root / "missing"), *self.args[1:]],
            input=b"{}", capture_output=True, check=False)
        self.assertEqual((done.returncode, done.stdout, done.stderr), (0, b"", b""))

    def test_report_prints_shape_and_never_a_value(self):
        self.install("codex")
        self.record(json.dumps({"tool_response": "VALUE-OF-OUTPUT"}))
        got = report("codex", self.dir, "-")
        self.assertTrue(got.startswith("::notice title=after-call codex PostToolUse::1 payload(s)"))
        self.assertIn("tool_response=string", got)
        self.assertNotIn("VALUE-OF-OUTPUT", got)
        self.assertEqual(got.count("\n"), 1)

    def test_not_captured_names_each_reason(self):
        self.dir.mkdir()
        log = self.root / "fake.log"
        got = report("codex", self.dir, log)
        self.assertIn("NOT CAPTURED", got)
        self.assertIn("not in the agent's hook file", got)
        self.install("codex")
        log.write_text("fake_openai: POST /v1/responses at=1.5 results=1\n", encoding="utf-8")
        self.assertIn("the fake API saw 1 tool", report("codex", self.dir, log))
        log.write_text("fake_openai: POST /v1/responses at=1.5 results=2\n", encoding="utf-8")
        self.assertIn("the hook never started", report("codex", self.dir, log))
        self.assertIn("unknown", report("codex", self.dir, "-"))
        self.assertIn("stopped in step `init`", report("codex", self.dir, log, "init"))
        log.write_text("model request at=1.5 results=1\n  result 1: run_command: {\"error\": "
                       "\"Encountered error in tool validation: invalid arguments\"}\n",
                       encoding="utf-8")
        self.assertIn("own tool validation", report("codex", self.dir, log))

    def test_report_on_an_unreadable_payload_is_a_notice_and_exit_zero(self):
        self.dir.mkdir()
        (self.dir / "codex-PostToolUse-1.json").write_text("{", encoding="utf-8")
        self.assertIn("NOT CAPTURED: report failed", report("codex", self.dir, "-"))

    def test_a_notice_cannot_start_a_second_workflow_command(self):
        self.assertEqual(after_call.escape("a\n::error::b%"), "a%0A::error::b%25")

    def test_bad_usage_is_64(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(after_call.main(["record", "only-one"]), 64)


class AgyProbe(unittest.TestCase):
    """agy_probe.py, which tells why Antigravity CLI ran no hook."""

    def setUp(self):
        self.probe = load("agy_probe")
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.hooks = self.root / "config" / "hooks.json"
        self.log = self.root / "probe.log"

    def tearDown(self):
        self.tmp.cleanup()

    def quietly(self, *argv, stdin="", code=0):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            old = sys.stdin
            sys.stdin = io.StringIO(stdin)
            try:
                got = self.probe.main(list(argv))
            finally:
                sys.stdin = old
        self.assertEqual(got, code)
        return out.getvalue()

    def test_install_keeps_other_entries_and_uses_the_documented_forms(self):
        self.hooks.parent.mkdir(parents=True)
        self.hooks.write_text('{"openmoat": {"enabled": true}}', encoding="utf-8")
        self.quietly("install", str(self.hooks), str(self.log))
        doc = json.loads(self.hooks.read_text(encoding="utf-8"))
        self.assertEqual(doc["openmoat"], {"enabled": True})
        entry = doc["moat-ci-probe"]
        self.assertTrue(entry["enabled"])
        self.assertIn("command", entry["SessionStart"][0])
        self.assertEqual(entry["PreToolUse"][0]["matcher"], "run_command")
        self.assertEqual(entry["PostToolUse"][0]["matcher"], "")

    def test_record_keeps_field_names_and_answers_each_event(self):
        payload = json.dumps({"toolCall": {"name": "run_command", "args": {"CommandLine": "s3cret"}},
                              "stepIdx": 1})
        got = self.quietly("record", "PreToolUse", str(self.log), stdin=payload)
        self.assertEqual(json.loads(got), {"decision": "allow"})
        self.assertEqual(json.loads(self.quietly("record", "SessionStart", str(self.log),
                                                 stdin="not json")), {})
        text = self.log.read_text(encoding="utf-8")
        self.assertIn("PreToolUse tool=run_command fields=stepIdx,toolCall\n", text)
        self.assertIn("SessionStart tool=- fields=<not json>\n", text)
        self.assertNotIn("s3cret", text)

    def test_report_tells_the_causes_apart(self):
        captured = self.root / "captured"
        captured.mkdir()
        cases = (([], "no hook ran at all"),
                 (["SessionStart", "PreInvocation"], "fires no tool event"),
                 (["SessionStart", "PreToolUse"], "the matcher first"),
                 (["PostToolUse"], "does not send PreToolUse"))
        for events, want in cases:
            self.log.write_text("".join(f"{e} tool=- fields=\n" for e in events), encoding="utf-8")
            got = self.quietly("report", str(self.log), str(captured))
            self.assertIn(want, got)
            self.assertTrue(got.startswith("::notice title=agy hook probe::"), got)
        (captured / "antigravity-cli-1-2.json").write_text("{}", encoding="utf-8")
        self.assertIn("OpenMoat's PreToolUse entry ran",
                      self.quietly("report", str(self.log), str(captured)))

    def test_bad_usage_is_64(self):
        self.quietly("record", "only-one", code=64)


if __name__ == "__main__":
    unittest.main()
