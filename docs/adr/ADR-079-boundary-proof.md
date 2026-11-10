# ADR-079: What each agent does when the hook fails, and coverage from tests

Status: accepted · Date: 2026-11-10 · Builds on ADR-004, ADR-033, ADR-064, ADR-076 and ADR-077

## Context

OpenMoat's guard fails closed on every error it can catch (ADR-004): a payload it cannot
read, a decision it cannot make in 30 s, a lock that drifted. What it cannot catch is a
hook that never answers: the binary is gone, the process is killed, the host's time limit
runs out, or the person turned the hook off. What happens to the call then is the agent's
choice, and it differs per agent. Until now each host spec said it in one line of prose
(`on_hook_failure`), the per-case table in `docs/THREAT_MODEL.md` §5 was written by hand,
`openmoat doctor` said nothing about it, and no test ran a real agent with the hook failing.

## Decision 1: hook failure is a typed host fact

1. **One fact per host, in its spec.** `HostSpec::hook_failure` is a `HookFailure`:
   - `fails`: the hook cannot start, crashes or exits non-zero without a decision;
   - `times_out`: it does not answer within `timeout_s`, the limit as `openmoat init`
     installs it (or OpenMoat's plugin's own 45 s for OpenClaw, pi and OpenCode);
   - `turned_off_by`: how a person or a project turns the hook off, when every call
     runs unchecked (no agent can block that case, so it is said, not typed);
   - `sources`: the vendor documentation, else the vendor source at a named release.

   Each outcome is a `FailureOutcome`: `Blocks`, `Runs`, `NotDocumented` (taken as
   `Runs`) or `BlocksFrom(version)`, for a host that blocks only when its entry carries
   a flag its newer versions read (Claude Code's `onFailure: "block"` from 2.1.295, which
   `openmoat init` writes only when every copy found reads it).
2. **Why in the spec and not one table file.** The brief asked for one table rather than
   constants spread over files. The host list is already that table: every host's facts
   are one field of one type, read through `Host::EVERY`, and the architecture tests
   forbid naming a host outside its own module. A separate table keyed by host id would
   break that rule and could fall out of step with the list. The table people read is
   generated from the field (`docs/LIMITS.md` "If the hook fails"), and a registry test
   refuses a host with no `turned_off_by` or no `https://` source.
3. **`on_hook_failure` stays** as the prose detail (`THREAT_MODEL.md` §5's generated
   list). The typed fact is what code reads.

### What each host's facts come from

Read on 2026-11-10 unless the source names a release. "Unverified" means nothing here
was tried against a running agent; the weekly job (Decision 3) is the first to.

| Host | Fails | Times out | Source |
|---|---|---|---|
| Claude Code | blocks from 2.1.295 | blocks from 2.1.295 | [hooks](https://code.claude.com/docs/en/hooks): "Non-blocking error … The action goes ahead, except for hooks whose failure blocks the action"; "Requires Claude Code v2.1.295 or later"; default timeout 600 s |
| Codex | runs | runs | [hooks](https://learn.chatgpt.com/docs/hooks) does not say for a local hook; [`command_runner.rs`](https://github.com/openai/codex/blob/rust-v0.166.0/codex-rs/hooks/src/engine/command_runner.rs#L417) at rust-v0.166.0 |
| Cursor | blocks | blocks | [hooks](https://cursor.com/docs/agent/hooks): `failClosed` blocks on "crash, timeout, non-zero exit code, no output"; a missing command is not stated |
| OpenClaw | blocks | blocks | [hook reference](https://docs.openclaw.ai/plugins/hooks/reference) (`before_tool_call` fails closed) and OpenMoat's own plugin |
| GitHub Copilot CLI | blocks | runs | [hooks reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-hooks-reference): "a crash or non-zero exit (including exit 2) denies the tool call"; "Command hook timeouts are always fail-open, even for preToolUse"; a hook that cannot start is not stated separately |
| pi | blocks | blocks | [extensions](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/extensions.md): "`tool_call` errors block the tool (fail-safe)"; the 45 s limit is OpenMoat's extension's |
| Gemini CLI | runs | runs | [hooks reference](https://geminicli.com/docs/hooks/reference/) and `hookRunner.ts` of 0.65.0 |
| OpenCode | blocks | blocks | [server plugins](https://opencode.ai/docs/build/plugins/server) does not say; OpenCode's source (1.19.4, 2.2.0) does: unverified against a running OpenCode |
| Hermes Agent | blocks | blocks | [`shell_hooks.py`](https://github.com/NousResearch/hermes-agent/blob/v0.22.5/agent/shell_hooks.py) at v0.22.5 (`fail_closed`, `plugins.hook_callback_timeout`) |
| Cline CLI | blocks | runs | [`hook-file-hooks.ts`](https://github.com/cline/cline/blob/cli-v3.0.74/sdk/packages/core/src/hooks/hook-file-hooks.ts), [`subprocess-runner.ts`](https://github.com/cline/cline/blob/cli-v3.0.74/sdk/packages/core/src/hooks/subprocess-runner.ts) at cli-v3.0.74 |
| goose | blocks | blocks | [`hooks/mod.rs`](https://github.com/aaif-goose/goose/blob/v1.57.0/crates/goose/src/hooks/mod.rs) at v1.57.0 (`on_failure: block`) |
| Antigravity CLI | not documented | not documented | [hooks](https://antigravity.google/docs/hooks?tab=cli): a 30 s default timeout and `enabled: false`, nothing on a failed hook |
| Continue CLI | runs | runs | [`hookRunner.ts`](https://github.com/continuedev/continue/blob/main/extensions/cli/src/hooks/hookRunner.ts); the released `cn` fires no hook |

## Decision 2: `doctor` names an agent that fails open

1. `openmoat status --format json` carries `hook_failure` for each agent whose hook is in
   place: `fails`, `times_out` (`blocks`, `runs`, `not-documented`), `timeout_s`,
   `turned_off_by`, `sources`, and `fails_open`, the cases in which the call runs. A
   `BlocksFrom` is resolved with the same check `openmoat init` uses to decide whether to
   write the flag, so the answer matches the entry `init` wrote.
2. `openmoat doctor` prints one row under such an agent: `fails open: runs the call when
   the hook <cases>; start it with openmoat run, whose OS sandbox holds when the hook does
   not (docs/SANDBOX.md), and add require.run: full-boundary to the policy so openmoat run
   refuses to start without it`. `--format json` has it as a note.
3. **Information, not a problem.** The hook is what the agent offers; nothing the person
   can set in the agent closes it, so it neither changes the exit code nor counts in the
   footer, as the `OS sandbox:` row of ADR-076 does not. `openmoat status` keeps its text
   output as it was; its JSON has the facts.
4. `require.run: full-boundary` does not make an agent run under `openmoat run`; it makes
   `openmoat run` refuse to start without its whole boundary (ADR-077). The row says so
   rather than suggest the setting alone protects anything.

## Decision 3: the weekly job proves the facts against the real agents

`scripts/ci/latest-agents.sh` gains a last step for every agent it starts with a model call.
`init` writes the hook naming a copy of the binary in the throwaway root; the step puts a
stand-in there, starts the agent once per case with one call that reads a probe file and
copies it into the project, then puts the binary back. The cases: `crash` (exit 1, nothing
printed), `missing` (no file) and `hang` (minutes past the time limit, only where the
limit is 120 s or less). The call ran when the probe's marker reaches the agent's output,
the fake API or the copy; it was blocked when the marker is nowhere and the hook started or
the agent sent the model a result of the call.

- A call that ran where the fact says the agent blocks **fails the job**.
- A call blocked where the fact says it runs or is not documented, and a case with no
  evidence either way, are **reported** in the job's annotations and `hook-failure.json`.
  A fact is changed only from the vendor's documentation or source, never from a run alone:
  one run of one version cannot say what the agent promises.
- Cursor (an account), Hermes Agent and OpenCode 2 (no model call driven) and `hang` where
  the limit is longer than 120 s are recorded as not run.

## Decision 4: the OWASP table states its evidence

The OWASP agentic table in `docs/COVERAGE.md` (from #777) was generated from the fixtures,
but a risk's status (`covered`, `partial`) was a hand-written claim: five risks showed no
evidence at all, and the end-to-end tests that do test some of them were not linked.

1. **Evidence is fixtures and named end-to-end tests.** A risk's evidence is every attack
   and review fixture whose threat class maps to it (as before), and every end-to-end test
   of `crates/openmoat-cli/tests/e2e/` marked `// coverage: ASI<nn>` above its `#[test]`.
   The conformance suite reads both and writes, in `docs/COVERAGE.md`, the test count in
   the table and a section listing each risk's test names and fixture ids.
2. **No evidence, no claim.** A risk with neither shows `not tested` in the status column,
   whatever its declared status. A risk declared `covered` or `partial` with no evidence
   fails the suite, as does a marker naming an unknown risk or not followed by a test.
3. **The drift check is the one CI already runs:** the conformance suite (in the quality
   gate on every platform) fails when `docs/COVERAGE.md` differs from what it generates
   (`OPENMOAT_TEST_UPDATE_COVERAGE=1 cargo test -p openmoat-core --test conformance`). It
   is a Rust test beside the existing generator rather than a separate script, so the
   fixtures are parsed by the same code that runs them and no workflow changes.
4. **What a mark claims.** A mark says the test exercises part of the risk, not that the
   risk is handled; the reason column still says what is left out. ASI07 and ASI08 have no
   evidence and read `not tested`.

## Consequences

- A new host cannot be added without saying, with a source, what it does when the hook
  fails; the LIMITS table and `doctor` follow from that.
- `openmoat doctor` asks the installed Claude Code its version (cached, as `init` does)
  when its hook is in place, to resolve `BlocksFrom`.
- The hook-failure facts of OpenCode, Hermes Agent, the Cline CLI and goose rest on vendor
  source at a release, and the Antigravity CLI's on documentation that says nothing; only
  the weekly job's runs, read by a person, show what a running agent does.
- The Antigravity CLI is not recorded as blocking in any case. In a weekly run of
  Antigravity CLI 1.5.5 the agent ran its tools without starting OpenMoat's hook from
  `~/.gemini/config/hooks.json` at all, so until that is understood and fixed it is not
  protected by its hook, whatever the hook would answer; this ADR does not change how
  its hook is installed.
- The weekly job takes longer: up to three more agent runs per agent, one of which waits
  past a time limit of up to 120 s.
- The OWASP table can no longer say more than the tests show: a risk without a fixture
  class or a marked test reads `not tested`, and a new end-to-end test is linked to a risk
  only by its mark.
