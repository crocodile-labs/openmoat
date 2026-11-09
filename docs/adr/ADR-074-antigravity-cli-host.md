# ADR-074: Antigravity CLI host, built from the documentation

Status: accepted · Date: 2026-11-09

## Context

Google's sign-in moved from Gemini CLI to the Antigravity CLI (`agy`) on 2026-06-18, so
OpenMoat's Gemini CLI adapter does not cover Google sign-in users. `agy` has a `PreToolUse`
hook of its own, with a file layout no other agent uses: each top-level key of
`~/.gemini/config/hooks.json` is a named hook, holding `enabled` and one list per event.

The only source available when this adapter was written is the official documentation
(<https://antigravity.google/docs/hooks?tab=cli> and its sandbox, permissions, MCP, settings,
install and CLI reference pages, read 2026-11-09), which states no version. It does not say
what happens when a hook crashes, times out or prints bad JSON, what the exit codes mean, how
hook files merge, whether MCP or subagent calls fire hooks, or what name a hook receives for an
MCP tool. `agy` has not been run here.

## Decision

1. **A new layout, one place.** The `HookFile` trait gains `section()` (the object holding the
   event lists, `hooks` by default) and `section_switch()`/`turned_off()`, and the document
   code reads them rather than naming `hooks`. Antigravity CLI's layout, `hook_file::Named`,
   names `openmoat`; `init` writes `"enabled": true` and repairs a `false`, and `HookState::TurnedOff`
   reports it as `not protected`.
2. **`defer` answers `allow`.** `decision` is documented as required, so "no output" is not a
   documented answer. `allow` is documented as deferring to the next hook or the default
   policy, which is what `defer` means. `auto_approve` is never sent.
3. **`review` answers `force_ask`.** It always prompts and ignores cached permissions, so a saved
   "Always Allow" cannot answer a review. Where `settings.json` sets
   `toolPermission: always-proceed` (what `--dangerously-skip-permissions` corresponds to, which
   "auto-approves all tool permission requests") a review is a deny, as for Hermes Agent's YOLO.
   `Reviews::Unseen` gains `file`, so a host's "approves unseen" setting can live outside its
   hook file. The flag itself cannot be seen.
4. **The tools are mapped by what they do; what is not documented is held back.** Every
   documented tool is mapped. `manage_task` with `send_input` is typed input (`Unchecked`, as for
   GitHub Copilot CLI's `write_bash`). `schedule`, `define_subagent` and `invoke_subagent` are
   `Unchecked` around `UnknownTool`: the first runs a prompt later, the second writes a system
   prompt and tool grants for a later agent, and whether the third's calls reach the hook is not
   documented. A tool not listed is `UnknownTool`, never allowed silently.
5. **The hook-failure case is named, not guessed.** Antigravity CLI has no documented fail-closed
   setting and its failure behaviour is undocumented. `openmoat guard` denies and exits 2 on every
   error it can catch; the host's behaviour for a guard that cannot start or times out is taken
   to be that the call runs. `HostSpec::limit` and `HOST.md` say so; `openmoat status` reports
   `hook only`.
6. **No `PostToolUse` hook.** Its documented payload carries `toolCall`, `stepIdx` and `error` but
   no output, so there is nothing for the injected-input check (ADR-057, ADR-063) to read.
7. **Project files are the attacker's.** A workspace's `.agents/hooks.json`, `.agents/mcp_config.json`
   and `.agents/plugins` are `kernel-self`; `status` and `doctor` warn about them, a project entry
   that sets `openmoat.enabled` off is reported, and a write leaving one is denied, as for the
   other hosts' project settings.

## Consequences

The adapter ships unverified against a running `agy`. Its fixtures are documented shapes, marked
as such, and the weekly `latest agents` job installs `agy`, captures real payloads and drives a
model turn at a fake Gemini API, which only CI can run. When the first capture lands, the fixtures
are replaced and this ADR's assumptions are checked against it; any that do not hold need a new ADR.

Where the documentation is silent, OpenMoat errs toward review or a stated limit: agents using
`--dangerously-skip-permissions` get no prompt for a `review`, and an unsettled hook failure may run
a call. People relying on `agy` should read `HOST.md`'s gaps and run it under `openmoat run` or
with its own sandbox (`enableTerminalSandbox`).
