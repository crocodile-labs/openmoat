# openmoat-hosts

Host adapters for [OpenMoat](https://github.com/crocodile-labs/openmoat): the only
code that knows each agent's hook wire format.

An adapter turns a host payload into a `HookRequest` (session, tool, normalised
`Action`) and a `Decision` back into the host's response document. Adapters never
decide; `openmoat-core` does.

Supported today: Claude Code and Codex (shared `PreToolUse` contract,
`hookSpecificOutput.permissionDecision`; Codex gets no output for an allow), Claude Code `ConfigChange`, Cursor
(`beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, `preToolUse`;
`{"permission": …}` responses), OpenClaw (`before_tool_call`, through OpenMoat's plugin),
GitHub Copilot CLI (`preToolUse`), pi (`tool_call`, through OpenMoat's extension), Gemini
CLI (`BeforeTool`), OpenCode 1 and 2 (`tool.execute.before` and `execute.before`, through
OpenMoat's plugin), Hermes Agent (`pre_tool_call`), the Cline CLI (`PreToolUse`, through
OpenMoat's hook script) and goose (`PreToolUse`, through OpenMoat's plugin); the Continue
CLI adapter waits for a
`cn` release that runs hooks. Golden payloads live in `crates/openmoat-hosts/src/host/<module>/fixtures`.

Adding a host: see
[docs/ADDING_AN_AGENT.md](https://github.com/crocodile-labs/openmoat/blob/main/docs/ADDING_AN_AGENT.md).
