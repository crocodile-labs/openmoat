# openmoat-hosts

Host adapters for [OpenMoat](https://github.com/crocodile-labs/openmoat): the only
code that knows each agent's hook wire format.

An adapter turns a host payload into a `HookRequest` (session, tool, normalised
`Action`) and a `Decision` back into the host's response document. Adapters never
decide; `openmoat-core` does.

Supported today: Claude Code and Codex (shared `PreToolUse` contract,
`hookSpecificOutput.permissionDecision`), Claude Code `ConfigChange`, and Cursor
(`beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, `preToolUse`;
`{"permission": …}` responses). Golden payloads live in `crates/openmoat-hosts/src/host/<module>/fixtures`.

Adding a host: see
[docs/ADDING_AN_AGENT.md](https://github.com/crocodile-labs/openmoat/blob/main/docs/ADDING_AN_AGENT.md).
