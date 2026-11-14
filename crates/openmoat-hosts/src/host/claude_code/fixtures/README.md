# Claude Code fixtures

Payloads Claude Code sends `openmoat guard --host claude-code`, with paths
replaced by `/p` and `/Users/me`.

## Other agents running Claude Code's hook (ADR-095)

Built from the agents' source and documentation, not captured from a run:

| Fixture | Agent | Source |
|---|---|---|
| `grok-shell.json`, `grok-edit.json`, `grok-post-shell.json` | Grok Build | envelope and snake-case aliases: `xai-org/grok-build` at `2bdd1d6a`, `crates/codegen/xai-grok-hooks/src/event.rs` (`HookEventEnvelope`, `to_hook_json`); tool names `run_terminal_command`, `search_replace`: `matcher.rs` tests. The argument names of those tools were not read and are a guess (`command`, `file_path`) |
| `devin-exec.json`, `devin-read.json` | Devin CLI | <https://docs.devin.ai/cli/extensibility/hooks/overview> (the `exec` example) and <https://docs.devin.ai/cli/extensibility/hooks/lifecycle-hooks> (tool names); `read`'s argument name is a guess |

`cursor-grep.json` and `cursor-shell.json` are Cursor's (`from_cursor.rs`).
