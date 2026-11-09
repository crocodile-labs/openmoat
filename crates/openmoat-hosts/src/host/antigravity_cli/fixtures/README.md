# Antigravity CLI hook payloads

None of these fixtures is captured from a running Antigravity CLI. Each is built from the
documented shape, so a guess is never mistaken for a capture. The weekly real-agent job
(`scripts/ci/latest-agents.sh antigravity-cli`) copies the first real payloads it sees;
they replace these and this page then names each capture's version and date.

| Field | Source |
|---|---|
| `conversationId`, `workspacePaths`, `transcriptPath`, `artifactDirectoryPath`, `modelName`, `lastUserInput` | <https://antigravity.google/docs/hooks?tab=cli>, "All hooks receive", read 2026-11-09 (no version stated). |
| `toolCall` (`name`, `args`), `stepIdx` | The same page's `PreToolUse` section. |
| Tool names and argument names | The same page's tool list. |
| `call_mcp_tool`, `mcp_<server>_<tool>` | <https://antigravity.google/docs/mcp?tab=cli>; the page does not say what name a hook receives for an MCP tool, so `mcp_eager.json` is a guess. |

The values are made up (`/p` for the project, `/Users/me` for the home directory), as are
`multi_replace_file_content`'s chunk keys and `schedule`'s optional arguments, which the
documentation does not spell out.
