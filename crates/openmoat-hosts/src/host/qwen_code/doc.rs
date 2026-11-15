//! What the docs say about Qwen Code: its README row and its rows of the
//! "Host tool mapping" table (`tests/docs/` generates both, and checks that
//! every tool name `tools.rs` matches has a row).

use crate::contract::{HostDocs, ToolRow};

pub(super) const DOCS: HostDocs = HostDocs {
    hooked_by: "`PreToolUse` hook in `settings.json` (preview)",
    protection: "hook only",
    tools: TOOLS,
};

const TOOLS: &[ToolRow] = &[
    ToolRow::new(
        "`run_shell_command`",
        "`command`, after a `cd` to `directory`; PowerShell on Windows",
        "`Shell`; `ForeignShell` on Windows",
    ),
    ToolRow::new(
        "`read_file`, `list_directory` / `write_file`, `edit`",
        "`file_path`, `path` / `file_path` (`write_file` `content`, `edit` `old_string` and \
         `new_string` for provenance)",
        "`FsRead` / `FsWrite`",
    ),
    ToolRow::new(
        "`glob`, `grep_search`",
        "`path`, else `cwd`; for `glob` also the directory an absolute `pattern` names and \
         where a relative one climbs to",
        "`FsRead`, `ReadFiles`",
    ),
    ToolRow::new(
        "`web_fetch` / `web_search`",
        "`url` / `query` (the key `web_search` takes was not verified: a call without it is \
         refused)",
        "`Fetch` / `WebSearch`",
    ),
    ToolRow::new(
        "`read_mcp_resource`",
        "`uri`: a `file:` URI as its path; any other URI",
        "`FsRead`; `UnknownTool`",
    ),
    ToolRow::new(
        "MCP tool (`mcp__<server>__<tool>`)",
        "server, tool and arguments",
        "`McpTool`",
    ),
    ToolRow::new(
        "`todo_write`, `ask_user_question`, `enter_plan_mode`, `exit_plan_mode`, `tool_search`",
        "—",
        "none: `ungoverned`",
    ),
    ToolRow::new(
        "any other tool (`agent`, `skill`, `exec`, `notebook_edit`, `save_memory`, `monitor`, \
         `enter_worktree`, a discovered tool)",
        "tool name and arguments",
        "`UnknownTool` (`tool.unknown`)",
    ),
];
