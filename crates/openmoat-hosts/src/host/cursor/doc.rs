//! What the docs say about Cursor: its README row and its rows of the "Host
//! tool mapping" table (`tests/docs.rs` generates both, and checks that every
//! tool name `cursor.rs` and `pre_tool.rs` match has a row).

use crate::contract::{HostDocs, ToolRow};

pub(super) const DOCS: HostDocs = HostDocs {
    hooked_by: "`beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile` and `preToolUse` \
         hooks, fail-closed",
    protection: "hook + OS sandbox (macOS, Linux); hook only on Windows",
    tools: TOOLS,
};

const TOOLS: &[ToolRow] = &[
    ToolRow::new("`beforeShellExecution`", "`command`", "`Shell`"),
    ToolRow::new("`beforeReadFile`", "`file_path`", "`FsRead`"),
    ToolRow::new(
        "`beforeMCPExecution`",
        "`mcp_server_name`, `tool_name`, `tool_input`",
        "`McpTool` `mcp__<server>__<tool>`",
    ),
    ToolRow::new("`preToolUse` `Read`", "`file_path`", "`FsRead`"),
    ToolRow::new(
        "`preToolUse` `Write`, `Edit`, `MultiEdit`, `StrReplace`, `Delete`",
        "`file_path`",
        "`FsWrite`",
    ),
    ToolRow::new(
        "`preToolUse` `Grep`, `Glob`",
        "every path in `path`, `file_path`, `target_file`, `target_directory`, \
         `target_directories`, else the working directory",
        "`FsRead`, `ReadFiles`",
    ),
    ToolRow::new(
        "`preToolUse` listing and search tools (`LS`, `ListDir`, `list_dir`, `SemanticSearch`, \
         `codebase_search`, `grep_search`, `file_search`, `read_file`) that name a path under \
         those keys",
        "every such path",
        "`FsRead`, `ReadFiles`",
    ),
    ToolRow::new(
        "`preToolUse`, any other tool that names a path under those keys (an editing tool \
         need not have a write verb in its name)",
        "every such path",
        "`FsWrite`, `Patch`",
    ),
    ToolRow::new("`preToolUse` `WebFetch`", "`url`", "`Fetch`"),
    ToolRow::new(
        "`preToolUse` `WebSearch`",
        "`query` (`allowed_domains` and `blocked_domains` only filter results)",
        "`WebSearch`",
    ),
    ToolRow::new(
        "`preToolUse`, any other tool that names no path key, except to-do tools \
         (`TodoWrite`, `TodoRead`, `todo_write`: ungoverned)",
        "tool name",
        "`UnknownTool` (`tool.unknown`)",
    ),
    ToolRow::new(
        "`preToolUse` `Shell`, `Task`, `MCP:<tool>` (`beforeShellExecution` and \
         `beforeMCPExecution` decide shell and MCP calls; a `Task` subagent's own calls are \
         hooked)",
        "—",
        "none: `ungoverned`",
    ),
];
