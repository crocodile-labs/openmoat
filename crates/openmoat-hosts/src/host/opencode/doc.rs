//! What the docs say about OpenCode: its README row and its rows of the "Host
//! tool mapping" table (`tests/docs.rs` generates both, and checks that every
//! tool name `tools/v1.rs` and `tools/v2.rs` match has a row).

use crate::contract::{HostDocs, ToolRow};

pub(super) const DOCS: HostDocs = HostDocs {
    hooked_by: "OpenMoat's plugin on OpenCode 1's `tool.execute.before` (1.3.4 and later) \
         and OpenCode 2's `execute.before` hook",
    protection: "hook only",
    tools: TOOLS,
};

const TOOLS: &[ToolRow] = &[
    ToolRow::new(
        "`bash` (1), `shell` (2)",
        "`command`, run after a `cd` to `workdir` when it names one; on Windows, where it may \
         be Git Bash, PowerShell or `cmd`, left to OpenCode",
        "`Shell` / `ForeignShell`",
    ),
    ToolRow::new(
        "`read`, `lsp` (1) / `write`, `edit` / `apply_patch` (1), `patch` (2)",
        "`filePath` (1) or `path` (2), a relative one joined to the instance directory (`~` \
         is expanded by OpenCode 2 only) (`write` `content` for provenance) / every file \
         `patchText` adds, changes, moves or deletes",
        "`FsRead` / `FsWrite` / `Patch`",
    ),
    ToolRow::new(
        "`glob`, `grep`",
        "`path`, else the instance directory; the directory of an absolute `pattern` \
         (`glob`) or `include` (`grep`), and where a `..` in it climbs to",
        "`FsRead`, `ReadFiles`",
    ),
    ToolRow::new("`webfetch`", "`url`", "`Fetch`"),
    ToolRow::new("`websearch`", "`query`", "`WebSearch`"),
    ToolRow::new(
        "`opencode_worktree_remove` (2)",
        "`directory`, which it deletes",
        "`FsWrite`",
    ),
    ToolRow::new(
        "`<server>_<tool>` of a server named under `mcp` (`mcp.servers` in 2); \
         `read_mcp_resource`",
        "decided as `mcp__<server>__<tool>`, the longest server name that begins it when \
         several do, and its arguments; `server`, `uri` as for Claude Code's \
         `ReadMcpResourceTool`",
        "`McpTool`",
    ),
    ToolRow::new(
        "`task`, `invalid`, `list_mcp_resource_templates` (1); `subagent`, \
         `opencode_session_rename`, `opencode_worktree_list`, `opencode_models` (2); \
         `todowrite`, `skill`, `question`, `execute` (Code Mode), `list_mcp_resources`",
        "—",
        "none: `ungoverned`",
    ),
    ToolRow::new(
        "any other tool (a plugin's, a custom tool's, OpenCode 2's other `opencode_*` tools)",
        "decided as an MCP tool of that name, every path, URL and command in its arguments \
         checked",
        "`McpTool`",
    ),
];
