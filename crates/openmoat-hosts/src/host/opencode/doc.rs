//! What the docs say about OpenCode: its README row and its rows of the "Host
//! tool mapping" table (`tests/docs.rs` generates both, and checks that every
//! tool name `tools.rs` matches has a row).

use crate::contract::{HostDocs, ToolRow};

pub(super) const DOCS: HostDocs = HostDocs {
    hooked_by: "OpenMoat's plugin on OpenCode 1's `tool.execute.before` hook",
    protection: "hook only",
    tools: TOOLS,
};

const TOOLS: &[ToolRow] = &[
    ToolRow::new(
        "`bash`",
        "`command`, run after a `cd` to `workdir` when it names one; on Windows, where it may \
         be Git Bash, PowerShell or `cmd`, left to OpenCode",
        "`Shell` / `ForeignShell`",
    ),
    ToolRow::new(
        "`read`, `lsp` / `write`, `edit` / `apply_patch`",
        "`filePath`, a relative one joined to the instance directory (`~` is not expanded) \
         (`write` `content` for provenance) / every file `patchText` adds, changes, moves or \
         deletes",
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
        "`<server>_<tool>` of a server named under `mcp`; `read_mcp_resource`",
        "decided as `mcp__<server>__<tool>`, the longest server name that begins it when \
         several do, and `args`; `server`, `uri` as for Claude Code's `ReadMcpResourceTool`",
        "`McpTool`",
    ),
    ToolRow::new(
        "`task`, `todowrite`, `skill`, `question`, `invalid`, `execute` (Code Mode), \
         `list_mcp_resources`, `list_mcp_resource_templates`",
        "—",
        "none: `ungoverned`",
    ),
    ToolRow::new(
        "any other tool (a plugin's or a custom tool's)",
        "decided as an MCP tool of that name, every path, URL and command in its arguments \
         checked",
        "`McpTool`",
    ),
];
