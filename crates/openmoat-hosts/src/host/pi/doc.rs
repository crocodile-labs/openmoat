//! What the docs say about pi: its README row and its rows of the "Host tool
//! mapping" table (`tests/docs.rs` generates both, and checks that every tool
//! name `tools.rs` matches has a row).

use crate::contract::{HostDocs, ToolRow};

pub(super) const DOCS: HostDocs = HostDocs {
    hooked_by: "OpenMoat's extension on pi's `tool_call` event",
    protection: "hook only",
    tools: TOOLS,
};

const TOOLS: &[ToolRow] = &[
    ToolRow::new(
        "`bash` / `powershell`",
        "`command`",
        "`Shell` / `ForeignShell`",
    ),
    ToolRow::new(
        "`read` / `write`, `edit`",
        "`path` as pi resolves it: Unicode spaces as spaces, a leading `@` dropped, a `file:` \
         URL as its path, on Windows `/c/…`, `/mnt/c/…`, `/cygdrive/c/…` as `C:/…`; a relative \
         path with no `cwd` is an adapter error (`write` `content` for provenance)",
        "`FsRead` / `FsWrite`",
    ),
    ToolRow::new(
        "`grep`, `ls` / `find`",
        "`path`, else the working directory / the same, the directory of an absolute \
         `pattern`, and where a `..` in it climbs to",
        "`FsRead` / `FsRead`, `ReadFiles`",
    ),
    ToolRow::new(
        "`mcp__<server>__<tool>`; `read_mcp_resource`",
        "tool name and `input`; `server`, `uri` as for Claude Code's `ReadMcpResourceTool`",
        "`McpTool`",
    ),
    ToolRow::new(
        "`codemode`, `tool_search`, `list_mcp_resources`, `list_mcp_resource_templates`",
        "—",
        "none: `ungoverned`",
    ),
    ToolRow::new(
        "any other tool (an extension's)",
        "tool name",
        "`UnknownTool` (`tool.unknown`)",
    ),
];
