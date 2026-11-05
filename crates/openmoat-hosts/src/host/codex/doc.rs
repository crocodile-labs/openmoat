//! What the docs say about Codex: its README row and its rows of the "Host
//! tool mapping" table (`tests/docs.rs` generates both). The mapping is
//! [`crate::wire::pre_tool_use`]'s, shared with Claude Code.

use crate::contract::{HostDocs, ToolRow};

pub(super) const DOCS: HostDocs = HostDocs {
    hooked_by: "`PreToolUse` hook in `hooks.json`; a `review` becomes a deny you approve with \
         `openmoat allow --last`",
    protection: "hook + OS sandbox",
    tools: TOOLS,
};

const TOOLS: &[ToolRow] = &[
    ToolRow::new(
        "`Bash`",
        "`command`; a start of a shell, REPL, editor or login without its own commands, \
         which `write_stdin` types into unhooked",
        "`Shell`; that start `Unchecked` (review)",
    ),
    ToolRow::new(
        "`read_mcp_resource`",
        "`server`, `uri` (a `file:` URI as its file)",
        "`McpTool` (`read_resource`)",
    ),
    ToolRow::new(
        "`view_image`",
        "`path` (an `http(s)` URL fetched)",
        "`FsRead` or `Fetch`",
    ),
    ToolRow::new(
        "`apply_patch`",
        "`command` (the patch envelope)",
        "`Patch`",
    ),
    ToolRow::new(
        "`mcp__<server>__<tool>`",
        "tool name and arguments",
        "`McpTool`",
    ),
    ToolRow::new(
        "any other tool (`update_plan`, `list_mcp_resources`, …)",
        "—",
        "none: `ungoverned`",
    ),
];
