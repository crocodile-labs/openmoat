//! What the docs say about Codex: its README row and its rows of the "Host
//! tool mapping" table (`tests/docs.rs` generates both). The mapping is
//! [`crate::wire::pre_tool_use`]'s, shared with Claude Code.

use crate::contract::{HostDocs, ToolRow};

pub(super) const DOCS: HostDocs = HostDocs {
    hooked_by: "`PreToolUse` hook in `hooks.json`; an `ask` becomes a deny you approve with \
         `openmoat allow --last`",
    protection: "hook + OS sandbox",
    tools: TOOLS,
};

const TOOLS: &[ToolRow] = &[
    ToolRow::new("`Bash`", "`command`", "`Shell`"),
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
        "any other tool (`update_plan`, …)",
        "—",
        "none: `ungoverned`",
    ),
];
