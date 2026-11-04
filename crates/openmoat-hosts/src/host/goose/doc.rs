//! What the docs say about goose: its README row and its rows of the "Host
//! tool mapping" table (`tests/docs.rs` generates both, and checks that every
//! tool name `tools.rs` matches has a row).

use crate::contract::{HostDocs, ToolRow};

pub(super) const DOCS: HostDocs = HostDocs {
    hooked_by: "`PreToolUse` hook in OpenMoat's plugin, `~/.agents/plugins/openmoat/hooks/\
         hooks.json`, with `on_failure: block`",
    protection: "hook only",
    tools: TOOLS,
};

const TOOLS: &[ToolRow] = &[
    ToolRow::new(
        "`shell`",
        "`command`, in the session's `working_dir`; `cmd` (or `GOOSE_SHELL`) on Windows",
        "`Shell`; `ForeignShell` on Windows",
    ),
    ToolRow::new(
        "`write`, `edit` / `tree`, `analyze`",
        "`path` (`write` `content`, `edit` `before` and `after` for provenance); a relative \
         path is the session's `working_dir`'s",
        "`FsWrite` / `FsRead`",
    ),
    ToolRow::new(
        "`read_image`",
        "`source`: an http(s) URL goose downloads, else a path",
        "`Fetch`; `FsRead`",
    ),
    ToolRow::new(
        "`execute_javascript` (Code Mode)",
        "the arguments, and a review: the tools the script calls do not reach the hook",
        "`Unchecked` `UnknownTool`",
    ),
    ToolRow::new(
        "`load`, `delegate` (its subagent's calls fire the hook), `load_skill`",
        "tool name and arguments",
        "`UnknownTool` (`tool.unknown`)",
    ),
    ToolRow::new(
        "extension tool (`<extension>__<tool>`), the built-in ones (`todo__…`, \
         `extensionmanager__…`) included",
        "tool name and `tool_input`, recorded as `mcp__<extension>__<tool>`",
        "`McpTool`",
    ),
    ToolRow::new(
        "`list_functions`, `get_function_details`",
        "—",
        "none: `ungoverned`",
    ),
    ToolRow::new(
        "any other unprefixed tool",
        "tool name and arguments",
        "`UnknownTool` (`tool.unknown`)",
    ),
];
