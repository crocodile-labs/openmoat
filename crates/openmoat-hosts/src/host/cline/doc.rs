//! What the docs say about Cline: its README row and its rows of the "Host
//! tool mapping" table (`tests/docs.rs` generates both, and checks that every
//! tool name `tools.rs` matches has a row).

use crate::contract::{HostDocs, ToolRow};

pub(super) const DOCS: HostDocs = HostDocs {
    hooked_by: "OpenMoat's `PreToolUse` hook script in `~/.cline/hooks`",
    protection: "hook only",
    tools: TOOLS,
};

const TOOLS: &[ToolRow] = &[
    ToolRow::new(
        "`run_commands`",
        "`commands` (lines, or `{command, args}` run without a shell), in every shape Cline \
         accepts; several are decided together, each in a subshell, and held for review when one \
         cannot be read alone",
        "`Shell` (`ForeignShell` for PowerShell on Windows)",
    ),
    ToolRow::new(
        "`read_files`",
        "every `path` (`file_path`, `filePath`) of `files`, `file_paths` or `paths`",
        "`FsRead` / `ReadFiles`",
    ),
    ToolRow::new("`editor`", "`path`", "`FsWrite`"),
    ToolRow::new("`apply_patch`", "`input`: every file the patch touches", "`Patch`"),
    ToolRow::new("`search_codebase`", "the workspace root", "`FsRead`"),
    ToolRow::new(
        "`fetch_web_content`",
        "`requests[].url`: one URL; several are checked as an unknown tool's hosts",
        "`Fetch` / `UnknownTool`",
    ),
    ToolRow::new(
        "`<server>__<tool>`",
        "recorded as `mcp__<server>__<tool>`; a browser server's call that only opens a page \
         is that page's open (ADR-047), any other is checked for every path, URL and command \
         its arguments name",
        "`McpTool`",
    ),
    ToolRow::new("`ask_question`, `submit_and_exit`", "—", "none: `ungoverned`"),
    ToolRow::new(
        "any other tool (`skills`, subagent and team tools, a plugin's)",
        "tool name and arguments",
        "`UnknownTool` (`tool.unknown`)",
    ),
    ToolRow::new(
        "`web_search` (the provider's)",
        "—",
        "not hooked: the provider runs it",
    ),
];
