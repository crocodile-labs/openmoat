//! What the docs say about GitHub Copilot CLI: its README row and its rows of
//! the "Host tool mapping" table (`tests/docs.rs` generates both, and checks
//! that every tool name `tools.rs` matches has a row).

use crate::contract::{HostDocs, ToolRow};

pub(super) const DOCS: HostDocs = HostDocs {
    hooked_by: "`preToolUse` hook in a hook file of OpenMoat's own",
    protection: "hook only",
    tools: TOOLS,
};

const TOOLS: &[ToolRow] = &[
    ToolRow::new(
        "`bash`, `local_shell` / `write_bash`",
        "`command` (asks when it leaves the shell in a directory OpenMoat cannot know) / `input` \
         (typed into a running shell: asks); `toolArgs` is parsed when it is a JSON string",
        "`Shell` / `Unchecked`",
    ),
    ToolRow::new(
        "`powershell` / `write_powershell`",
        "`command` / `input` (asks)",
        "`ForeignShell` / `Unchecked`",
    ),
    ToolRow::new(
        "`view` / `create`, `edit`, `str_replace`",
        "`path` (`create` `file_text` for provenance)",
        "`FsRead` / `FsWrite`",
    ),
    ToolRow::new(
        "`str_replace_editor`",
        "`path`; `command` `view` reads, any other command writes",
        "`FsRead` / `FsWrite`",
    ),
    ToolRow::new(
        "`apply_patch`",
        "the patch text: `toolArgs` itself, or its `input` or `patch`",
        "`Patch`",
    ),
    ToolRow::new(
        "`grep`, `rg`, `glob`",
        "every path in `paths` and `path`, the directory of an absolute `glob` `pattern`, else \
         the working directory",
        "`FsRead`, `ReadFiles`",
    ),
    ToolRow::new(
        "`web_fetch` / `web_search`",
        "`url` / `query`",
        "`Fetch` / `WebSearch`",
    ),
    ToolRow::new(
        "`ask_user`, `report_intent`, `task`, `think`, `update_todo`, \
         `read_bash`/`stop_bash`/`list_bash` and their PowerShell forms",
        "—",
        "none: `ungoverned`",
    ),
    ToolRow::new(
        "any other tool, MCP tools included (`<server>-<tool>`; the payload does not mark them)",
        "tool name and arguments, read as an unknown tool's (paths and URLs by key and by look, \
         commands)",
        "`McpTool`",
    ),
];
