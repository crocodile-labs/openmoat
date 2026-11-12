//! What the docs say about Antigravity CLI: its README row and its rows of the
//! "Host tool mapping" table (`tests/docs/` generates both, and checks that
//! every tool name `tools.rs` matches has a row).

use crate::contract::{HostDocs, ToolRow};

pub(super) const DOCS: HostDocs = HostDocs {
    // A preview host until a real run shows the hook deciding a call (`HOST.md`,
    // "The first real run").
    hooked_by: "`PreToolUse` hook in `~/.gemini/config/hooks.json`; **preview**: the hook \
         is new; use `openmoat run` for an OS boundary until it leaves preview",
    protection: "hook only",
    tools: TOOLS,
};

const TOOLS: &[ToolRow] = &[
    ToolRow::new(
        "`run_command`",
        "`CommandLine`, after a `cd` to `Cwd`; needs review when it names an earlier \
         terminal (`RequestedTerminalID`); the Windows shell is not documented",
        "`Shell`, `Unchecked`; `ForeignShell` on Windows",
    ),
    ToolRow::new(
        "`view_file`, `list_dir` / `write_to_file`, `replace_file_content`, \
         `multi_replace_file_content`",
        "`AbsolutePath`, `DirectoryPath` / `TargetFile`",
        "`FsRead` / `FsWrite`",
    ),
    ToolRow::new(
        "`find_by_name`, `grep_search`",
        "`SearchDirectory`, `SearchPath`, and the directory `Pattern` or `Includes` names \
         before its first wildcard and where a `..` climbs to",
        "`FsRead`, `ReadFiles`",
    ),
    ToolRow::new(
        "`read_url_content` / `search_web`",
        "`Url` / `query`",
        "`Fetch` / `WebSearch`",
    ),
    ToolRow::new(
        "`generate_image`",
        "each of `ImagePaths`, read and sent to the model; with none, the tool itself",
        "`ReadFiles`; `UnknownTool`",
    ),
    ToolRow::new(
        "`manage_task` with `send_input`",
        "`Input` typed into a running shell",
        "`Unchecked` around `Shell` (needs review)",
    ),
    ToolRow::new(
        "`schedule`, `define_subagent`, `invoke_subagent`",
        "tool name and arguments; whether a subagent's calls reach the hook is not documented",
        "`Unchecked` around `UnknownTool` (needs review)",
    ),
    ToolRow::new(
        "`call_mcp_tool`",
        "`ServerName`, `ToolName`, `Arguments`",
        "`McpTool` as `mcp__<server>__<tool>`",
    ),
    ToolRow::new(
        "MCP tool (`mcp_<server>_<tool>`)",
        "tool name and arguments; the name cannot be split, and the hook payload's name is \
         not documented",
        "`McpTool` as written",
    ),
    ToolRow::new(
        "`ask_question`, `list_permissions`, `ask_permission`, `manage_task` with `list`, \
         `status` or `kill`, `manage_subagents` with `list`, `kill` or `kill_all`",
        "—",
        "none: `ungoverned`",
    ),
    ToolRow::new(
        "`send_message` and any other tool (a `browser_*` tool, one the documentation does \
         not list)",
        "tool name and arguments",
        "`UnknownTool` (`tool.unknown`)",
    ),
];
