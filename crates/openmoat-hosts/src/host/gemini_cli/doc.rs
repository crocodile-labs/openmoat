//! What the docs say about Gemini CLI: its README row and its rows of the
//! "Host tool mapping" table (`tests/docs.rs` generates both, and checks that
//! every tool name `tools.rs` matches has a row).

use crate::contract::{HostDocs, ToolRow};

pub(super) const DOCS: HostDocs = HostDocs {
    hooked_by: "`BeforeTool` hook in `settings.json`",
    protection: "hook only",
    tools: TOOLS,
};

const TOOLS: &[ToolRow] = &[
    ToolRow::new(
        "`run_shell_command`",
        "`command`, after a `cd` to `dir_path` (quoted whole: Gemini CLI expands no `~`); the \
         project stays the session's; PowerShell on Windows",
        "`Shell`; `ForeignShell` on Windows",
    ),
    ToolRow::new(
        "`read_file`, `list_directory` / `write_file`, `replace`",
        "`file_path`, `dir_path` / `file_path` (`write_file` `content` for provenance)",
        "`FsRead` / `FsWrite`",
    ),
    ToolRow::new(
        "`glob`, `grep_search` (`search_file_content`)",
        "`dir_path`, else `cwd` and an ask, since Gemini CLI then searches every workspace \
         directory; for `glob` also the directory `pattern` names before its first wildcard, \
         for `grep_search` where `include_pattern` (`include` before 0.65) climbs to",
        "`FsRead`, `ReadFiles`; `Unchecked`",
    ),
    ToolRow::new(
        "`read_many_files`",
        "each `include`, up to its first wildcard, and an ask: it reads every workspace directory",
        "`Unchecked`",
    ),
    ToolRow::new(
        "`web_fetch` / `google_web_search`",
        "the one URL in `prompt` (a `github.com` `blob` page as the `raw.githubusercontent.com` \
         file Gemini CLI fetches; none or several is an adapter error) / `query`",
        "`Fetch` / `WebSearch`",
    ),
    ToolRow::new(
        "`read_mcp_resource`",
        "`uri`: a `file:` URI as its path; any other URI",
        "`FsRead`; `UnknownTool`",
    ),
    ToolRow::new(
        "MCP tool (`mcp_<server>_<tool>`)",
        "`mcp_context.server_name`, `mcp_context.tool_name` and `tool_input`; without \
         `mcp_context` the name cannot be split",
        "`McpTool` as `mcp__<server>__<tool>`; `UnknownTool`",
    ),
    ToolRow::new(
        "`write_todos`, `ask_user`, `tracker_*`, `update_topic`, plan-mode, `complete_task`, \
         `activate_skill`, `get_internal_docs`, `list_mcp_resources`, `invoke_agent` and the \
         built-in subagents",
        "—",
        "none: `ungoverned`",
    ),
    ToolRow::new(
        "any other tool (a custom subagent's, a browser subagent's, a discovered tool)",
        "tool name and arguments",
        "`UnknownTool` (`tool.unknown`)",
    ),
];
