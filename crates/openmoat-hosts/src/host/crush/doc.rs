//! What the docs say about Crush: its README row and its rows of the "Host
//! tool mapping" table (`tests/docs/` generates both, and checks that every
//! tool name `tools.rs` matches has a row).

use crate::contract::{HostDocs, ToolRow};

pub(super) const DOCS: HostDocs = HostDocs {
    hooked_by: "`PreToolUse` hook in `crush.json` (preview)",
    protection: "hook only",
    tools: TOOLS,
};

const TOOLS: &[ToolRow] = &[
    ToolRow::new(
        "`bash`",
        "`command`, after a `cd` to `working_dir`; left to Crush on Windows",
        "`Shell`; `ForeignShell` on Windows",
    ),
    ToolRow::new(
        "`view`, `lsp_diagnostics`, `lsp_symbols` / `write`, `edit`, `multiedit`, \
         `lsp_replace_symbol`",
        "`file_path` (`write` `content`, the replacements of `edit` and `multiedit` for \
         provenance)",
        "`FsRead` / `FsWrite`",
    ),
    ToolRow::new(
        "`ls`, `glob`, `grep`",
        "`path`, else `cwd`; for `glob` also the directory an absolute `pattern` names and \
         where a relative one climbs to",
        "`FsRead`, `ReadFiles`",
    ),
    ToolRow::new(
        "`fetch`, `web_fetch` / `web_search`, `sourcegraph`",
        "`url` / `query`",
        "`Fetch` / `WebSearch`",
    ),
    ToolRow::new(
        "`read_mcp_resource`",
        "`uri`: a `file:` URI as its path; any other URI",
        "`FsRead`; `UnknownTool`",
    ),
    ToolRow::new(
        "`agent`, `agentic_fetch` (subagents)",
        "tool name and arguments; the subagent's own calls fire no hook",
        "`UnknownTool`, `Unchecked`: needs review, a deny in Crush",
    ),
    ToolRow::new(
        "MCP tool (`mcp_<server>_<tool>`)",
        "the name, told apart by its server prefix, and the arguments",
        "`McpTool` of that name",
    ),
    ToolRow::new(
        "`todos`, `question`, `job_output`, `job_kill`, `crush_logs`, `crush_info`, \
         `list_mcp_resources`, `agent_status`",
        "—",
        "none: `ungoverned`",
    ),
    ToolRow::new(
        "any other tool (`download`, `lsp_rename`, `lsp_references`, `lsp_definition`, \
         `agent_dispatch`, a tool added later)",
        "tool name and arguments",
        "`UnknownTool` (`tool.unknown`)",
    ),
];
