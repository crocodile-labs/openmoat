//! What the docs say about Hermes Agent: its README row and its rows of the
//! "Host tool mapping" table (`tests/docs.rs` generates both, and checks that
//! every tool name `tools.rs` matches has a row).

use crate::contract::{HostDocs, ToolRow};

pub(super) const DOCS: HostDocs = HostDocs {
    hooked_by: "`pre_tool_call` shell hook in `config.yaml`, allowlisted in \
         `shell-hooks-allowlist.json`",
    protection: "hook only",
    tools: TOOLS,
};

const TOOLS: &[ToolRow] = &[
    ToolRow::new(
        "`terminal`",
        "`command`, after a `cd` to `workdir`; the project stays the payload's `cwd` (the \
         Hermes process's); a relative `workdir`, or a command that leaves the session's \
         shell where OpenMoat cannot know, asks",
        "`Shell`; `Unchecked`",
    ),
    ToolRow::new(
        "`read_file` / `write_file`, `patch`",
        "`path` (`write_file` `content` for provenance); `patch` with `mode: patch`: every \
         file its V4A `patch` names; a relative path asks, since Hermes resolves it against \
         the session's directory, which the payload does not send",
        "`FsRead` / `FsWrite`, `Patch`; `Unchecked`",
    ),
    ToolRow::new(
        "`search_files`",
        "`path`, else the session's directory (an ask); for `target: files`, also where a \
         relative `pattern` climbs to",
        "`FsRead`, `ReadFiles`; `Unchecked`",
    ),
    ToolRow::new(
        "`web_search` / `web_extract`",
        "`query` / each of `urls`: one URL is a fetch, several an unknown tool with every URL",
        "`WebSearch` / `Fetch`; `UnknownTool`",
    ),
    ToolRow::new(
        "`browser_navigate`",
        "`url`: the browser loads the page and runs its scripts",
        "`Net`",
    ),
    ToolRow::new(
        "`execute_code`",
        "`code` (Python); the tools it calls through `hermes_tools` are checked one by one",
        "`ForeignShell` (`unparseable`)",
    ),
    ToolRow::new(
        "`process_manage`",
        "`list`, `poll`, `log`, `wait`, `kill`, `close`, `handoff`: ungoverned; `write`, \
         `submit`: `data`, typed into a running process",
        "none; `Unchecked` `Shell`",
    ),
    ToolRow::new(
        "`cronjob_manage`",
        "`list`: ungoverned; any other action: the arguments, `script` as a command, and an \
         ask, since the job runs the agent later, unattended",
        "none; `Unchecked` `UnknownTool`",
    ),
    ToolRow::new(
        "MCP tool (`mcp__<server>__<tool>`)",
        "tool name and `tool_input`; a name cut to 64 characters is traced by the part kept",
        "`McpTool`",
    ),
    ToolRow::new(
        "`todo_list`, `clarify`, `session_search`, `skills_list`, `delegate_task` (its \
         subagents' calls fire the hook), `read_terminal`, `close_terminal`",
        "—",
        "none: `ungoverned`",
    ),
    ToolRow::new(
        "any other tool (`memory`, `skill_manage`, `skill_view`, the other `browser_*` tools, \
         `vision_analyze`, `computer_use`, the messaging tools, connectors, a plugin's tool, a \
         `tool_call` Hermes did not unwrap)",
        "tool name and arguments",
        "`UnknownTool` (`tool.unknown`)",
    ),
];
