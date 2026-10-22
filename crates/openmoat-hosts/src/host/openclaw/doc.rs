//! What the docs say about OpenClaw: its README row and its rows of the "Host
//! tool mapping" table (`tests/docs.rs` generates both, and checks that every
//! tool name and action `tools.rs` matches has a row).

use crate::contract::{HostDocs, ToolRow};

pub(super) const DOCS: HostDocs = HostDocs {
    hooked_by: "OpenMoat's plugin on OpenClaw's `before_tool_call` hook",
    protection: "hook only",
    tools: TOOLS,
};

const TOOLS: &[ToolRow] = &[
    ToolRow::new(
        "`exec`",
        "`command`, with each `env` entry written as `NAME='value'` before it; `workdir` as a \
         `cd` before the command, the project staying the session's; PowerShell on Windows",
        "`Shell`; `ForeignShell` on Windows",
    ),
    ToolRow::new(
        "Code Mode `exec`",
        "the params as JSON",
        "`ForeignShell` (`unparseable`)",
    ),
    ToolRow::new(
        "`process`",
        "`list`, `poll`, `log`, `kill`, `clear`, `remove`: ungoverned; any other action \
         (`send-keys`, `submit`, `paste`, `write`, typed into a running session): the params \
         as JSON",
        "none; `ForeignShell` (`unparseable`)",
    ),
    ToolRow::new(
        "`read` / `write`, `edit`",
        "`path` and `file_path` when both are given; a relative path with no workspace (`cwd`) \
         is an adapter error",
        "`FsRead`, `ReadFiles` / `FsWrite`, `Patch`",
    ),
    ToolRow::new("`apply_patch`", "`input` (the patch envelope)", "`Patch`"),
    ToolRow::new(
        "`web_fetch` / `web_search`, `x_search`",
        "`url` / `query`",
        "`Fetch` / `WebSearch`",
    ),
    ToolRow::new(
        "`browser`",
        "`open`, `navigate`: `url` or `targetUrl`; `upload`: `paths`; any other action",
        "`Net`; `ReadFiles`; `UnknownTool`",
    ),
    ToolRow::new(
        "`gateway`",
        "`config.get`: the plugin's `configPath`; `config.schema.lookup`: ungoverned; any \
         other action",
        "`FsRead`; none; `UnknownTool`",
    ),
    ToolRow::new(
        "`plugins`",
        "`list`, `inspect`, `search`: ungoverned; any other action (`install`, `enable`, \
         `disable`, `uninstall`, `reload`, `reloadAndResume`): the plugin's `configPath`",
        "none; `FsWrite` (`kernel-self` denies it)",
    ),
    ToolRow::new(
        "`cron`",
        "`status`, `list`, `get`, `runs`: ungoverned; `add`, `update`, `next_check`: the state \
         database `<stateDir>/state/openclaw.sqlite` (beside `configPath` from a plugin that \
         sends no `stateDir`); any other action (`run`, `remove`, `wake`)",
        "none; `FsWrite` (`kernel-self` denies it); `UnknownTool`",
    ),
    ToolRow::new(
        "`nodes`",
        "`status`, `describe`, `pending`, `camera_list`, `device_*`, `which`: ungoverned; \
         `invoke`: the params as JSON; an action with `outPath`: `outPath`; any other action",
        "none; `ForeignShell` (`unparseable`); `FsWrite`; `UnknownTool`",
    ),
    ToolRow::new(
        "`view_image`",
        "`path` and each of `paths`: local files (a `file://` URL as its path); `http(s)` URLs \
         when no file is named; `data:` images touch nothing",
        "`FsRead`, `ReadFiles`; `Fetch` for one URL, `UnknownTool` for several",
    ),
    ToolRow::new(
        "`<server>__<tool>`",
        "`mcp__<server>__<tool>` and `params`",
        "`McpTool`",
    ),
    ToolRow::new(
        "`ask_user`, `session_status`, `agents_list`, `agents_wait`, the goal tools, \
         `progress_card`, `theme`, `screen`, `wait`, `tool_search`, `tool_describe`, \
         `heartbeat_respond`",
        "—",
        "none: `ungoverned`",
    ),
    ToolRow::new(
        "any other tool (`message`, `sessions_*`, a plugin's tool)",
        "tool name and arguments",
        "`UnknownTool` (`tool.unknown`)",
    ),
];
