//! What the docs say about Claude Code: its README row and its rows of the
//! "Host tool mapping" table (`tests/docs.rs` generates both). The mapping is
//! [`crate::wire::pre_tool_use`]'s; a tool it matches must have a row here.

use crate::contract::{HostDocs, ToolRow};

pub(super) const DOCS: HostDocs = HostDocs {
    hooked_by: "`PreToolUse` and `ConfigChange` hooks in `settings.json`",
    protection: "hook + OS sandbox (macOS, Linux, WSL2); hook only on native Windows",
    tools: TOOLS,
};

const TOOLS: &[ToolRow] = &[
    ToolRow::new("`Bash`", "`command`", "`Shell`"),
    ToolRow::new(
        "`Monitor`",
        "`command`, or `ws.url` (exactly one)",
        "`Shell`, or `Net`",
    ),
    ToolRow::new("`PowerShell`", "`command`", "`ForeignShell`"),
    ToolRow::new("`Read`", "`file_path`", "`FsRead`"),
    ToolRow::new("`LSP`", "`filePath`", "`FsRead`"),
    ToolRow::new(
        "`Glob`, `Grep`",
        "`path`, else the working directory; an absolute or `~` Glob `pattern` also reads its \
         directory part (Claude Code searches that instead of `path`), and a relative one \
         where its `..` climbs to",
        "`FsRead`, `ReadFiles`",
    ),
    ToolRow::new(
        "`SendFile`",
        "every path in `files` (the contents go to another session; an empty or non-string \
         list is an adapter error, so `deny`)",
        "`ReadFiles`",
    ),
    ToolRow::new(
        "`Artifact`; `ArtifactData`",
        "every local file it uploads to a claude.ai page (`file_path`, `file_paths`, each \
         source of `files`, a relative one below `root`); with `action: \"read\"` and \
         `out_dir`, each file it saves there; `ArtifactData`'s `file_path`",
        "`ReadFiles`, `Patch`; `FsRead`",
    ),
    ToolRow::new(
        "`Edit`, `Write`, `MultiEdit`; `NotebookEdit`",
        "`file_path` (`Write` `content` for provenance); `notebook_path`",
        "`FsWrite`",
    ),
    ToolRow::new("`WebFetch`", "`url`", "`Fetch`"),
    ToolRow::new(
        "`WebSearch`",
        "`query` (`allowed_domains` and `blocked_domains` only filter results)",
        "`WebSearch`",
    ),
    ToolRow::new(
        "`ReadMcpResourceTool`",
        "`server`, `uri`: a `file:` URI is a read of its (percent-decoded) path, any other URI \
         a host; a `file:` URI without an absolute path is an adapter error, so `deny`",
        "`McpTool` `mcp__<server>__read_resource`",
    ),
    ToolRow::new(
        "`EnterWorktree`",
        "`path` (an existing worktree becomes the session's directory and project root); \
         with `name` or nothing, ungoverned",
        "`FsRead`",
    ),
    ToolRow::new(
        "`mcp__<server>__<tool>`",
        "tool name and arguments",
        "`McpTool`",
    ),
    ToolRow::new(
        "any other tool (`Task`, `Skill`, …)",
        "—",
        "none: `ungoverned`",
    ),
];
