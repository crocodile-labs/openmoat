//! What the docs say about Claude Code: its README row and its rows of the
//! "Host tool mapping" table (`tests/docs/` generates both). The mapping is
//! [`crate::wire::pre_tool_use`]'s; a tool it matches must have a row here.

use crate::contract::{HostDocs, ToolRow};

pub(super) const DOCS: HostDocs = HostDocs {
    hooked_by: "`PreToolUse`, `PostToolUse`, `ConfigChange` and `SessionStart` hooks in `settings.json`",
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
         source of `files`, a relative one also below `root`); with `action: \"read\"` and \
         `out_dir`, each file it saves there, and without, the page it reads (`url`, as \
         `fetch`: untrusted content); `ArtifactData`'s `file_path`",
        "`ReadFiles`, `Patch`, `Fetch`; `FsRead`",
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
        "`mcp__ide__getDiagnostics`, `mcp__claude-vscode__getDiagnostics` (the editor's \
         errors and warnings, VS Code and JetBrains)",
        "`uri`: a `file:` URI or an absolute path is a read of that file, without one a read \
         of the working directory; a `file:` URI without an absolute path is an adapter \
         error, so `deny`; any other argument is read as for any MCP tool",
        "`McpTool` with that read",
    ),
    ToolRow::new(
        "`mcp__ide__executeCode` (Python in the VS Code notebook's kernel)",
        "`code`, which OpenMoat does not read: at least `review`",
        "`Unchecked` `McpTool`",
    ),
    ToolRow::new(
        "`mcp__<server>__<tool>`",
        "tool name and arguments",
        "`McpTool`",
    ),
    ToolRow::new(
        "a payload Cursor sends to this hook (it carries `cursor_version`)",
        "read as Cursor's `preToolUse` (its `Shell` as the command); cannot prompt",
        "as Cursor's rows",
    ),
    ToolRow::new(
        "any other tool (`Task`, `Skill`, …)",
        "—",
        "none: `ungoverned`",
    ),
];
