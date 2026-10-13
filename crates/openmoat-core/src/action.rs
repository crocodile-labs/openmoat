//! What a tool call asks to do, in two forms.
//!
//! [`Action`] is the call as a host adapter reports it: one per payload,
//! before any classification. [`AtomicAction`] is one primitive operation the
//! classifier derives from it (an argv, a path read or written, a host, an
//! environment variable, an MCP tool name). Policy rules are matched against
//! atoms, never against an `Action` directly; [`Action::kind`] and
//! [`AtomicAction::kind`] map each to the rule [`Kind`] it belongs to.

use serde::{Deserialize, Serialize};

use crate::kind::Kind;

/// A tool call as seen from a host, before classification.
///
/// Host adapters (`openmoat-hosts`) translate each payload into exactly one of
/// these. Adapters never decide.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Action {
    /// A shell command string as the host would execute it.
    /// A shell command line, exactly as the host would run it.
    Shell {
        /// The command line.
        command: String,
    },
    /// A command for a shell the classifier cannot read (Claude Code `PowerShell`).
    /// Never classified, so always `unparseable`: an `ask`, never an `allow`.
    ForeignShell {
        /// The shell's name, for reasons and the audit log.
        shell: String,
        /// The command line.
        command: String,
    },
    /// A direct file read through a host tool (e.g. Claude Code `Read`).
    /// A file read by a host tool (`Read`, `Glob`, `Grep`, `LSP`, `beforeReadFile`).
    FsRead {
        /// Path as the tool gave it; normalised during classification.
        path: String,
    },
    /// A direct file write/edit through a host tool.
    /// A file write or edit by a host tool (`Edit`, `Write`, `NotebookEdit`).
    FsWrite {
        /// Path as the tool gave it; normalised during classification.
        path: String,
    },
    /// A network connection a host tool opens and may send data over
    /// (Claude Code `Monitor` WebSocket).
    Net {
        /// The URL as the tool gave it.
        url: String,
    },
    /// A URL read by a host's own fetch tool (Claude Code `WebFetch`): a
    /// request the agent cannot attach a body to, judged by `fetch` and `net`
    /// rules (ADR-017).
    Fetch {
        /// The URL as the tool gave it.
        url: String,
    },
    /// A query a host's own web search tool (Claude Code and Cursor `WebSearch`)
    /// sends to the host's search provider: judged by `defaults.web.search`.
    WebSearch {
        /// The query as the tool gave it.
        query: String,
    },
    /// A host tool the adapter cannot classify: it names no path or URL the
    /// adapter knows to read, so what it touches is unknown. Judged by
    /// `defaults.tool.unknown`, which the default policy sets to `ask`.
    UnknownTool {
        /// The host's id (`cursor`).
        host: String,
        /// The tool name as the host sent it.
        tool: String,
    },
    /// A patch that edits several files in one call (Codex `apply_patch`):
    /// every path it adds, updates, deletes or moves to is written.
    /// Files changed by one multi-file patch (Codex `apply_patch`).
    Patch {
        /// Every file the patch adds, updates, deletes or moves to.
        writes: Vec<String>,
    },
    /// Files one tool call reads together (Claude Code `SendFile`, which sends
    /// their contents to another session): every path is read.
    ReadFiles {
        /// Every file the call reads.
        paths: Vec<String>,
    },
    /// An MCP tool call, `mcp__<server>__<tool>`. Adapters that understand a
    /// server's arguments add the paths and hosts the call touches so the
    /// usual `fs.*` and `net` rules apply to it as well.
    McpTool {
        /// `mcp__<server>__<tool>`.
        name: String,
        /// Paths the call reads, derived from its arguments.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        reads: Vec<String>,
        /// Paths the call writes, derived from its arguments.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        writes: Vec<String>,
        /// URLs or hosts the call contacts, derived from its arguments.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        hosts: Vec<String>,
        /// The limit that stopped the adapter searching the arguments (nesting
        /// depth, number of paths and URLs). What was not searched may name a
        /// file or host, so the engine decides the call at least `ask`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        unchecked: Option<String>,
    },
}

impl Action {
    /// The kind of action as a user would describe it (`Patch` writes files).
    #[must_use]
    pub fn kind(&self) -> Kind {
        match self {
            Self::Shell { .. } | Self::ForeignShell { .. } => Kind::Shell,
            Self::FsRead { .. } | Self::ReadFiles { .. } => Kind::FsRead,
            Self::FsWrite { .. } | Self::Patch { .. } => Kind::FsWrite,
            Self::Net { .. } => Kind::Net,
            Self::Fetch { .. } => Kind::Fetch,
            Self::WebSearch { .. } => Kind::WebSearch,
            Self::UnknownTool { .. } => Kind::UnknownTool,
            Self::McpTool { .. } => Kind::Mcp,
        }
    }

    /// An MCP call whose arguments are not interpreted.
    #[must_use]
    pub fn mcp(name: impl Into<String>) -> Self {
        Self::McpTool {
            name: name.into(),
            reads: Vec::new(),
            writes: Vec::new(),
            hosts: Vec::new(),
            unchecked: None,
        }
    }
}

/// The primitive operations an [`Action`] decomposes into.
///
/// One shell command typically yields several: the command itself, every
/// path it touches, every host it may contact, every env var it reads or sets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AtomicAction {
    /// Normalised argv of one (sub-)command.
    Shell {
        /// Program and arguments after quote removal.
        argv: Vec<String>,
    },
    /// A whole pipeline / list (`a | b && c`) with separators kept as tokens, so
    /// rules such as `curl * | sh` can match across sub-commands. Never carries
    /// a default verdict (see `engine.rs`).
    Pipeline {
        /// Words and separator tokens of the whole pipeline or list.
        argv: Vec<String>,
    },
    /// Absolute path in slash-separated canonical form (`~`, `${project}` and
    /// `cwd` already applied).
    FsRead {
        /// Absolute path in canonical form.
        path: String,
    },
    /// A file write, create, delete or move.
    FsWrite {
        /// Absolute path in canonical form.
        path: String,
    },
    /// Host name only (no scheme, no port).
    Net {
        /// Lowercase host name.
        host: String,
    },
    /// The host of a URL a fetch tool reads; matched by `fetch` and `net` rules.
    Fetch {
        /// Lowercase host name.
        host: String,
    },
    /// A shell word with no scheme that looks like a host, outside the arguments
    /// of a program that names hosts (ADR-025): it may be a JSON path or a method
    /// call (`check_runs.0.id`, `app.run`). Matched by `net` rules; when none
    /// matches, the policy's catch-all decides it, not `defaults.net`.
    NetWord {
        /// Lowercase host name.
        host: String,
    },
    /// A web search query; no rule list names it, so `defaults` decide it.
    WebSearch {
        /// The query as the tool gave it.
        query: String,
    },
    /// A host tool the adapter cannot classify; only `defaults` decide it.
    UnknownTool {
        /// The host's id.
        host: String,
        /// The tool name as the host sent it.
        tool: String,
    },
    /// An environment variable read (`$NAME`, `printenv NAME`).
    EnvRead {
        /// Variable name.
        name: String,
    },
    /// An environment variable set (`NAME=value`, `export NAME=…`).
    EnvSet {
        /// Variable name.
        name: String,
    },
    /// An MCP tool invocation.
    McpTool {
        /// `mcp__<server>__<tool>`.
        name: String,
    },
}

impl AtomicAction {
    /// The rule kind this atom is matched against.
    #[must_use]
    pub fn kind(&self) -> Kind {
        match self {
            Self::Shell { .. } | Self::Pipeline { .. } => Kind::Shell,
            Self::FsRead { .. } => Kind::FsRead,
            Self::FsWrite { .. } => Kind::FsWrite,
            Self::Net { .. } | Self::NetWord { .. } => Kind::Net,
            Self::Fetch { .. } => Kind::Fetch,
            Self::WebSearch { .. } => Kind::WebSearch,
            Self::UnknownTool { .. } => Kind::UnknownTool,
            Self::EnvRead { .. } => Kind::EnvRead,
            Self::EnvSet { .. } => Kind::EnvSet,
            Self::McpTool { .. } => Kind::Mcp,
        }
    }

    /// The same read or write of `path`; `None` for any other atom.
    pub(crate) fn with_path(&self, path: String) -> Option<Self> {
        match self {
            Self::FsRead { .. } => Some(Self::FsRead { path }),
            Self::FsWrite { .. } => Some(Self::FsWrite { path }),
            _ => None,
        }
    }

    /// The text a glob rule is matched against; `None` for shell atoms, which
    /// are matched as argv.
    pub(crate) fn subject(&self) -> Option<&str> {
        match self {
            Self::Shell { .. } | Self::Pipeline { .. } => None,
            Self::FsRead { path } | Self::FsWrite { path } => Some(path),
            Self::Net { host } | Self::Fetch { host } | Self::NetWord { host } => Some(host),
            Self::EnvRead { name } | Self::EnvSet { name } | Self::McpTool { name } => Some(name),
            Self::WebSearch { query } => Some(query),
            Self::UnknownTool { tool, .. } => Some(tool),
        }
    }

    /// Short human description used in reasons and audit lines.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Shell { argv } => format!("shell \"{}\"", argv.join(" ")),
            Self::Pipeline { argv } => format!("pipeline \"{}\"", argv.join(" ")),
            Self::FsRead { path } => format!("read {path}"),
            Self::FsWrite { path } => format!("write {path}"),
            Self::Net { host } => format!("net {host}"),
            Self::NetWord { host } => format!("net {host} (a word that looks like a host)"),
            Self::Fetch { host } => format!("fetch {host}"),
            Self::WebSearch { query } => format!("web search \"{query}\""),
            Self::UnknownTool { host, tool } => format!("unknown {host} tool {tool}"),
            Self::EnvRead { name } => format!("env read {name}"),
            Self::EnvSet { name } => format!("env set {name}"),
            Self::McpTool { name } => format!("mcp {name}"),
        }
    }
}
