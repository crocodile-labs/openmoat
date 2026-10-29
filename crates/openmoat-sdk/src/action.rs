//! The tool calls an engine decides, in the SDK's stable shape (ADR-046).
//!
//! Each [`Action`] is one tool call as the agent would run it. Its JSON form is
//! tagged by `type` (`{"type": "shell", "command": "git status"}`), the shape
//! the JavaScript package sends; an unknown field is an error, so a misspelt
//! key never decides an empty call.

use serde::{Deserialize, Serialize};

use openmoat_core::Action as CoreAction;

/// One tool call, before it runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum Action {
    /// A POSIX shell command line, exactly as it will run (`sh -c <command>`).
    Shell {
        /// The command line.
        command: String,
    },
    /// A command for a shell OpenMoat cannot read (`PowerShell`, `cmd`). Never
    /// classified, so never `allow`.
    ForeignShell {
        /// The shell's name, for reasons.
        shell: String,
        /// The command line.
        command: String,
    },
    /// A file the tool reads.
    FsRead {
        /// The path, absolute or relative to the context's `cwd`.
        path: String,
    },
    /// A file the tool writes, creates, edits or deletes.
    FsWrite {
        /// The path, absolute or relative to the context's `cwd`.
        path: String,
    },
    /// Files one call reads together.
    ReadFiles {
        /// Every file the call reads.
        paths: Vec<String>,
    },
    /// Files one multi-file patch writes (adds, updates, deletes, moves to).
    Patch {
        /// Every file the patch writes.
        writes: Vec<String>,
    },
    /// A network connection the tool opens and may send data over.
    Net {
        /// A URL (`https://api.example.com/v1`) or a host (`api.example.com`,
        /// `api.example.com:443`).
        url: String,
    },
    /// A URL read by a fetch tool that sends no request body.
    Fetch {
        /// The URL.
        url: String,
    },
    /// A query sent to a web search provider.
    WebSearch {
        /// The query.
        query: String,
    },
    /// A Model Context Protocol tool call.
    McpTool(McpCall),
    /// A tool the caller cannot describe as any of the above.
    UnknownTool(UnknownToolCall),
    /// A call the caller sees only in part: `action` is decided as usual and the
    /// call is at least `ask` (rule `unchecked`), since `reason` names what the
    /// caller cannot see.
    Unchecked {
        /// What the caller sees of the call.
        action: Box<Action>,
        /// What it does not see.
        reason: String,
    },
}

/// An MCP tool call, `mcp__<server>__<tool>`, with what its arguments name.
///
/// Fill `reads`, `writes`, `hosts` and `commands` from the arguments you
/// understand, so the usual file, network and shell rules apply to them too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct McpCall {
    /// `mcp__<server>__<tool>`.
    pub name: String,
    /// Paths the call reads.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reads: Vec<String>,
    /// Paths the call writes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub writes: Vec<String>,
    /// URLs or hosts the call contacts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    /// Shell commands the call runs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commands: Vec<String>,
    /// Why the arguments were not searched in full (a depth or size limit);
    /// the call is then at least `ask`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unchecked: Option<String>,
}

/// A tool of `host` the caller cannot classify, with what its arguments name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct UnknownToolCall {
    /// The product or host the tool belongs to (`my-agent`).
    pub host: String,
    /// The tool's name.
    pub tool: String,
    /// Paths the call may read.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reads: Vec<String>,
    /// Paths the call may write.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub writes: Vec<String>,
    /// URLs or hosts the call may contact.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    /// Shell commands the call may run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commands: Vec<String>,
}

impl Action {
    /// A shell command line.
    #[must_use]
    pub fn shell(command: impl Into<String>) -> Self {
        Self::Shell {
            command: command.into(),
        }
    }

    /// A file read.
    #[must_use]
    pub fn read(path: impl Into<String>) -> Self {
        Self::FsRead { path: path.into() }
    }

    /// A file write.
    #[must_use]
    pub fn write(path: impl Into<String>) -> Self {
        Self::FsWrite { path: path.into() }
    }

    /// A network connection to a URL or host.
    #[must_use]
    pub fn net(url: impl Into<String>) -> Self {
        Self::Net { url: url.into() }
    }

    /// A URL read by a fetch tool.
    #[must_use]
    pub fn fetch(url: impl Into<String>) -> Self {
        Self::Fetch { url: url.into() }
    }

    /// An MCP tool call; see [`McpCall`] for its arguments.
    #[must_use]
    pub fn mcp(call: McpCall) -> Self {
        Self::McpTool(call)
    }

    /// `action`, seen only in part: at least `ask` because of `reason`.
    #[must_use]
    pub fn unchecked(action: Self, reason: impl Into<String>) -> Self {
        Self::Unchecked {
            action: Box::new(action),
            reason: reason.into(),
        }
    }

    /// The engine's form of this action.
    pub(crate) fn to_core(&self) -> CoreAction {
        match self.clone() {
            Self::Shell { command } => CoreAction::Shell { command },
            Self::ForeignShell { shell, command } => CoreAction::ForeignShell { shell, command },
            Self::FsRead { path } => CoreAction::FsRead { path },
            Self::FsWrite { path } => CoreAction::FsWrite { path },
            Self::ReadFiles { paths } => CoreAction::ReadFiles { paths },
            Self::Patch { writes } => CoreAction::Patch { writes },
            Self::Net { url } => CoreAction::Net { url },
            Self::Fetch { url } => CoreAction::Fetch { url },
            Self::WebSearch { query } => CoreAction::WebSearch { query },
            Self::McpTool(call) => CoreAction::McpTool {
                name: call.name,
                reads: call.reads,
                writes: call.writes,
                hosts: call.hosts,
                commands: call.commands,
                unchecked: call.unchecked,
            },
            Self::UnknownTool(call) => CoreAction::UnknownTool {
                host: call.host,
                tool: call.tool,
                reads: call.reads,
                writes: call.writes,
                hosts: call.hosts,
                commands: call.commands,
            },
            Self::Unchecked { action, reason } => CoreAction::unchecked(action.to_core(), reason),
        }
    }
}

impl McpCall {
    /// A call of `name` whose arguments name nothing to check.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            reads: Vec::new(),
            writes: Vec::new(),
            hosts: Vec::new(),
            commands: Vec::new(),
            unchecked: None,
        }
    }

    /// Add paths the call reads.
    #[must_use]
    pub fn reads<S: Into<String>>(mut self, paths: impl IntoIterator<Item = S>) -> Self {
        self.reads.extend(paths.into_iter().map(Into::into));
        self
    }

    /// Add paths the call writes.
    #[must_use]
    pub fn writes<S: Into<String>>(mut self, paths: impl IntoIterator<Item = S>) -> Self {
        self.writes.extend(paths.into_iter().map(Into::into));
        self
    }

    /// Add URLs or hosts the call contacts.
    #[must_use]
    pub fn hosts<S: Into<String>>(mut self, hosts: impl IntoIterator<Item = S>) -> Self {
        self.hosts.extend(hosts.into_iter().map(Into::into));
        self
    }

    /// Add shell commands the call runs.
    #[must_use]
    pub fn commands<S: Into<String>>(mut self, commands: impl IntoIterator<Item = S>) -> Self {
        self.commands.extend(commands.into_iter().map(Into::into));
        self
    }

    /// Mark the arguments as not searched in full, for `reason`.
    #[must_use]
    pub fn unchecked(mut self, reason: impl Into<String>) -> Self {
        self.unchecked = Some(reason.into());
        self
    }
}

impl UnknownToolCall {
    /// A call of `tool` of `host` whose arguments name nothing to check.
    #[must_use]
    pub fn new(host: impl Into<String>, tool: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            tool: tool.into(),
            reads: Vec::new(),
            writes: Vec::new(),
            hosts: Vec::new(),
            commands: Vec::new(),
        }
    }

    /// Add paths the call may read.
    #[must_use]
    pub fn reads<S: Into<String>>(mut self, paths: impl IntoIterator<Item = S>) -> Self {
        self.reads.extend(paths.into_iter().map(Into::into));
        self
    }

    /// Add paths the call may write.
    #[must_use]
    pub fn writes<S: Into<String>>(mut self, paths: impl IntoIterator<Item = S>) -> Self {
        self.writes.extend(paths.into_iter().map(Into::into));
        self
    }

    /// Add URLs or hosts the call may contact.
    #[must_use]
    pub fn hosts<S: Into<String>>(mut self, hosts: impl IntoIterator<Item = S>) -> Self {
        self.hosts.extend(hosts.into_iter().map(Into::into));
        self
    }

    /// Add shell commands the call may run.
    #[must_use]
    pub fn commands<S: Into<String>>(mut self, commands: impl IntoIterator<Item = S>) -> Self {
        self.commands.extend(commands.into_iter().map(Into::into));
        self
    }
}

#[cfg(test)]
mod tests;
