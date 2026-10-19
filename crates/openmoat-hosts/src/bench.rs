//! What `moat bench` needs from a host: the payload it sends for one tool
//! call, and how it reads the hook's reply. Payload shapes follow the golden
//! payloads in `tests/fixtures/hosts/`; reply rules follow
//! `docs/ARCHITECTURE.md` §5 and `docs/THREAT_MODEL.md` §5.

use std::path::Path;

use openmoat_core::Verdict;
use serde::Serialize;
use serde_json::Value;

/// A tool call, independent of the host that makes it.
#[derive(Debug, Clone, PartialEq)]
pub enum Call {
    /// Run a shell command.
    Shell(String),
    /// Read a file (`~/` is the home, anything relative is in the project).
    Read(String),
    /// Write a whole file.
    Write(String),
    /// Change part of a file.
    Edit(String),
    /// Fetch a URL.
    Fetch(String),
    /// Call an MCP server's tool.
    Mcp {
        /// The server's name.
        server: String,
        /// The tool's name.
        tool: String,
        /// The tool's arguments.
        args: Value,
    },
}

impl Call {
    /// Whether the call reads or writes a file through a file tool.
    #[must_use]
    pub fn is_file_tool(&self) -> bool {
        matches!(self, Self::Read(_) | Self::Write(_) | Self::Edit(_))
    }
}

/// Where a call happens: the throwaway home, the project, and its ids.
#[derive(Debug)]
pub struct Place<'a> {
    /// The home directory.
    pub home: &'a Path,
    /// The project, the call's working directory.
    pub project: &'a Path,
    /// The session id.
    pub session: &'a str,
    /// The call id.
    pub call_id: &'a str,
}

impl Place<'_> {
    /// The working directory as the host sends it.
    pub(crate) fn cwd(&self) -> String {
        self.project.to_string_lossy().into_owned()
    }

    /// File tools send absolute paths: `~/x` is in the home, anything relative
    /// is in the project.
    pub(crate) fn file(&self, path: &str) -> String {
        let full = match path.strip_prefix("~/") {
            Some(rest) => self.home.join(rest),
            None => self.project.join(path),
        };
        full.to_string_lossy().into_owned()
    }
}

/// What the agent writes in a bench write or edit.
pub(crate) const CONTENT: &str = "written by the agent";

/// How the hook process ended.
#[derive(Debug, Clone, Copy)]
pub struct Exit<'a> {
    /// The exit code; `None` when a signal ended it.
    pub code: Option<i32>,
    /// What it printed on stdout.
    pub stdout: &'a str,
    /// What it printed on stderr.
    pub stderr: &'a str,
}

impl Exit<'_> {
    /// Stdout as JSON, or `null`.
    pub(crate) fn document(&self) -> Value {
        serde_json::from_str(self.stdout.trim()).unwrap_or(Value::Null)
    }
}

/// What the host does with the hook's reply, ordered by strictness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Answer {
    /// The hook allowed the call.
    Allow,
    /// The hook made no decision the host acts on; the host's own permission
    /// settings apply.
    Passthrough,
    /// The hook failed (crashed, timed out, could not start, or answered outside the
    /// protocol); what the host then does is its failure behaviour
    /// ([`HostSpec::on_hook_failure`](crate::HostSpec::on_hook_failure)).
    Error,
    /// The host asks the person.
    Ask,
    /// The host blocks the call.
    Deny,
}

impl From<Verdict> for Answer {
    fn from(verdict: Verdict) -> Self {
        match verdict {
            Verdict::Allow => Self::Allow,
            // ADR-025: no decision, the host's own permission flow runs.
            Verdict::Defer => Self::Passthrough,
            Verdict::Ask => Self::Ask,
            // `Deny`, and any verdict added to the core later: the strictest.
            _ => Self::Deny,
        }
    }
}

impl Answer {
    /// The answer as the report spells it.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Passthrough => "passthrough",
            Self::Error => "error",
            Self::Ask => "ask",
            Self::Deny => "deny",
        }
    }

    /// Whether this answer satisfies `want`: a hook that leaves an allowed call
    /// to the host's own settings has not blocked it.
    #[must_use]
    pub fn meets(self, want: Self) -> bool {
        self == want || (want == Self::Allow && self == Self::Passthrough)
    }
}
