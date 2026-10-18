//! Host adapters: the only place that knows each agent's hook wire format.
//!
//! An adapter translates a host payload into a [`HookRequest`] and a
//! [`Decision`] back into the host's response document. Adapters never
//! decide; `openmoat-core` does.

#![warn(missing_docs)]
// A library reports to its caller; only the `moat` binary prints.
#![warn(clippy::print_stdout, clippy::print_stderr)]

mod config_change;
mod continue_cli;
mod cursor;
mod mcp;
mod pre_tool_use;

pub use config_change::proposal_target;
pub use continue_cli::CONTINUE_ENV;

use std::fmt;
use std::str::FromStr;

use openmoat_core::{Action, Decision, Verdict};
use serde_json::Value;
use thiserror::Error;

/// Session id recorded when a host omits it.
const UNKNOWN_SESSION: &str = "unknown";

/// Appended to an `ask` that Codex receives as a `deny` ([`Host::answer`]).
const CODEX_ASK: &str = "this needs your approval and Codex hooks cannot ask: run `moat` to \
     approve it, or `moat allow --last` (this session) or `moat allow --last --always`, then retry";

/// Appended to an `ask` that the Continue CLI receives as a `deny` ([`Host::answer`]).
const CONTINUE_ASK: &str = "this needs your approval and the Continue CLI runs a call its \
     hook asks about: run `moat` to approve it, or `moat allow --last` (this session) or \
     `moat allow --last --always`, then retry";

/// Appended to an `ask` that Cursor receives as a `deny` ([`Host::answer`]). Only
/// file tools reach these hooks; `moat allow --last` approves the exact file.
const CURSOR_ASK: &str = "this needs your approval and Cursor does not prompt for this \
     hook: run `moat` to approve it, or `moat allow --last` (this session) or \
     `moat allow --last --always`, then retry";

/// One line the model can act on: verdict, rule ids, then the reasons.
#[must_use]
pub fn reason_line(decision: &Decision) -> String {
    let verdict = decision.verdict.as_str();
    let rules = decision.rules.join(", ");
    let reasons = decision.reasons.join("; ");
    match (rules.is_empty(), reasons.is_empty()) {
        (true, true) => format!("moat: {verdict}"),
        (false, true) => format!("moat: {verdict} [{rules}]"),
        (true, false) => format!("moat: {verdict} — {reasons}"),
        (false, false) => format!("moat: {verdict} [{rules}] — {reasons}"),
    }
}

/// Words that make a tool name write-shaped (`write_file`, `DeleteDirectory`):
/// the paths such a tool names are checked as written, not read.
const WRITE_VERBS: &[&str] = &[
    "write", "edit", "create", "move", "rename", "delete", "remove", "append", "mkdir", "copy",
    "save", "patch", "update", "download",
];

/// A non-empty string field of a tool's input, or the error naming it.
fn input_str(input: &Value, tool: &str, field: &'static str) -> Result<String, HostError> {
    input
        .get(field)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or(HostError::MissingField {
            tool: tool.to_owned(),
            field,
        })
}

/// The directory a search tool (`Glob`, `Grep`) reads: its `path`, else the
/// working directory.
fn search_root(input: &Value, cwd: Option<&str>) -> Action {
    let path = search_path(input).or(cwd).unwrap_or(".");
    Action::FsRead {
        path: path.to_owned(),
    }
}

fn search_path(input: &Value) -> Option<&str> {
    input
        .get("path")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

/// The directories a Claude Code `Glob` reads. An absolute or `~` `pattern`
/// carries its own directory, which Claude Code searches instead of `path`
/// (its Glob tool splits the pattern with `isAbsolute`); `path` is read too
/// when given, so either spelling is checked.
fn glob_roots(input: &Value, cwd: Option<&str>) -> Action {
    let from_pattern = input
        .get("pattern")
        .and_then(Value::as_str)
        .and_then(pattern_dir);
    match (from_pattern, search_path(input)) {
        (Some(dir), Some(path)) => Action::ReadFiles {
            paths: vec![path.to_owned(), dir],
        },
        (Some(dir), None) => Action::FsRead { path: dir },
        (None, _) => search_root(input, cwd),
    }
}

/// The static directory of an absolute or `~` glob pattern, as Claude Code
/// takes it: everything before the last separator ahead of the first glob
/// metacharacter (`*?[{`), `/` at the root. `None` for a relative pattern.
fn pattern_dir(pattern: &str) -> Option<String> {
    let bytes = pattern.as_bytes();
    let drive = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    if !(drive || pattern.starts_with(['/', '\\', '~'])) {
        return None;
    }
    let stem = &pattern[..pattern.find(['*', '?', '[', '{']).unwrap_or(pattern.len())];
    let dir = &stem[..stem.rfind(['/', '\\'])?];
    Some(match dir {
        "" => "/".to_owned(),
        d if drive && d.len() == 2 => format!("{d}/"),
        d => d.to_owned(),
    })
}

/// The host's session id, or a placeholder when it sent none.
fn session_or_unknown(session: Option<String>) -> String {
    session.unwrap_or_else(|| UNKNOWN_SESSION.to_owned())
}

/// Whether `session_id` names no real session: the placeholder recorded when a
/// host sent none, or an empty id. Every such call shares it, so it can never
/// scope a session grant.
#[must_use]
pub fn is_unknown_session(session_id: &str) -> bool {
    session_id.is_empty() || session_id == UNKNOWN_SESSION
}

/// Agents with a supported integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Host {
    /// Anthropic's Claude Code (`PreToolUse`, `ConfigChange`).
    ClaudeCode,
    /// The Codex CLI (`PreToolUse`).
    Codex,
    /// Cursor (`beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, `preToolUse`).
    Cursor,
    /// The Continue CLI (`cn`), which runs the Claude Code hooks. It has no hook
    /// of its own to install, so it is not in [`Host::ALL`]; `guard` recognises
    /// it with [`Host::sender`].
    Continue,
}

impl Host {
    /// Every host with a hook to install, in the order commands list them.
    pub const ALL: [Host; 3] = [Host::ClaudeCode, Host::Codex, Host::Cursor];

    /// The identifier used on the command line and in the audit log.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
            Self::Cursor => "cursor",
            Self::Continue => "continue",
        }
    }

    /// The product name shown to people.
    #[must_use]
    pub fn display_name(self) -> &'static str {
        match self {
            Self::ClaudeCode => "Claude Code",
            Self::Codex => "Codex",
            Self::Cursor => "Cursor",
            Self::Continue => "Continue CLI",
        }
    }

    /// The host whose hook format this host speaks: `cn` sends Claude Code's.
    fn wire(self) -> Self {
        match self {
            Self::Continue => Self::ClaudeCode,
            other => other,
        }
    }

    /// Parse a hook payload read from the host. The event name selects the format;
    /// Claude Code and Codex may omit it on `PreToolUse`.
    pub fn parse_request(self, payload: &str) -> Result<HookRequest, HostError> {
        #[derive(serde::Deserialize)]
        struct Envelope {
            #[serde(default)]
            hook_event_name: Option<String>,
        }
        let envelope: Envelope = serde_json::from_str(payload)?;
        match (self.wire(), envelope.hook_event_name.as_deref()) {
            (Self::Cursor, Some(event)) if cursor::EVENTS.contains(&event) => {
                cursor::parse(self, payload)
            }
            (Self::Cursor, _) => Err(HostError::WrongEvent(
                envelope.hook_event_name.unwrap_or_default(),
            )),
            (_, None | Some(pre_tool_use::EVENT)) => pre_tool_use::parse(self, payload),
            (Self::ClaudeCode, Some(config_change::EVENT)) => config_change::parse(self, payload),
            (_, Some(other)) => Err(HostError::WrongEvent(other.to_owned())),
        }
    }

    /// The event a payload claims to be for, read as leniently as possible, so a
    /// payload that fails [`Host::parse_request`] is still answered in its event's
    /// response format.
    #[must_use]
    pub fn event_of(self, payload: &str) -> HookEvent {
        #[derive(serde::Deserialize)]
        struct Envelope {
            hook_event_name: String,
        }
        match serde_json::from_str::<Envelope>(payload) {
            Ok(e)
                if self.wire() == Self::ClaudeCode && e.hook_event_name == config_change::EVENT =>
            {
                HookEvent::ConfigChange {
                    source: String::new(),
                    change_type: None,
                }
            }
            _ => HookEvent::PreToolUse,
        }
    }

    /// The decision to record and answer for `event`. A `defer` (ADR-025) needs a
    /// host flow that decides by itself; Cursor's `preToolUse` and `beforeReadFile`
    /// have none and run file tools outside Cursor's sandbox, so there OpenMoat asks
    /// itself: the `ask` is recorded, and [`Self::answer`] sends it as a deny that
    /// says how to approve it.
    #[must_use]
    pub fn decided(self, event: &HookEvent, mut decision: Decision) -> Decision {
        if self == Self::Cursor
            && *event == HookEvent::PreToolUseNoAsk
            && decision.verdict == Verdict::Defer
        {
            decision.verdict = Verdict::Ask;
        }
        decision
    }

    /// The decision as this host has to receive it. Codex's `PreToolUse` rejects
    /// `permissionDecision: "ask"` as unsupported and then runs the call, the
    /// Continue CLI ignores it and runs the call, and Cursor does not enforce
    /// `ask` on `preToolUse` or `beforeReadFile` ([`HookEvent::PreToolUseNoAsk`]).
    /// There an `ask` reaches the host as a `deny` that says how to approve it;
    /// the audit log keeps the `ask`, which is what `moat allow --last` looks for.
    #[must_use]
    pub fn answer(self, event: &HookEvent, decision: &Decision) -> Decision {
        let how = match (self, event) {
            (Self::Codex, HookEvent::PreToolUse) => Some(CODEX_ASK),
            (Self::Continue, HookEvent::PreToolUse) => Some(CONTINUE_ASK),
            (Self::Cursor, HookEvent::PreToolUseNoAsk) => Some(CURSOR_ASK),
            _ => None,
        };
        let mut answer = decision.clone();
        if let Some(how) = how
            && decision.verdict == Verdict::Ask
        {
            answer.verdict = Verdict::Deny;
            answer.reasons.push(how.to_owned());
        }
        answer
    }

    /// Render the response document the host expects on stdout for `event`.
    #[must_use]
    pub fn render_response(self, event: &HookEvent, decision: &Decision) -> String {
        match (self, event) {
            (Self::Cursor, _) => cursor::render(decision),
            (_, HookEvent::PreToolUse | HookEvent::PreToolUseNoAsk) => {
                pre_tool_use::render(decision)
            }
            (_, HookEvent::ConfigChange { .. }) => config_change::render(decision),
        }
    }
}

impl FromStr for Host {
    type Err = HostError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|h| h.id() == s)
            .ok_or_else(|| HostError::UnknownHost(s.to_owned()))
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// Which hook fired. Drives the response format and the guard's handling.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum HookEvent {
    /// A tool is about to run.
    #[default]
    PreToolUse,
    /// A tool is about to run under a hook that ignores `ask`: Cursor `preToolUse`
    /// accepts it but runs the call, and `beforeReadFile` takes only allow or deny.
    PreToolUseNoAsk,
    /// A host settings file changed on disk (Claude Code only).
    ConfigChange {
        /// Which settings scope changed (`user_settings`, `project_settings`, …).
        source: String,
        /// The kind of change, when the host reports one (earlier Claude Code builds).
        change_type: Option<String>,
    },
}

/// A host tool call, normalised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookRequest {
    /// The host that sent the payload.
    pub host: Host,
    /// The host's session or conversation id (`unknown` when omitted).
    pub session_id: String,
    /// The host's id for this tool call, when it sends one.
    pub call_id: Option<String>,
    /// The working directory the tool runs in, when the host sends it.
    pub cwd: Option<String>,
    /// The tool name as the host spells it.
    pub tool: String,
    /// `None` when the tool is outside the kernel's scope (e.g. a todo list).
    pub action: Option<Action>,
    /// Which hook fired.
    pub event: HookEvent,
}

/// Why a payload could not be turned into a request. `guard` denies on any of these.
///
/// Messages include their cause, so no variant also exposes it as `source`:
/// a chained report (`{:#}`) would print it twice.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HostError {
    /// `--host` named no supported host.
    #[error("unknown host `{0}`; supported: claude-code, codex, cursor")]
    UnknownHost(String),
    /// The payload is not JSON or does not fit the host's schema.
    #[error("{problem}: {0}", problem = json_problem(.0))]
    Json(serde_json::Error),
    /// The payload is for a hook event this adapter does not handle.
    #[error("payload is for event `{0}`, which this host adapter does not handle")]
    WrongEvent(String),
    /// A governed tool's payload lacks a field the decision needs.
    #[error("tool `{tool}` payload is missing field `{field}`")]
    MissingField {
        /// The tool or event name.
        tool: String,
        /// The missing field.
        field: &'static str,
    },
    /// A tool's arguments cannot be read, so what it touches cannot be checked.
    #[error("tool `{tool}` arguments cannot be checked: {problem}")]
    MalformedArguments {
        /// The tool name.
        tool: String,
        /// What is wrong with the arguments.
        problem: String,
    },
}

impl From<serde_json::Error> for HostError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

fn json_problem(error: &serde_json::Error) -> &'static str {
    if error.is_data() {
        "payload is JSON but does not fit the hook schema"
    } else {
        "payload is not valid JSON"
    }
}

#[cfg(test)]
mod tests {
    use openmoat_core::{Decision, Verdict};

    use super::{HookEvent, Host};

    /// ADR-025: `defer` writes nothing, so Claude Code, Codex and the Continue CLI
    /// run their own permission flow; hosts that cannot ask do not turn it into a deny.
    #[test]
    fn defer_is_no_decision_for_every_pre_tool_use_host() {
        let defer = Decision::new(Verdict::Defer);
        for host in [Host::ClaudeCode, Host::Codex, Host::Continue] {
            let answer = host.answer(&HookEvent::PreToolUse, &defer);
            assert_eq!(answer.verdict, Verdict::Defer, "{host:?}");
            assert_eq!(
                host.render_response(&HookEvent::PreToolUse, &answer),
                "",
                "{host:?}"
            );
        }
    }
}
