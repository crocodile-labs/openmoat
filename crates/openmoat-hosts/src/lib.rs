//! Host adapters: the only place that knows each agent's hook wire format.
//!
//! An adapter translates a host payload into a [`HookRequest`] and a
//! [`Decision`] back into the host's response document. Adapters never
//! decide; `openmoat-core` does.

#![warn(missing_docs)]
// A library reports to its caller; only the `moat` binary prints.
#![warn(clippy::print_stdout, clippy::print_stderr)]

pub mod bench;
mod contract;
mod glob;
mod host;
mod registry;
mod wire;

pub use contract::{
    Advisories, Advisory, AlsoDir, Asks, ConsentFile, Detect, ExtraFile, GUARD_BUDGET_S, Helper,
    HookDir, HookLayout, HookSpec, HookVersions, HostDocs, HostSpec, InstallSpec, KeyShape, Locate,
    Located, Location, McpFile, McpNames, McpReader, McpServer, McpSpec, McpSyntax, Paths,
    Platform, ProcessSpec, ProjectSettingsSpec, Protect, RelaxedKey, SandboxFormat, SandboxSpec,
    SettingsFile, SettingsReader, ToolRow, Unseen, Version,
};
pub use host::claude_code::config_change::proposal_target;
pub use host::claude_code::project_settings::findings as claude_code_settings_findings;
pub use host::continue_cli::CONTINUE_ENV;
pub use host::openclaw::{
    CONFIG_FILE as OPENCLAW_CONFIG_FILE, PLUGIN_ID as OPENCLAW_PLUGIN_ID,
    STATE_DIR_NAME as OPENCLAW_STATE_DIR_NAME, STATE_DIR_VARIABLE as OPENCLAW_STATE_DIR_VARIABLE,
};
pub use wire::hook_file::yaml as yaml_hooks;
pub use wire::hook_file::{HookFile, HookFileError, HookFileState, HookOutcome};
pub use wire::owned_file::{OwnedFile, OwnedFileError};

use std::fmt;
use std::str::FromStr;

use openmoat_core::{Action, Decision, Verdict};
use serde_json::Value;
use thiserror::Error;

use glob::{below, bounded, glob_reach};

pub use host::Host;

/// Session id recorded when a host omits it.
const UNKNOWN_SESSION: &str = "unknown";

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
/// when given, so either spelling is checked. A relative pattern that climbs
/// out of the searched directory (`../..`) reads where it climbs to as well.
fn glob_roots(input: &Value, cwd: Option<&str>) -> Action {
    let pattern = input.get("pattern").and_then(Value::as_str).unwrap_or("");
    let root = search_path(input).or(cwd).unwrap_or(".");
    let mut paths = match (pattern_dir(pattern), search_path(input)) {
        (Some(dir), Some(path)) => vec![path.to_owned(), dir],
        (Some(dir), None) => vec![dir],
        (None, _) => vec![root.to_owned()],
    };
    paths.extend(glob_reach(root, pattern));
    let action = match paths.len() {
        1 => Action::FsRead {
            path: paths.remove(0),
        },
        _ => Action::ReadFiles { paths },
    };
    bounded(action, [pattern])
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

impl Host {
    /// The facts about this host.
    #[must_use]
    pub fn spec(self) -> &'static HostSpec {
        registry::spec(self)
    }

    /// The identifier used on the command line and in the audit log.
    #[must_use]
    pub fn id(self) -> &'static str {
        self.spec().id
    }

    /// The product name shown to people.
    #[must_use]
    pub fn display_name(self) -> &'static str {
        self.spec().display_name
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
        registry::adapter(self).parse(self, envelope.hook_event_name.as_deref(), payload)
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
            Ok(e) => registry::adapter(self).event_of(&e.hook_event_name),
            Err(_) => HookEvent::PreToolUse,
        }
    }

    /// The decision to record and answer for `event` (ADR-025): a `defer` where
    /// the host has no flow that decides by itself is an `ask`
    /// ([`Asks::defer_is_ask_on_no_ask`]).
    #[must_use]
    pub fn decided(self, event: &HookEvent, decision: Decision) -> Decision {
        contract::decided(self.spec(), event, decision)
    }

    /// The decision as this host has to receive it: where the host cannot ask
    /// ([`HostSpec::asks`]), an `ask` reaches it as a `deny` that says how to
    /// approve it.
    #[must_use]
    pub fn answer(self, event: &HookEvent, decision: &Decision) -> Decision {
        contract::answer(self.spec(), event, decision)
    }

    /// Render the response document the host expects on stdout for `event`.
    #[must_use]
    pub fn render_response(self, event: &HookEvent, decision: &Decision) -> String {
        registry::adapter(self).render(event, decision)
    }

    /// The hook payload this host sends for `call` at `at`, or `None` when it
    /// has no tool for it (Codex reads files through its shell; only Claude
    /// Code and OpenClaw fetch).
    #[must_use]
    pub fn bench_payload(self, call: &bench::Call, at: &bench::Place<'_>) -> Option<String> {
        registry::adapter(self).bench_payload(call, at)
    }

    /// What this host does with the hook's reply to `call`.
    #[must_use]
    pub fn read_reply(self, call: &bench::Call, exit: &bench::Exit<'_>) -> bench::Answer {
        registry::adapter(self).read_reply(call, exit)
    }

    /// What this host must end up doing when OpenMoat decides `verdict` on
    /// `call`: where it cannot ask, an `ask` arrives as a blocking `deny`.
    #[must_use]
    pub fn seen(self, call: &bench::Call, verdict: Verdict) -> bench::Answer {
        registry::adapter(self).seen(call, verdict)
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
    /// Claude Code in a permission mode that puts no question to a person
    /// (`bypassPermissions`, `dontAsk`) sends this too; there a `defer` stays a
    /// `defer` ([`Host::decided`] turns it into an `ask` for Cursor only).
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
    /// The whole new content of the one file the call writes, when the tool
    /// sends it (Claude Code `Write`): file provenance (ADR-029) records its
    /// hash. `None` for a tool that changes part of a file (`Edit`) or names
    /// no content.
    pub content: Option<String>,
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
    #[error("unknown host `{0}`; supported: {supported}", supported = supported_hosts())]
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

/// The ids `--host` takes, in [`Host::ALL`] order.
fn supported_hosts() -> String {
    Host::ALL.map(Host::id).join(", ")
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

    /// Every host's spec names it once and round-trips through its id; a host
    /// that speaks another's format speaks a host with a format of its own.
    #[test]
    fn every_spec_names_its_host() {
        let all = Host::EVERY;
        for (i, host) in all.into_iter().enumerate() {
            let spec = host.spec();
            assert_eq!(host.to_string(), spec.id);
            assert!(!spec.display_name.is_empty(), "{host:?}");
            assert!(all[..i].iter().all(|h| h.id() != spec.id), "{host:?}");
            if Host::ALL.contains(&host) {
                assert_eq!(spec.id.parse::<Host>().unwrap(), host);
            }
            if let Some(wire) = spec.speaks {
                assert_eq!(wire.spec().speaks, None, "{host:?}");
            }
        }
    }

    /// The unknown-host message lists every `--host` id, as it always has.
    #[test]
    fn unknown_host_lists_every_installable_host() {
        let error = "nope".parse::<Host>().unwrap_err();
        assert_eq!(
            error.to_string(),
            "unknown host `nope`; supported: claude-code, codex, cursor, openclaw, \
             copilot-cli, pi, gemini-cli, opencode, hermes"
        );
    }

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
