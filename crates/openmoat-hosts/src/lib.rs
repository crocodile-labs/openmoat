//! Host adapters: the only place that knows each agent's hook wire format.
//!
//! An adapter translates a host payload into a [`HookRequest`] and a
//! [`Decision`] back into the host's response document. Adapters never
//! decide; `openmoat-core` does.

#![warn(missing_docs)]
// A library reports to its caller; only the `moat` binary prints.
#![warn(clippy::print_stdout, clippy::print_stderr)]

pub mod bench;
mod block;
mod contract;
mod glob;
mod host;
mod program;
mod registry;
mod request;
mod wire;

pub use block::{NEVER_SUGGESTED, RULE_PAGE, rule_page};
pub use contract::{
    Activity, Advisories, Advisory, AlsoDir, AutoStart, Bundle, ConsentFile, Detect, ExtraFile,
    FailureOutcome, GUARD_BUDGET_S, HEARTBEAT_FLAG, Heartbeat, Helper, HookDir, HookFailure,
    HookLayout, HookSpec, HookTrust, HookVersions, HostDocs, HostSpec, InstallSpec, KeyShape,
    Locate, Located, Location, McpAutoStart, McpCommandForm, McpFile, McpNames, McpReader,
    McpServer, McpSpec, McpSyntax, OtherHooks, Paths, Platform, PluginDir, ProcessSpec,
    ProjectSettingsSpec, Protect,
    ProxySessions, RelaxedKey, Reviews, RunFacts, RunWrite, SandboxFormat, SandboxSpec, SessionDir,
    SettingsFile, SettingsReader, SystemFile, SystemSettingsSpec, ToolRow, ToolToken, Unseen,
    Version,
};
pub use host::claude_code::config_change::proposal_target;
pub use host::claude_code::project_settings::findings as claude_code_settings_findings;
pub use wire::guard_command::{GuardCommand, HOME_FLAG, decode_home, encode_home};
pub use wire::hook_file::yaml as yaml_hooks;
pub use wire::hook_file::{HookFile, HookFileError, HookFileState, HookOutcome};
pub use wire::mcp_call::{
    canonical_json, mcp_call_action, mcp_call_arguments, mcp_resource_action, mcp_tool_acts,
    mcp_tools_list_request,
};
pub use wire::owned_file::{OwnedFile, OwnedFileError, Syntax};
pub use wire::plugin_config::PluginConfig;

use std::fmt;
use std::str::FromStr;

use openmoat_core::{Action, Decision, Verdict};
use serde_json::Value;
use thiserror::Error;

use glob::{below, bounded, glob_reach};

pub use host::Host;

/// Session id recorded when a host omits it.
const UNKNOWN_SESSION: &str = "unknown";

/// What the agent and its person read about `decision`, in every host's
/// reason field: the block message (ADR-059) for a `deny` or `review` whose
/// decision carries a [`openmoat_core::Notice`], else one line: verdict, rule
/// ids, then the reasons. The block's `rule` line is that one line.
#[must_use]
pub fn reason_line(decision: &Decision) -> String {
    block::message(decision).unwrap_or_else(|| block::line(decision, &decision.reasons.join("; ")))
}

/// Words that make a tool name write-shaped (`write_file`, `DeleteDirectory`):
/// the paths such a tool names are checked as written, not read. A browser's
/// screenshot, snapshot or trace tool writes the file its path names (Chrome
/// DevTools MCP `take_screenshot {filePath}`, Playwright MCP
/// `browser_take_screenshot {filename}`).
const WRITE_VERBS: &[&str] = &[
    "write",
    "edit",
    "create",
    "move",
    "rename",
    "delete",
    "remove",
    "append",
    "mkdir",
    "copy",
    "save",
    "patch",
    "update",
    "download",
    "screenshot",
    "snapshot",
    "trace",
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
            hook_event_name: Option<String>,
            /// Cline names the event in `hookName`.
            #[serde(rename = "hookName")]
            hook_name: Option<String>,
        }
        match serde_json::from_str::<Envelope>(payload) {
            Ok(e) => match e.hook_event_name.or(e.hook_name) {
                Some(event) => registry::adapter(self).event_of(&event),
                None => HookEvent::PreToolUse,
            },
            Err(_) => HookEvent::PreToolUse,
        }
    }

    /// The decision to record and answer for `event` (ADR-025): a `defer` where
    /// the host has no flow that decides by itself is a `review`
    /// ([`Reviews::defer_is_review_on_no_prompt`]).
    #[must_use]
    pub fn decided(self, event: &HookEvent, decision: Decision) -> Decision {
        contract::decided(self.spec(), event, decision)
    }

    /// The decision as this host has to receive it: where the host cannot prompt
    /// ([`HostSpec::reviews`]), a `review` reaches it as a `deny` that says how to
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

    /// [`Host::render_response`] for the call `request` describes: a host
    /// whose answer names the call (Hermes Agent's approval key) or depends on
    /// how the host runs it (Cursor's sandbox) reads it from there.
    #[must_use]
    pub fn render_response_for(self, request: &HookRequest, decision: &Decision) -> String {
        registry::adapter(self).render_for(request, decision)
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
    /// `call`: where it cannot prompt, a `review` arrives as a blocking `deny`.
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
    /// A tool is about to run under a hook that ignores `"ask"`: Cursor `preToolUse`
    /// accepts it but runs the call, and `beforeReadFile` takes only allow or deny.
    /// Claude Code in a permission mode that puts no question to a person
    /// (`bypassPermissions`, `dontAsk`) sends this too; there a `defer` stays a
    /// `defer` ([`Host::decided`] turns it into a `review` for Cursor only).
    PreToolUseNoPrompt,
    /// A host settings file changed on disk (Claude Code only).
    ConfigChange {
        /// Which settings scope changed (`user_settings`, `project_settings`, …).
        source: String,
        /// The kind of change, when the host reports one (earlier Claude Code builds).
        change_type: Option<String>,
    },
    /// A session started, resumed, or began again after `/clear` or a
    /// compaction (Claude Code only): no call to decide; OpenMoat gives the
    /// session its `openmoat proxy` credential (ADR-044).
    SessionStart {
        /// Why it started (`startup`, `resume`, `clear`, `compact`).
        source: String,
    },
    /// A tool ran and the host reports what it returned (Claude Code
    /// `PostToolUse`): nothing to decide; OpenMoat keeps fingerprints of
    /// untrusted output for later calls (ADR-057).
    PostToolUse {
        /// The tool's output as text: every string the host's `tool_response`
        /// holds, joined by newlines, at most
        /// [`openmoat_core::MAX_INJECTED_SCAN_BYTES`].
        output: String,
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
    /// The directory the call is decided from, when the host sends it: the
    /// session's working directory, whose project is `${project}`. Where a
    /// host sends the directory the tool runs in, which the model chooses
    /// (Codex, Cursor), and it lies outside the session's project, the
    /// request is moved to the session's directory
    /// ([`HookRequest::from_session_dir`]) and the action carries where the
    /// tool runs.
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
    /// The replacements a partial edit of the one file makes, in order (Claude
    /// Code `Edit`, each entry of `MultiEdit`): the guard applies them to the
    /// file as it is to learn the content the call leaves (ADR-048). Empty
    /// for every other tool.
    pub edits: Vec<Replacement>,
    /// The `apply_patch` envelope the call applies, when the tool sends one
    /// (Codex `apply_patch`, OpenCode `apply_patch` and `patch`): the guard
    /// replays it on the files as they are to learn the content it leaves
    /// ([`openmoat_core::patch_replay`]). `None` for every other tool.
    pub patch: Option<String>,
    /// For an MCP tool call, its arguments as [`mcp_call_arguments`] reads
    /// them: `openmoat mcp proxy` passes a call on to the server only when it
    /// matches one the hook decided (ADR-045). `None` for any other call.
    pub mcp_arguments: Option<String>,
    /// Whether the host says it runs the call inside its own OS sandbox
    /// (Cursor `beforeShellExecution` `sandbox: true`). The guard clears it
    /// when OpenMoat's sandbox settings for the host are not installed; while
    /// set, a host whose hooks have no "no decision" may answer a `defer` as
    /// the host would without a hook.
    pub sandboxed: bool,
    /// Which hook fired.
    pub event: HookEvent,
}

/// One replacement a partial edit makes: `old` becomes `new`, once (`old` must
/// then occur exactly once, as Claude Code requires) or everywhere (`all`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replacement {
    /// The text to find.
    pub old: String,
    /// What replaces it.
    pub new: String,
    /// Replace every occurrence (`replace_all`), not exactly one.
    pub all: bool,
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
    use super::Host;

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
             copilot-cli, pi, gemini-cli, opencode, hermes, cline, goose, antigravity-cli"
        );
    }
}
