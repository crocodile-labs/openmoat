//! What every host adapter declares: the facts about a host as data
//! ([`HostSpec`]), and the one place an `ask` or `defer` is turned into what
//! the host can act on ([`answer`], [`decided`]).

use openmoat_core::{Decision, Verdict};

use crate::bench::{Answer, Call, Exit, Place};
use crate::{HookEvent, HookRequest, Host, HostError};

/// The code each host format needs beyond its [`HostSpec`]: reading a payload
/// and writing the response. One per format; a host that sends another's
/// format ([`HostSpec::speaks`]) uses that host's adapter.
pub(crate) trait HostAdapter: Sync {
    /// The facts about the host whose format this is.
    fn spec(&self) -> &'static HostSpec;

    /// The request in `payload`, sent by `host` for the hook named `event`
    /// (`None` when the payload names none).
    fn parse(
        &self,
        host: Host,
        event: Option<&str>,
        payload: &str,
    ) -> Result<HookRequest, HostError>;

    /// The event a payload whose hook is named `event` is answered for, even
    /// when it fails [`HostAdapter::parse`].
    fn event_of(&self, _event: &str) -> HookEvent {
        HookEvent::PreToolUse
    }

    /// The response document the host expects on stdout.
    fn render(&self, event: &HookEvent, decision: &Decision) -> String;

    /// The hook payload the host sends for `call` at `at`, or `None` when the
    /// host has no tool for it.
    fn bench_payload(&self, call: &Call, at: &Place<'_>) -> Option<String>;

    /// What the host does with the hook's reply to `call`.
    fn read_reply(&self, call: &Call, exit: &Exit<'_>) -> Answer;

    /// What the host must end up doing when OpenMoat decides `verdict` on `call`.
    fn seen(&self, _call: &Call, verdict: Verdict) -> Answer {
        verdict.into()
    }
}

/// The error for a payload whose hook this format does not handle.
pub(crate) fn wrong_event(event: Option<&str>) -> HostError {
    HostError::WrongEvent(event.unwrap_or_default().to_owned())
}

/// How a person approves a call a host could not ask about. Every host that
/// receives an `ask` as a `deny` ends its reason with this.
const HOW_TO_APPROVE: &str = "run `moat` to approve it, or `moat allow --last` (this session) \
     or `moat allow --last --always`, then retry";

/// The facts about one host. Code covers only what a fact cannot say.
#[derive(Debug)]
#[non_exhaustive]
pub struct HostSpec {
    /// The identifier used on the command line and in the audit log.
    pub id: &'static str,
    /// The product name shown to people.
    pub display_name: &'static str,
    /// The host whose hook format this host sends, when it is another host's
    /// (`cn` sends Claude Code's).
    pub speaks: Option<Host>,
    /// What the host does with an `ask` on each kind of tool hook.
    pub asks: Asks,
    /// What the host does when its hook is missing, crashes or times out, as
    /// `docs/THREAT_MODEL.md` §5 ("When the hook fails") says; change them together.
    pub on_hook_failure: &'static str,
    /// What the hook and sandbox do not cover for this host, and what it does
    /// when the hook fails, as `moat status` and `moat doctor` report it.
    /// Mirrors README "Limits" and `docs/THREAT_MODEL.md` §5; change them together.
    pub gaps: &'static str,
    /// Where `moat init` installs the hook; `None` for a host that runs another
    /// host's hook.
    pub install: Option<InstallSpec>,
    /// Where the host reads its MCP server definitions; `None` for a host
    /// OpenMoat reads none of.
    pub mcp: Option<McpSpec>,
    /// The OS sandbox OpenMoat configures inside the host (the Standard tier);
    /// `None` for a host it configures none for.
    pub sandbox: Option<SandboxSpec>,
}

/// Where a host keeps the configuration `moat init` writes its hook into.
#[derive(Debug)]
#[non_exhaustive]
pub struct InstallSpec {
    /// The environment variable that moves the configuration directory.
    pub dir_variable: &'static str,
    /// The directory's name under the home directory otherwise.
    pub dir_name: &'static str,
    /// The file in that directory the hook goes into.
    pub config_file: &'static str,
}

/// Where a host reads its MCP server definitions. A file that does not exist
/// lists no servers.
#[derive(Debug)]
#[non_exhaustive]
pub struct McpSpec {
    /// The user-level file, in or beside the host's configuration.
    pub user_file: McpFile,
    /// How that file lays out its servers.
    pub user_layout: McpLayout,
    /// A project's file, relative to the working directory and each directory
    /// above it up to the project root, and its layout; `None` when the host
    /// documents none.
    pub project_file: Option<(&'static str, McpLayout)>,
}

/// Where a host's user-level MCP server file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpFile {
    /// The file the hook goes into, wherever the host's configuration puts it.
    HookFile,
    /// The file of this name beside the hook file.
    BesideHookFile(&'static str),
    /// The file of this name in the home directory while the configuration
    /// directory is the default `~/<dir_name>`, inside the configuration
    /// directory otherwise (Claude Code's `~/.claude.json`).
    BesideDefaultDir(&'static str),
}

/// How a file lays out its MCP servers. The CLI has one reader per layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpLayout {
    /// `{"mcpServers": {"<name>": {...}}}`: `.mcp.json`, Cursor's `mcp.json`.
    Json,
    /// `~/.claude.json`: `mcpServers`, and `projects.<path>.mcpServers`.
    ClaudeJson,
    /// Codex `config.toml`: `[mcp_servers.<name>]`.
    Toml,
    /// OpenClaw `openclaw.json`, JSON5: `{mcp: {servers: {"<name>": {...}}}}`.
    OpenClaw,
}

/// The OS sandbox OpenMoat writes into a host's own settings.
#[derive(Debug)]
#[non_exhaustive]
pub struct SandboxSpec {
    /// The format of the settings, which names the backend that writes them.
    pub format: SandboxFormat,
    /// The file beside the hook file the settings go into (the hook file
    /// itself when it has the hook file's name).
    pub file: &'static str,
    /// Why the sandbox is not written on native Windows, as `init`, `sandbox`,
    /// `doctor` and `status` print it; `None` when it is written there.
    pub unavailable_on_windows: Option<&'static str>,
}

/// A host's sandbox settings format. The CLI has one backend per format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxFormat {
    /// Claude Code's `sandbox` block and permission rules, in the file that
    /// holds its hooks; `moat uninstall` removes them with the hooks.
    ClaudeSettings,
    /// OpenMoat's permissions profile in Codex's `config.toml`, which the lock
    /// pins by the part OpenMoat owns.
    CodexProfile,
    /// Cursor's `sandbox.json`, which the lock pins whole.
    CursorSandbox,
}

/// What a host does with an `ask` (and a `defer`, ADR-025) on a tool hook.
#[derive(Debug)]
#[non_exhaustive]
pub struct Asks {
    /// On [`HookEvent::PreToolUse`]: `None` when the host puts the question to a
    /// person, else why it cannot, which the `deny` it receives instead says.
    pub on_pre_tool_use: Option<&'static str>,
    /// The same for [`HookEvent::PreToolUseNoAsk`].
    pub on_no_ask: Option<&'static str>,
    /// Whether a `defer` on [`HookEvent::PreToolUseNoAsk`] is an `ask`: the
    /// host has no flow of its own there that decides.
    pub defer_is_ask_on_no_ask: bool,
}

/// The decision to record for `event` on the host `spec` describes. A `defer`
/// needs a host flow that decides by itself; where there is none, OpenMoat
/// asks itself: the `ask` is recorded, and [`answer`] sends it as a deny that
/// says how to approve it.
pub(crate) fn decided(spec: &HostSpec, event: &HookEvent, mut decision: Decision) -> Decision {
    if spec.asks.defer_is_ask_on_no_ask
        && *event == HookEvent::PreToolUseNoAsk
        && decision.verdict == Verdict::Defer
    {
        decision.verdict = Verdict::Ask;
    }
    decision
}

/// The decision as the host `spec` describes has to receive it. Where the host
/// cannot ask, an `ask` reaches it as a `deny` that says how to approve it; the
/// audit log keeps the `ask`, which is what `moat allow --last` looks for.
pub(crate) fn answer(spec: &HostSpec, event: &HookEvent, decision: &Decision) -> Decision {
    let why = match event {
        HookEvent::PreToolUse => spec.asks.on_pre_tool_use,
        HookEvent::PreToolUseNoAsk => spec.asks.on_no_ask,
        HookEvent::ConfigChange { .. } => None,
    };
    let mut answer = decision.clone();
    if let Some(why) = why
        && decision.verdict == Verdict::Ask
    {
        answer.verdict = Verdict::Deny;
        answer.reasons.push(format!(
            "this needs your approval and {why}: {HOW_TO_APPROVE}"
        ));
    }
    answer
}
