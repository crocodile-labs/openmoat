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
const HOW_TO_APPROVE: &str = "run `openmoat` to approve it, or `openmoat allow --last` (this session) \
     or `openmoat allow --last --always`, then retry";

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
    /// Mirrors README "Limits" and `docs/THREAT_MODEL.md` §5, whose per-host
    /// list of it and of [`Self::on_hook_failure`] is generated (`tests/docs.rs`);
    /// change README with it.
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
    /// The settings files the host reads from a project and merges over the
    /// user settings OpenMoat pins; `None` for a host OpenMoat checks none of.
    pub project_settings: Option<ProjectSettingsSpec>,
}

/// Where a host reads a project's own settings. They come from the repository,
/// so OpenMoat does not pin them: `moat doctor` and `moat status` warn about
/// what one sets, and a host's settings-change hook may veto loading one.
#[derive(Debug)]
#[non_exhaustive]
pub struct ProjectSettingsSpec {
    /// The directory holding them, in the working directory and in the
    /// project root.
    pub dir: &'static str,
    /// The file shared with the project.
    pub shared: &'static str,
    /// The person's own file, kept out of version control.
    pub local: &'static str,
    /// A directory of the project whose every `*.json` file the host loads as
    /// hooks (GitHub Copilot CLI's `.github/hooks`); `None` when it has none.
    pub hook_dir: Option<&'static str>,
}

impl ProjectSettingsSpec {
    /// Both files, the shared one first.
    #[must_use]
    pub const fn files(&self) -> [&'static str; 2] {
        [self.shared, self.local]
    }
}

/// Where a host keeps the configuration `moat init` writes its hook into.
#[derive(Debug)]
#[non_exhaustive]
pub struct InstallSpec {
    /// The environment variable that moves the configuration directory (for
    /// [`HookFormat::Gemini`], the home directory it is in:
    /// [`InstallSpec::variable_names_home`]).
    pub dir_variable: &'static str,
    /// The directory's name under the home directory otherwise.
    pub dir_name: &'static str,
    /// The file in that directory the hook goes into.
    pub config_file: &'static str,
    /// The hook entries `moat init` writes into that file, one per event.
    pub hooks: &'static [HookSpec],
    /// How that file lays out the entries.
    pub hook_format: HookFormat,
    /// Keys of that file the host rewrites itself for a person's choice (a
    /// model, a theme, a sign-in method) and that change no OpenMoat decision.
    /// When the pinned file drifted in these keys only, each holding a value
    /// of its [`RelaxedKey::shape`], `moat guard` keeps deciding every call and
    /// `moat doctor` reports the drift; any other change still denies them all.
    /// Only keys that cannot run a program, change a hook, the sandbox, MCP
    /// servers, tools, the files the agent may touch or the network belong
    /// here. Found by the file's path ending in `<dir_name>/<config_file>`.
    /// Empty for most hosts; Claude Code's own list, with its permission
    /// lists, is the CLI's (`integrity/relaxed.rs`).
    pub relaxed_keys: &'static [RelaxedKey],
}

/// A key of a host's hook file that may drift while the guard keeps deciding
/// ([`InstallSpec::relaxed_keys`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelaxedKey {
    /// The key's path from the top of the file, its names joined by `.`
    /// (`model.name` is `{"model": {"name": …}}`).
    pub path: &'static str,
    /// The only kind of value it may change to.
    pub shape: KeyShape,
}

impl RelaxedKey {
    /// A key whose value is a string.
    #[must_use]
    pub const fn string(path: &'static str) -> Self {
        Self {
            path,
            shape: KeyShape::String,
        }
    }

    /// A key whose value is `true` or `false`.
    #[must_use]
    pub const fn flag(path: &'static str) -> Self {
        Self {
            path,
            shape: KeyShape::Bool,
        }
    }
}

/// The kind of value a [`RelaxedKey`] may hold. A value of any other kind, an
/// object or a list among them, is drift like any other key's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyShape {
    /// A JSON string.
    String,
    /// A JSON boolean.
    Bool,
}

impl KeyShape {
    /// Whether `value` is of this kind.
    #[must_use]
    pub fn holds(self, value: &serde_json::Value) -> bool {
        match self {
            Self::String => value.is_string(),
            Self::Bool => value.is_boolean(),
        }
    }
}

impl InstallSpec {
    /// Whether [`Self::dir_variable`] names a home directory that holds
    /// [`Self::dir_name`] rather than the configuration directory itself, as
    /// Gemini CLI's `GEMINI_CLI_HOME` does.
    #[must_use]
    pub fn variable_names_home(&self) -> bool {
        self.hook_format == HookFormat::Gemini
    }
}

/// Seconds `moat guard` may take before it denies on its own. A host that times
/// a hook out treats it as failed, and Claude Code, Codex and the Continue CLI
/// then run the call; below every hook timeout a spec sets, so the host gets the
/// deny (the contract test checks every host).
///
/// The watchdog measures wall-clock time, which includes the time the guard
/// waits to be scheduled. A guard decides in 10–20 ms, but on a machine loaded
/// by parallel builds (load average near 100) a call can wait seconds for a CPU
/// and for the audit database's lock; 10 s denied such calls that were only
/// slow. 30 s leaves room for that and stays half the settings-change timeout.
pub const GUARD_BUDGET_S: u64 = 30;

/// Seconds a host waits for a tool-call hook. Long enough for a person to
/// answer an `ask` prompted by the host; Claude Code and Codex default to 600.
pub(crate) const TOOL_HOOK_TIMEOUT_S: u64 = 600;
/// Seconds for the settings-change veto, which never waits for a person.
pub(crate) const CONFIG_HOOK_TIMEOUT_S: u64 = 60;
const _: () = assert!(GUARD_BUDGET_S < CONFIG_HOOK_TIMEOUT_S);
const _: () = assert!(GUARD_BUDGET_S < TOOL_HOOK_TIMEOUT_S);

/// One hook entry OpenMoat owns in a host's configuration.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct HookSpec {
    /// Host event name, e.g. `PreToolUse`.
    pub event: &'static str,
    /// Host matcher expression for that event.
    pub matcher: &'static str,
    /// Seconds the host waits for `moat guard` before treating it as failed.
    pub timeout: u64,
    /// Whether the entry asks the host to block the call when `moat guard`
    /// fails to run, crashes or times out (Claude Code `onFailure`), where the
    /// host's version knows the key (the CLI asks the `claude` on `PATH`).
    pub block_on_failure: bool,
}

impl HookSpec {
    /// The entry for `event` and `matcher`, waited for `timeout` seconds.
    #[must_use]
    pub const fn new(
        event: &'static str,
        matcher: &'static str,
        timeout: u64,
        block_on_failure: bool,
    ) -> Self {
        Self {
            event,
            matcher,
            timeout,
            block_on_failure,
        }
    }
}

/// How a host's hook file is laid out. The CLI writes and reads each layout;
/// like [`McpLayout`] and [`SandboxFormat`] the enum is exhaustive, so a new
/// layout fails to compile at every CLI `match` until it has its arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookFormat {
    /// `{"hooks": {"<Event>": [{"matcher", "hooks": [{type, command, args, timeout}]}]}}`
    /// (Claude Code `settings.json`, Codex `hooks.json`).
    Nested,
    /// `{"version": 1, "hooks": {"<event>": [{"command": "<shell string>", "timeout", "failClosed"}]}}`
    /// (Cursor `hooks.json`). Cursor is fail-open unless `failClosed` is set,
    /// so every entry of this layout sets it.
    Cursor,
    /// OpenClaw `openclaw.json`: OpenMoat's plugin file in `plugins.load.paths`
    /// and its `plugins.entries.openmoat`, at the location OpenClaw's own
    /// variables give.
    OpenClaw,
    /// GitHub Copilot CLI: a hook file of OpenMoat's own in its hooks
    /// directory, `{"version": 1, "hooks": {"<event>": [{"type": "command",
    /// "bash", "powershell", "timeoutSec"}]}}`, with no `matcher` (the CLI
    /// skips an entry whose matcher is empty).
    Copilot,
    /// pi: the hook file is OpenMoat's extension itself, which pi loads from
    /// its agent directory's `extensions/`; the whole file is OpenMoat's.
    Pi,
    /// Gemini CLI `settings.json`: `{"hooks": {"<Event>": [{"matcher", "hooks":
    /// [{name, type, command, timeout}]}]}}`, with `command` one shell string
    /// (bash, PowerShell on Windows) and `timeout` in milliseconds. Gemini CLI
    /// has no fail-closed key. Its [`InstallSpec::dir_variable`]
    /// (`GEMINI_CLI_HOME`) names the home directory `dir_name` is in, not that
    /// directory.
    Gemini,
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
