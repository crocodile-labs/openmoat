//! What every host adapter declares: the facts about a host as data
//! ([`HostSpec`]), and the one place an `ask` or `defer` is turned into what
//! the host can act on ([`answer`], [`decided`]).

use openmoat_core::{Decision, Verdict};

use crate::bench::{Answer, Call, Exit, Place};
use crate::{HookEvent, HookRequest, Host, HostError};

mod asks;
mod base;
mod docs;
mod hook_file;
mod location;
mod mcp;
mod protect;
mod relaxed;
mod settings;

pub use asks::Asks;
pub(crate) use asks::{answer, decided};
pub use docs::{HostDocs, ToolRow};
pub use location::{Locate, Located, Location};
pub use mcp::{McpFile, McpNames, McpReader, McpServer, McpSpec, McpSyntax};
pub(crate) use mcp::{McpServersJson, Prefixed, escape, server, servers_at, spelled};
pub use protect::{Helper, Paths, ProcessSpec, Protect};
pub use relaxed::{KeyShape, RelaxedKey};
pub(crate) use settings::set;
pub use settings::{SettingsFile, SettingsReader};

/// The code each host format needs beyond its [`HostSpec`]: reading a payload
/// and writing the response. One per format; a host that sends another's
/// format ([`HostSpec::speaks`]) uses that host's adapter.
pub(crate) trait HostAdapter: Sync {
    /// The facts about the host whose format this is.
    #[cfg_attr(not(test), expect(dead_code, reason = "lookups read the host list"))]
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
    /// How to tell the host is present when it has no hook of its own to
    /// install, so `moat status` and `moat doctor` can name its [`Self::gaps`].
    pub detect: Option<Detect>,
    /// How the person resumes an agent session after `moat allow` granted it
    /// something, which `moat allow` adds after "a new session asks again".
    pub resume_hint: Option<&'static str>,
    /// The host's own files the default policy's `kernel-self` rule and the
    /// taint list protect, in their generated blocks (`tests/protect.rs`).
    pub protect: Protect,
    /// How to tell the host's process among a command's ancestors.
    pub process: ProcessSpec,
    /// What the generated host tables of the docs say (`tests/docs.rs`).
    pub docs: HostDocs,
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
    /// A second file the host reads from that directory: the person's own,
    /// kept out of version control (Claude Code's `settings.local.json`), or
    /// another file of the project's (Codex's `hooks.json`); `None` when the
    /// host reads none.
    pub local: Option<&'static str>,
    /// A directory of the project whose files the host loads as hooks or
    /// extensions (GitHub Copilot CLI's `.github/hooks`, pi's `.pi/extensions`);
    /// `None` when it has none.
    pub hook_dir: Option<HookDir>,
    /// Which keys of these files turn OpenMoat's hook off, run a program or
    /// redirect the agent; one reader per host folder.
    pub reader: &'static dyn SettingsReader,
    /// The person's own settings file in the configuration directory, read
    /// in the same format: what in it turns OpenMoat's hook off is reported
    /// by `moat status` and `moat doctor` as "not protected". For Claude Code
    /// and Gemini CLI it is the hook file itself.
    pub user_file: &'static str,
}

impl ProjectSettingsSpec {
    /// The files of a project's settings directory, the shared one first.
    #[must_use]
    pub fn files(&self) -> Vec<&'static str> {
        std::iter::once(self.shared).chain(self.local).collect()
    }
}

/// A directory of a project whose files a host loads and runs.
#[derive(Debug)]
#[non_exhaustive]
pub struct HookDir {
    /// The directory, relative to the project.
    pub path: &'static str,
    /// The file name extensions it loads (`json`, or `js` and `ts`).
    pub extensions: &'static [&'static str],
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
    /// What the person must do in the host after `moat init` writes or changes
    /// its hook entry before the host runs it, when the host keeps a record
    /// of its own that OpenMoat cannot see; `moat doctor` repeats it.
    pub trust_step: Option<&'static str>,
    /// How the CLI finds the directory and the file.
    pub location: Location,
    /// The form of the file, read as JSON5, the lock pins in place of its
    /// bytes, when the file holds what this host's hook needs: `None` from
    /// the function for any other file, and no function for a host whose
    /// file is pinned by its bytes. OpenClaw's leaves out `mcp.servers`,
    /// whose servers the MCP pins hold one by one.
    pub pinned_form: Option<fn(serde_json::Value) -> Option<serde_json::Value>>,
    /// Files besides the hook file that `moat init` writes and the lock pins
    /// with it (OpenClaw's plugin); the sandbox file is [`SandboxSpec::file`].
    pub extra_files: &'static [ExtraFile],
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
/// like [`SandboxFormat`] the enum is exhaustive, so a new
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
    /// Whether the sandbox lets a command type into the terminal (`TIOCSTI`)
    /// on Linux, so only the kernel stops it, as `moat doctor` warns.
    pub tiocsti_open_on_linux: bool,
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

/// A file besides the hook file that `moat init` writes for a host and the
/// lock pins as one of its hook files ([`InstallSpec::extra_files`]). Like
/// [`HookFormat`] the enum is exhaustive, so a new kind fails to compile in
/// the CLI until it says where the file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtraFile {
    /// The file at this path under the host's configuration directory, one
    /// name per directory level (OpenClaw's plugin).
    InConfigDir(&'static [&'static str]),
}

/// How to tell that a host with no hook of its own to install is present on
/// this machine ([`HostSpec::detect`]): its directory, or its program on the
/// search path.
#[derive(Debug)]
#[non_exhaustive]
pub struct Detect {
    /// The environment variable that moves the host's directory.
    pub dir_variable: &'static str,
    /// The directory's name under the home directory otherwise.
    pub dir_name: &'static str,
    /// The host's program, looked for on the search path.
    pub binary: &'static str,
}
