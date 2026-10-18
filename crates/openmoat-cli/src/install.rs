//! Host hook installation.

mod binary;
mod claude_version;
mod dirs;
mod hook_file;
pub mod self_paths;

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use openmoat_hosts::Host;

pub use binary::{hook_binary, stale_hint};
pub use dirs::Recorded;
pub use hook_file::{HookState, Outcome, read_or_empty};

use crate::home::{Home, user_home};

/// Suffix of the copy of a host file taken before OpenMoat's hook edit changes it.
pub const HOOK_BACKUP: &str = "moat-backup";
/// Suffix of the copy taken before OpenMoat's sandbox edit changes it.
pub const SANDBOX_BACKUP: &str = "moat-sandbox-backup";

/// The copy of `path` named `<path>.<suffix>`.
pub fn backup_path(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".");
    name.push(suffix);
    PathBuf::from(name)
}

/// Copy `path` to its `suffix` backup before OpenMoat edits it, unless
/// something is at the backup's name, and record the copy in `hosts.json`.
/// The first one holds the file as it was before OpenMoat touched it; a later
/// copy would replace it with an already edited file. A file of the user's at
/// that name is left alone, and a link there is never followed.
pub fn back_up(home: &Home, path: &Path, suffix: &str) -> Result<()> {
    let backup = backup_path(path, suffix);
    if !path.exists() || fs::symlink_metadata(&backup).is_ok() {
        return Ok(());
    }
    fs::copy(path, &backup).with_context(|| format!("backing up {}", path.display()))?;
    let mut recorded = Recorded::load(home)?;
    recorded.backups.push(backup);
    recorded.save(home)
}

/// The files at `path`'s backup names, hook backup first. OpenMoat created
/// only those [`Recorded::owns`]; any of them may still hold the original.
pub fn backups(path: &Path) -> Vec<PathBuf> {
    [HOOK_BACKUP, SANDBOX_BACKUP]
        .into_iter()
        .map(|suffix| backup_path(path, suffix))
        .filter(|p| p.is_file())
        .collect()
}

/// One hook entry we own in a host's configuration.
#[derive(Debug, Clone, Copy)]
pub struct HookSpec {
    /// Host event name, e.g. `PreToolUse`.
    pub event: &'static str,
    /// Host matcher expression for that event.
    pub matcher: &'static str,
    /// Seconds the host waits for `moat guard` before treating it as failed.
    pub timeout: u64,
    /// Whether the entry asks the host to block the call when `moat guard`
    /// fails to run, crashes or times out (Claude Code `onFailure`), where the
    /// host's version knows the key ([`HostConfig::blocks_on_failure`]).
    pub block_on_failure: bool,
}

/// Seconds a host waits for a tool-call hook. Long enough for a person to
/// answer an `ask` prompted by the host; Claude Code and Codex default to 600.
const TOOL_HOOK_TIMEOUT_S: u64 = 600;
/// Seconds for the settings-change veto, which never waits for a person.
const CONFIG_HOOK_TIMEOUT_S: u64 = 60;
/// Seconds `moat guard` may take before it denies on its own. A host that times
/// a hook out treats it as failed, and Claude Code, Codex and the Continue CLI
/// then run the call; below every timeout above, so the host gets the deny.
///
/// The watchdog measures wall-clock time, which includes the time the guard
/// waits to be scheduled. A guard decides in 10–20 ms, but on a machine loaded
/// by parallel builds (load average near 100) a call can wait seconds for a CPU
/// and for the audit database's lock; 10 s denied such calls that were only
/// slow. 30 s leaves room for that and stays half the settings-change timeout.
pub const GUARD_BUDGET_S: u64 = 30;
const _: () = assert!(GUARD_BUDGET_S < CONFIG_HOOK_TIMEOUT_S);
const _: () = assert!(GUARD_BUDGET_S < TOOL_HOOK_TIMEOUT_S);

/// Every Claude Code tool `openmoat-hosts` maps to an action; a tool missing here
/// never reaches `moat guard`.
/// `Skill` and `EnterWorktree` without a `path` are recorded and left to Claude
/// Code's own permission flow; changing this list makes existing entries stale,
/// which `moat doctor` and `moat status` report with "run `moat init`".
const TOOL_MATCHER: &str = "Bash|Monitor|PowerShell|Edit|Write|MultiEdit|NotebookEdit|Read|Glob|Grep|LSP|SendFile|WebFetch|WebSearch|ReadMcpResourceTool|EnterWorktree|Skill|mcp__.*";

const CLAUDE_CODE_HOOKS: &[HookSpec] = &[
    HookSpec {
        event: "PreToolUse",
        matcher: TOOL_MATCHER,
        timeout: TOOL_HOOK_TIMEOUT_S,
        block_on_failure: true,
    },
    HookSpec {
        event: "ConfigChange",
        matcher: "user_settings|project_settings|local_settings",
        timeout: CONFIG_HOOK_TIMEOUT_S,
        block_on_failure: false,
    },
];

/// Codex runs `PreToolUse` for shell, `apply_patch` file edits and MCP tools;
/// web search and hosted tools have no hook. Codex has no key that blocks a
/// call whose hook fails: "a failed `PreToolUse` hook marks that hook run as
/// failed, reports the error, and continues the tool call"
/// (<https://learn.chatgpt.com/docs/hooks>), so `guard` itself must answer.
const CODEX_HOOKS: &[HookSpec] = &[HookSpec {
    event: "PreToolUse",
    matcher: "Bash|apply_patch|mcp__.*",
    timeout: TOOL_HOOK_TIMEOUT_S,
    block_on_failure: false,
}];

/// Cursor blocks a failed hook through `failClosed` on every entry
/// ([`HookFormat::Cursor`]), not through `block_on_failure`.
const CURSOR_HOOKS: &[HookSpec] = &[
    HookSpec {
        event: "beforeShellExecution",
        matcher: "",
        timeout: TOOL_HOOK_TIMEOUT_S,
        block_on_failure: false,
    },
    HookSpec {
        event: "beforeMCPExecution",
        matcher: "",
        timeout: TOOL_HOOK_TIMEOUT_S,
        block_on_failure: false,
    },
    HookSpec {
        event: "beforeReadFile",
        matcher: "",
        timeout: TOOL_HOOK_TIMEOUT_S,
        block_on_failure: false,
    },
    HookSpec {
        event: "preToolUse",
        matcher: "",
        timeout: TOOL_HOOK_TIMEOUT_S,
        block_on_failure: false,
    },
];

/// How a host's hook file is laid out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookFormat {
    /// `{"hooks": {"<Event>": [{"matcher", "hooks": [{type, command, args, timeout}]}]}}`
    /// (Claude Code `settings.json`, Codex `hooks.json`).
    Nested,
    /// `{"version": 1, "hooks": {"<event>": [{"command": "<shell string>", "timeout", "failClosed"}]}}`
    /// (Cursor `hooks.json`). Cursor is fail-open unless `failClosed` is set.
    Cursor,
}

/// Where a host keeps its hook configuration and which events we subscribe to.
#[derive(Debug, Clone)]
pub struct HostConfig {
    pub host: Host,
    pub settings_path: PathBuf,
    pub hooks: &'static [HookSpec],
    pub format: HookFormat,
    /// Whether the host's version knows `onFailure`; asked only when an
    /// entry with [`HookSpec::block_on_failure`] lacks the key, so commands
    /// that never compare entries (`uninstall`) never ask.
    pub blocks_on_failure: fn() -> bool,
}

/// The environment variable that moves `host`'s configuration directory, and
/// the directory's name under the home directory otherwise.
pub fn dir_variable(host: Host) -> Result<(&'static str, &'static str)> {
    Ok(match host {
        Host::ClaudeCode => ("CLAUDE_CONFIG_DIR", ".claude"),
        Host::Codex => ("CODEX_HOME", ".codex"),
        Host::Cursor => ("CURSOR_CONFIG_DIR", ".cursor"),
        Host::Continue => {
            bail!("the Continue CLI runs the Claude Code hook; it has none of its own")
        }
    })
}

/// `host`'s configuration directory as named by this shell's environment,
/// when its variable is set.
pub fn env_config_dir(host: Host) -> Result<Option<PathBuf>> {
    Ok(env_dir(dir_variable(host)?.0))
}

impl HostConfig {
    /// `host`'s configuration where `moat init` recorded it (`hosts.json`), else
    /// where this shell's environment or the default puts it.
    pub fn for_host(home: &Home, host: Host) -> Result<Self> {
        let recorded = Recorded::load(home)?;
        Self::at(host, recorded.dir(host).or(env_config_dir(host)?))
    }

    /// For `moat init`: this shell's environment wins over the record, so a
    /// person moves an agent by running `init` with its variable set.
    pub fn for_init(home: &Home, host: Host) -> Result<Self> {
        match env_config_dir(host)? {
            Some(dir) => Self::at(host, Some(dir)),
            None => Self::for_host(home, host),
        }
    }

    fn at(host: Host, dir: Option<PathBuf>) -> Result<Self> {
        let (_, default) = dir_variable(host)?;
        let dir = match dir {
            Some(dir) => dir,
            None => user_home()?.join(default),
        };
        let (file, hooks, format) = match host {
            Host::ClaudeCode => ("settings.json", CLAUDE_CODE_HOOKS, HookFormat::Nested),
            Host::Codex => ("hooks.json", CODEX_HOOKS, HookFormat::Nested),
            _ => ("hooks.json", CURSOR_HOOKS, HookFormat::Cursor),
        };
        let blocks_on_failure: fn() -> bool = match host {
            Host::ClaudeCode => claude_version::blocks_on_failure,
            _ => || false,
        };
        Ok(Self {
            host,
            settings_path: dir.join(file),
            hooks,
            format,
            blocks_on_failure,
        })
    }

    /// The configuration directory, the one `hosts.json` records.
    pub fn dir(&self) -> &Path {
        self.settings_path.parent().unwrap_or(&self.settings_path)
    }

    /// The host is considered present when its configuration directory exists.
    pub fn host_present(&self) -> bool {
        self.settings_path
            .parent()
            .is_some_and(std::path::Path::is_dir)
    }

    /// Install the hook, recording any backup in `home`'s `hosts.json`.
    pub fn install(&self, home: &Home, binary: &Path, dry_run: bool) -> Result<Outcome> {
        hook_file::install(home, self, binary, dry_run)
    }

    /// The hook file's text `current` as [`Self::install`] would write it;
    /// `None` when it would not change.
    pub fn render(&self, binary: &Path, current: &str) -> Result<Option<String>> {
        hook_file::render(self, binary, current)
    }

    pub fn state(&self, binary: &std::path::Path) -> HookState {
        hook_file::state(self, binary)
    }

    /// Whether the host is set up: OpenMoat's hook for `binary` is installed
    /// there. Only then do `moat sandbox sync`, `status` and `doctor` deal with
    /// its sandbox settings; the files of any other host are never touched.
    pub fn set_up(&self, binary: &std::path::Path) -> bool {
        self.state(binary) == HookState::Installed
    }

    /// Remove OpenMoat's hook entries from the parsed hook file `root`.
    pub fn remove(&self, root: &mut serde_json::Value) -> bool {
        hook_file::remove(root, self)
    }

    /// Whether an installed entry that should block the call when `moat guard`
    /// fails lacks `onFailure`, because this host's version does not know it
    /// or no `claude` is on `PATH`: the host then runs a call whose hook failed.
    pub fn runs_calls_when_hook_fails(&self) -> bool {
        hook_file::lacks_on_failure(self)
    }
}

/// What `moat doctor` and `moat status` say when the Continue CLI is present.
pub const CONTINUE_CLI_WARNING: &str = "the released Continue CLI does not run hooks, so \
     OpenMoat cannot check its tool calls; run it under `moat run`";

/// Where the Continue CLI (`cn`) shows itself: its global directory
/// (`CONTINUE_GLOBAL_DIR`, else `~/.continue`, as `cn` resolves it), or `cn`
/// on the search path. `cn` loads Claude Code's hooks but fires none of them
/// yet (released 1.5.47), so its tool calls never reach `guard`.
pub fn continue_cli() -> Result<Option<PathBuf>> {
    let dir = match env_dir("CONTINUE_GLOBAL_DIR") {
        Some(dir) => dir,
        None => user_home()?.join(".continue"),
    };
    if dir.is_dir() {
        return Ok(Some(dir));
    }
    let path: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    Ok(crate::environment::find_in(&path, &[], "cn"))
}

fn env_dir(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}
