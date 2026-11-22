//! How OpenMoat tells that a host still runs its hook or plugin
//! ([`super::InstallSpec::heartbeat`], ADR-042; [`super::InstallSpec::liveness`],
//! ADR-104).
//!
//! A host that cannot load a plugin (a syntax error after an update, an API
//! the host dropped, a broken Node) logs it and keeps running, and the tool
//! calls then run unchecked: OpenClaw marks the plugin `status: "error"` and
//! starts the Gateway, OpenCode 1 publishes a session error and skips it, pi
//! shows a diagnostic and starts the session. So the plugin runs
//! `openmoat guard --heartbeat --host <id>` as it loads ([`HEARTBEAT_FLAG`]),
//! and `openmoat status` and `openmoat doctor` say when it has not done so
//! since its file was written or the host's program changed.
//!
//! A host that runs a hook command has no plugin to report, and stops running
//! it just as quietly: an update that reads its hooks elsewhere, a setting
//! that turns hooks off, an entry lost in an edit. There the calls the guard
//! decided are the only sign, and the host's own session files tell whether
//! it ran since ([`Liveness`]).

/// The flag a plugin runs `openmoat guard` with to say that it loaded.
pub const HEARTBEAT_FLAG: &str = "--heartbeat";

/// What `openmoat status` and `openmoat doctor` need to tell whether the host
/// has loaded OpenMoat's plugin since it last could have stopped doing so.
#[derive(Debug)]
#[non_exhaustive]
pub struct Heartbeat {
    /// The host's program on the search path. A newer one there (an update)
    /// may no longer load the plugin, so the plugin has to report again after
    /// it; the link on the search path and the file it names are both looked
    /// at, the newer counting, since a package manager may keep the date a
    /// package's files were packed with and only the link it makes tells when.
    pub program: &'static str,
    /// Where the host writes as it works, so the two cases can be told apart:
    /// the host has not run since the plugin was written (a note), or it ran
    /// without loading the plugin (a warning). Empty where no such place is
    /// known for sure; then only the note is given.
    pub activity: &'static [Activity],
}

/// What `openmoat status`, `openmoat doctor` and `openmoat watch` need to tell
/// whether a host that runs a hook command still runs OpenMoat's (ADR-104).
/// The host's program on the search path is the first of its process names
/// ([`super::ProcessSpec::names`]); its hook file is the install's.
#[derive(Debug)]
#[non_exhaustive]
pub struct Liveness {
    /// Files in the configuration directory besides the hook file whose
    /// change may stop the host running the hook (Codex's `config.toml`,
    /// whose `[features]` turn hooks off): after one, a call has to reach the
    /// guard again before the hook counts as running.
    pub settings: &'static [&'static str],
    /// Where the host writes its sessions.
    pub sessions: Sessions,
    /// How a session start reaches the guard, for a host whose session start
    /// runs a hook OpenMoat installs (Claude Code's `SessionStart`): a session
    /// that started, called a tool OpenMoat's tool hook names, and sent no
    /// call is warned about at once rather than after ten minutes. `None`
    /// for most hosts.
    pub started: Option<Started>,
}

/// What tells that a session that started used a tool whose call never
/// reached the guard ([`Liveness::started`]). Only `openmoat status`,
/// `doctor` and `watch` read it; it never decides a call.
#[derive(Debug)]
#[non_exhaustive]
pub struct Started {
    /// The tool name the guard records a session start with.
    pub tool: &'static str,
    /// The matcher of OpenMoat's tool-call hook entry: a tool it names is one
    /// whose call reaches the guard.
    pub matcher: &'static str,
    /// The names of the tools one line of a session's file says were
    /// called. A session's file is `<session id><ending>` in one of the
    /// directories [`Sessions::Known`] names.
    pub tool_uses: fn(&serde_json::Value) -> Vec<String>,
}

impl Started {
    /// Whether [`Self::matcher`] names `tool`: an alternative equal to it, or
    /// one ending in `.*` whose start begins it. `None` when the matcher is
    /// another regular expression, which this does not read.
    #[must_use]
    pub fn names(&self, tool: &str) -> Option<bool> {
        let mut named = false;
        for alternative in self.matcher.split('|') {
            let (prefix, any) = match alternative.strip_suffix(".*") {
                Some(prefix) => (prefix, true),
                None => (alternative, false),
            };
            if !prefix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return None;
            }
            named |= if any {
                tool.starts_with(prefix)
            } else {
                tool == prefix
            };
        }
        Some(named)
    }
}

/// Where a host writes its sessions ([`Liveness::sessions`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sessions {
    /// One file per session in these directories of the configuration
    /// directory, written only while a session runs, which is where the hook
    /// would have run.
    Known(&'static [Activity]),
    /// No such place is known for sure; why, in a few words. OpenMoat then
    /// only notes that no call came since the change.
    Unknown(&'static str),
}

/// The directories of the host's configuration directory where it writes
/// files only while it does work it loads the plugin for (a session's
/// transcript), never for a command that loads no plugin (setup, sign-in).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Activity {
    /// The directories under the configuration directory, one name per
    /// level; [`Activity::ANY`] stands for every directory at its level
    /// (OpenClaw's `agents/<agent>/sessions`).
    pub dir: &'static [&'static str],
    /// The end of the name of a session's file there (`.jsonl`); empty for
    /// every file.
    pub ending: &'static str,
}

impl Activity {
    /// The name in [`Activity::dir`] that stands for every directory there.
    pub const ANY: &'static str = "*";

    /// The files directly in the directories `dir` names.
    #[must_use]
    pub const fn new(dir: &'static [&'static str]) -> Self {
        Self { dir, ending: "" }
    }

    /// Only the files whose names end in `ending`, one per session.
    #[must_use]
    pub const fn ending(self, ending: &'static str) -> Self {
        Self { ending, ..self }
    }
}
