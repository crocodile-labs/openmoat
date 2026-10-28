//! How a host that runs OpenMoat through a plugin of its own loading tells
//! OpenMoat that it loaded it ([`super::InstallSpec::heartbeat`], ADR-042).
//!
//! A host that cannot load a plugin (a syntax error after an update, an API
//! the host dropped, a broken Node) logs it and keeps running, and the tool
//! calls then run unchecked: OpenClaw marks the plugin `status: "error"` and
//! starts the Gateway, OpenCode 1 publishes a session error and skips it, pi
//! shows a diagnostic and starts the session. So the plugin runs
//! `openmoat guard --heartbeat --host <id>` as it loads ([`HEARTBEAT_FLAG`]),
//! and `openmoat status` and `openmoat doctor` say when it has not done so
//! since its file was written or the host's program changed.

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
}

impl Activity {
    /// The name in [`Activity::dir`] that stands for every directory there.
    pub const ANY: &'static str = "*";

    /// The files directly in the directories `dir` names.
    #[must_use]
    pub const fn new(dir: &'static [&'static str]) -> Self {
        Self { dir }
    }
}
