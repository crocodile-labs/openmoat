//! What `openmoat run` needs to start a host that has no OS sandbox of its
//! own (ADR-076, which names the source of each host's facts).

/// What the host's documentation or source says about starting it under
/// `openmoat run`. A host whose facts are not known says so: no command is
/// offered for it rather than one that was guessed. Exhaustive, so a new kind
/// fails to compile in the CLI until it says what to print.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunFacts {
    /// No command is offered.
    Unknown {
        /// Why, in a few words, as `moat status` and `moat doctor` show it.
        why: &'static str,
    },
    /// The command that starts the host, and what it writes.
    Known {
        /// The program to start, one of the host's process names.
        program: &'static str,
        /// Arguments the host needs to run in the foreground.
        args: &'static [&'static str],
        /// Each directory it writes outside the project, a `--write` each.
        writes: &'static [RunWrite],
    },
}

impl RunFacts {
    /// What a host starts from, which `tests/contract.rs` refuses for a host
    /// with no OS sandbox of its own.
    pub const BASE: Self = Self::Unknown {
        why: "not checked for this host",
    };
}

/// The one loopback TCP port a host serves while it runs, which `openmoat run
/// --listen` lets it bind and accept on and nothing else (ADR-108 §7). Found
/// as the host finds it: its variable, then its configuration file's key,
/// then its default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunListen {
    /// What listens, in a few words (`its Gateway`).
    pub what: &'static str,
    /// The port when nothing sets one.
    pub default_port: u16,
    /// The variable that sets the port, which outranks the file.
    pub variable: &'static str,
    /// The key path of the port in the host's hook file ([`crate::InstallSpec`]'s
    /// configuration file), a JSON or JSON5 object.
    pub key: &'static [&'static str],
    /// A variable under which the default is not [`Self::default_port`] (a
    /// named profile's port is derived from its name): with it set and no port
    /// in the variable or the file, no port is assumed.
    pub moved_by: &'static str,
}

/// One directory a host writes outside the project ([`RunFacts::Known`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunWrite {
    /// The host's configuration directory, wherever it was found.
    ConfigDir,
    /// This path below the home directory.
    Home(&'static str),
    /// The directory of this name in the per-user cache directory
    /// (`~/Library/Caches` on macOS, `~/.cache` elsewhere).
    Cache(&'static str),
}
