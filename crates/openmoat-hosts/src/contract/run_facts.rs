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
