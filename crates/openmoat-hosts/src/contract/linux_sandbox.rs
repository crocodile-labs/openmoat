//! What a host's own sandbox needs from a Linux machine to start a command,
//! as the host's documentation states it, which `openmoat doctor` and
//! `openmoat status` check (the source of each host's fact is beside its
//! `SPEC`).

/// What the host's own Linux sandbox needs: programs on the search path and
/// unprivileged user namespaces.
#[derive(Debug)]
#[non_exhaustive]
pub struct LinuxSandboxNeeds {
    /// Programs the sandbox starts from the search path, each with the
    /// Debian and Ubuntu package that installs it, as the host's
    /// documentation names them.
    pub programs: &'static [LinuxProgram],
    /// Whether the sandbox creates a user namespace as the user (bubblewrap,
    /// or a helper of the host's own), which a distribution or a container
    /// can forbid.
    pub user_namespaces: bool,
    /// What the host does when its sandbox cannot start, as `openmoat doctor`
    /// prints it after "the agent's own sandbox cannot start commands on this
    /// machine".
    pub without: &'static str,
}

/// A program a host's Linux sandbox starts, and the package that has it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxProgram {
    /// The program's name on the search path (`bwrap`).
    pub name: &'static str,
    /// The Debian and Ubuntu package that installs it (`bubblewrap`).
    pub package: &'static str,
}
