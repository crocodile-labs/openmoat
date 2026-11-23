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
    /// What the host's documentation says to do where Ubuntu's `AppArmor`
    /// restriction on user namespaces stops its sandbox.
    pub apparmor: UsernsProfileFix,
}

/// The fix a host's documentation gives for Ubuntu's `AppArmor` restriction on
/// unprivileged user namespaces (`kernel.apparmor_restrict_unprivileged_userns`),
/// besides lifting it with `sysctl`, which every one of them can use.
///
/// Ubuntu's `bwrap-userns-restrict` profile (the `apparmor` package from 25.04,
/// `apparmor-profiles` before) attaches a profile named `bwrap` to
/// `/usr/bin/bwrap` and stacks what bubblewrap starts into `unpriv_bwrap`,
/// which denies every capability. A sandbox that needs a capability inside
/// bubblewrap's namespace fails under it whatever the `sysctl` says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UsernsProfileFix {
    /// The documentation gives its own profile for `/usr/bin/bwrap`, named
    /// `bwrap`, `flags=(unconfined)` with `userns`, in
    /// `/etc/apparmor.d/bwrap`; its sandbox fails under
    /// `bwrap-userns-restrict`, whose `bwrap` has the same name.
    UnconfinedBwrapProfile,
    /// The documentation says to load Ubuntu's `bwrap-userns-restrict`
    /// profile, from the `apparmor-profiles` package on Ubuntu 24.04.
    BwrapUsernsRestrict,
    /// The documentation gives an `AppArmor` package of the host's own.
    OwnPackage(&'static str),
}

/// A program a host's Linux sandbox starts, and the package that has it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxProgram {
    /// The program's name on the search path (`bwrap`).
    pub name: &'static str,
    /// The Debian and Ubuntu package that installs it (`bubblewrap`).
    pub package: &'static str,
}
