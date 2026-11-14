//! The programs OpenMoat keeps running as a user service, as data: one
//! [`Job`] each, so the launchd and systemd code, the read-back check and the
//! `doctor` lines serve every one of them without naming it.

/// One `openmoat` command kept running under the current user.
#[derive(Debug)]
pub struct Job {
    /// The reverse-DNS launchd label (`<label>.plist`).
    #[cfg_attr(
        not(any(target_os = "macos", test)),
        expect(dead_code, reason = "only launchd's plist names it")
    )]
    pub label: &'static str,
    /// The systemd user unit's file name.
    #[cfg_attr(
        not(any(target_os = "linux", test)),
        expect(dead_code, reason = "only systemd's unit names it")
    )]
    pub unit: &'static str,
    /// What it is, in the unit file's first comment line.
    #[cfg_attr(
        not(any(target_os = "linux", test)),
        expect(dead_code, reason = "only systemd's unit names it")
    )]
    pub title: &'static str,
    /// The unit's `Description=`.
    #[cfg_attr(
        not(any(target_os = "linux", test)),
        expect(dead_code, reason = "only systemd's unit names it")
    )]
    pub description: &'static str,
    /// What runs, in messages: "the proxy".
    pub noun: &'static str,
    /// The `openmoat` arguments the service runs.
    #[cfg_attr(
        not(any(target_os = "macos", target_os = "linux", test)),
        expect(dead_code, reason = "only macOS and Linux write a service file")
    )]
    pub args: &'static [&'static str],
    /// The same program as a person runs it in a terminal, after `openmoat`.
    pub terminal: &'static str,
    /// The command that writes the service file, in messages.
    pub install: &'static str,
    /// The command that removes it, in messages.
    pub uninstall: &'static str,
    /// The log files' stem under `MOAT_HOME/logs/` (`<log>.out.log`, `<log>.err.log`).
    #[cfg_attr(
        not(any(target_os = "macos", target_os = "linux", test)),
        expect(dead_code, reason = "only macOS and Linux write a service file")
    )]
    pub log: &'static str,
    /// Owner-only by construction: the service starts with umask `077`, and on
    /// Linux it writes its logs to those files rather than the journal, which
    /// others in the `systemd-journal` group can read.
    #[cfg_attr(
        not(any(target_os = "macos", target_os = "linux", test)),
        expect(dead_code, reason = "only macOS and Linux write a service file")
    )]
    pub private: bool,
    /// What its exit code 64 means, with the way out.
    #[cfg_attr(
        not(any(target_os = "macos", target_os = "linux", test)),
        expect(dead_code, reason = "only macOS and Linux write a service file")
    )]
    pub exit_64: &'static str,
}

/// `openmoat proxy install` (#272). Its file's bytes are what earlier releases
/// wrote, so an installed proxy service reads back unchanged.
pub const PROXY: Job = Job {
    label: "dev.openmoat.proxy",
    unit: "moat-proxy.service",
    title: "OpenMoat egress proxy",
    description: "OpenMoat default-deny egress proxy",
    noun: "the proxy",
    args: &["proxy"],
    terminal: "proxy",
    install: "openmoat proxy install",
    uninstall: "openmoat proxy uninstall",
    log: "proxy",
    private: false,
    exit_64: "the proxy exited because of policy-lock drift. Fix the drift (`openmoat doctor`), \
              then `openmoat proxy install` restarts it",
};

/// `openmoat approvals install` (ADR-094): the approvals listener, which holds
/// the channel's credential and the approval key while it runs.
pub const APPROVALS: Job = Job {
    label: "dev.openmoat.approvals",
    unit: "openmoat-approvals.service",
    title: "OpenMoat approvals listener",
    description: "OpenMoat remote approvals listener",
    noun: "the listener",
    args: &["approvals", "listen", "--service"],
    terminal: "approvals listen",
    install: "openmoat approvals install",
    uninstall: "openmoat approvals uninstall",
    log: "approvals",
    private: true,
    exit_64: "the listener stopped with an error; its log says why. Fix it, then \
              `openmoat approvals install` restarts it",
};
