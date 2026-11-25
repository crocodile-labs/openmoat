//! `openmoat agent-account` grammar (ADR-129).

use clap::Subcommand;

#[derive(Debug, Subcommand)]
pub enum AgentAccountCommand {
    /// Create the local account `openmoat run` starts agents as, hidden from the
    /// sign-in screen and in no group, with its password encrypted for you; grant it
    /// read on your profile; install the network filters that hold it to the run's
    /// proxy. Over an earlier setup without filters, add them. Refused unless run by
    /// a person from an interactive, administrator terminal.
    #[command(after_help = HELP)]
    Setup,
    /// Compare the account, its logon rights, its entries and its network filters
    /// with what setup recorded; exit 1 when they differ.
    #[command(after_help = HELP)]
    Status,
    /// Undo exactly what setup and the runs recorded: the network filters, the
    /// entries, the account and its profile, then the record. Refused unless run by a person from an
    /// interactive, administrator terminal.
    #[command(after_help = HELP)]
    Remove,
}

/// What `openmoat agent-account --help` and its commands end with.
pub const HELP: &str = "\
Windows only, a preview (ADR-129). From an administrator terminal, once:
  openmoat agent-account setup        creates the account and its network filters; takes a
                                      while in a large profile; again, adds the filters to
                                      an earlier setup that has none
Then from any terminal, as before:
  openmoat run -- <agent>             the agent runs as the account: Windows refuses its
                                      writes outside the project, its reads of ~/.ssh, other
                                      agents' logins and the rest the policy denies, and
                                      every connection and listen but its proxy's
  openmoat run --print-boundary -- <agent>
                                      shows `agent_account`, `wfp_network` and
                                      `windows_read_deny` in force, network `wfp_account`
Check:  openmoat agent-account status (exit 1 when the system differs from the record)
Undo:   openmoat agent-account remove (administrator terminal)
Guide: docs/USAGE.md, \"Run the agent as its own Windows account\"";

#[cfg(test)]
mod tests {
    use clap::CommandFactory as _;

    use crate::cli::Cli;

    /// Each command's `--help` ends with how to try it and the guide.
    #[test]
    fn the_help_shows_how_to_try_it() {
        let mut command = Cli::command();
        let group = command.find_subcommand_mut("agent-account").unwrap();
        for name in ["setup", "status", "remove"] {
            let help = group
                .find_subcommand_mut(name)
                .unwrap()
                .render_long_help()
                .to_string();
            assert!(help.contains("openmoat agent-account setup"), "{help}");
            assert!(help.contains("administrator terminal"), "{help}");
            assert!(help.contains("docs/USAGE.md"), "{help}");
        }
    }
}
