//! `openmoat team` and `openmoat inventory` grammar (ADR-119).

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

#[derive(Debug, Subcommand)]
pub enum TeamCommand {
    /// Install a team's signed bundle as a managed layer over your policy: its deny
    /// and review rules and the settings it requires, which your own policy can only
    /// make stricter. Refused unless run by a person from an interactive terminal.
    #[command(
        override_usage = "openmoat team join <BUNDLE> --signer \"<name> <key-type> <public-key>\"\n       \
                          for example: openmoat team join ~/src/acme-openmoat \\\n                \
                          --signer \"security@acme.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...\"",
        after_help = TEAM_HELP
    )]
    Join(TeamJoinArgs),
    /// Install the newer bundle from the folder `team join` used (or another): its
    /// signature must verify against the team's key, its serial must be higher, and
    /// a change that widens your policy waits for your answer.
    #[command(after_help = TEAM_HELP)]
    Update(TeamUpdateArgs),
    /// Remove the team's layer; shows what that widens and asks first.
    #[command(after_help = TEAM_HELP)]
    Leave,
}

/// What `openmoat team join|update|leave --help` ends with: how to try it, and where
/// the guide is.
const TEAM_HELP: &str = "\
The team publishes a folder (a git repository) with its rules, a manifest that names
each file's SHA-256, and the manifest's signature, made with:
  ssh-keygen -Y sign -f <team key> -n openmoat-team-bundle openmoat-team.yaml
and its public key as one line, \"<name> <key-type> <public-key>\".

Each person, once:
  git clone https://git.example.com/acme-openmoat ~/src/acme-openmoat
  openmoat team join ~/src/acme-openmoat --signer \"security@acme.example ssh-ed25519 AAAA...\"
Later:  git -C ~/src/acme-openmoat pull && openmoat team update
Check:  openmoat inventory --check ~/src/acme-openmoat
Undo:   openmoat team leave

Try it with a throwaway key, and the whole guide: docs/TEAM.md
(https://openmoat.dev/docs/team-rules/team-mode/)";

#[derive(Debug, Args)]
pub struct TeamJoinArgs {
    /// The bundle's folder: a local clone of the team's repository, or the path an
    /// MDM tool keeps it at. A URL is refused: clone it first.
    pub bundle: PathBuf,
    /// The team's signing key as an allowed-signers line, `<name> <type> <base64>`,
    /// as the team publishes it. It is trusted for team bundles only.
    #[arg(long, value_name = "ENTRY")]
    pub signer: String,
}

#[derive(Debug, Args)]
pub struct TeamUpdateArgs {
    /// The bundle's folder; absent, the one `team join` or the last update used.
    pub bundle: Option<PathBuf>,
}

/// What `openmoat inventory` prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum InventoryFormat {
    /// OpenMoat's own document (`openmoat-inventory-v1`).
    Json,
    /// OCSF events: Software Inventory Info (5020) per agent, Device Config State
    /// (5002) for the machine.
    Ocsf,
}

#[derive(Debug, Args)]
pub struct InventoryArgs {
    /// `json` (the inventory's default) or `ocsf`; `--check` prints lines, and its
    /// findings as JSON when given a format.
    #[arg(long, value_enum)]
    pub format: Option<InventoryFormat>,
    /// Compare this machine with what the bundle in this folder requires; exit 1
    /// when it differs (a missing hook, a weaker setting, an older bundle).
    #[arg(long, value_name = "BUNDLE", conflicts_with = "deliver")]
    pub check: Option<PathBuf>,
    /// Send the inventory to every sink of `~/.moat/delivery.yaml` that says
    /// `inventory: true`, masked as audit delivery is (ADR-081).
    #[arg(long)]
    pub deliver: bool,
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory as _, Parser as _};

    use crate::cli::Cli;

    /// `openmoat team join` without its arguments shows a real example, and its
    /// `--help` ends with how to try it and the guide.
    #[test]
    fn join_without_arguments_shows_an_example() {
        let error = Cli::try_parse_from(["openmoat", "team", "join"])
            .unwrap_err()
            .to_string();
        assert!(error.contains("for example: openmoat team join"), "{error}");
        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("team")
            .and_then(|team| team.find_subcommand_mut("join"))
            .unwrap()
            .render_long_help()
            .to_string();
        assert!(help.contains("ssh-keygen -Y sign"), "{help}");
        assert!(help.contains("docs/TEAM.md"), "{help}");
        println!("{error}\n----\n{help}");
    }
}
