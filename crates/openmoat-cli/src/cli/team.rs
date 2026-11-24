//! `openmoat team` and `openmoat inventory` grammar (ADR-119).

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

#[derive(Debug, Subcommand)]
pub enum TeamCommand {
    /// Install a team's signed bundle as a managed layer over your policy: its deny
    /// and review rules and the settings it requires, which your own policy can only
    /// make stricter. Refused unless run by a person from an interactive terminal.
    Join(TeamJoinArgs),
    /// Install the newer bundle from the folder `team join` used (or another): its
    /// signature must verify against the team's key, its serial must be higher, and
    /// a change that widens your policy waits for your answer.
    Update(TeamUpdateArgs),
    /// Remove the team's layer; shows what that widens and asks first.
    Leave,
}

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
