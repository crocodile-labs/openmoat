//! `openmoat approvals` grammar (ADR-078).

use std::path::PathBuf;

use clap::builder::PossibleValuesParser;
use clap::{Args, Subcommand};

use super::Format;

#[derive(Debug, Subcommand)]
pub enum ApprovalsCommand {
    /// Connect a channel to answer reviews from another device: stores its credential
    /// owner-only under ~/.moat/remote, never in a policy file. Refused unless run from an
    /// interactive terminal.
    Connect(ConnectArgs),
    /// Let a channel user id approve. Refused unless run from an interactive terminal.
    Allow(ApproverArgs),
    /// Stop a channel user id from approving. Refused unless run from an interactive terminal.
    Remove(ApproverArgs),
    /// Show the connected channel, its approvers and the requests waiting. Read-only;
    /// shows no credential.
    Status(ApprovalsStatusArgs),
    /// Send a test message to every approver. Refused unless run from an interactive terminal.
    Test,
    /// Send waiting requests to the approvers and take their answers, until Ctrl-C. Run
    /// it in a terminal of your own. Refused unless run from an interactive terminal.
    Listen,
    /// Remove the channel's credential and settings; reviews are answered only where
    /// the agent runs again. Refused unless run from an interactive terminal.
    Disconnect,
}

/// The channel names `connect` takes: the registry's, so a new channel needs
/// no change here.
fn channel_names() -> PossibleValuesParser {
    PossibleValuesParser::new(crate::remote::REGISTRY.names())
}

#[derive(Debug, Args)]
pub struct ConnectArgs {
    /// The channel (docs/APPROVALS.md describes each).
    #[arg(value_parser = channel_names())]
    pub channel: String,
    /// Read the channel's credential (a bot or app token) from this file instead of the
    /// terminal (delete it afterwards).
    #[arg(long, value_name = "FILE", alias = "token-file")]
    pub credential_file: Option<PathBuf>,
    /// A setting the channel asks for at `connect`, as KEY=VALUE; asked at the terminal
    /// when not given. Most channels have none.
    #[arg(long = "set", value_name = "KEY=VALUE")]
    pub options: Vec<String>,
    /// How long a request waits for an answer: 1 to 60 minutes (`5m`, `90s`, `1h`);
    /// 5 minutes when not given.
    #[arg(long, value_name = "DURATION")]
    pub expires: Option<String>,
}

#[derive(Debug, Args)]
pub struct ApproverArgs {
    /// The approver's id: `<channel>:<user id>` as `openmoat approvals listen` prints it
    /// when they message the channel, or the bare user id on the connected channel.
    pub user_id: String,
}

#[derive(Debug, Args)]
pub struct ApprovalsStatusArgs {
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
}
