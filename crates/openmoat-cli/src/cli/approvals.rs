//! `openmoat approvals` grammar (ADR-078).

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ChannelKind {
    /// A Telegram bot you made with Telegram's `@BotFather`.
    Telegram,
}

#[derive(Debug, Args)]
pub struct ConnectArgs {
    /// The channel.
    #[arg(value_enum)]
    pub channel: ChannelKind,
    /// Read the bot token from this file instead of the terminal (delete it afterwards).
    #[arg(long, value_name = "FILE")]
    pub token_file: Option<PathBuf>,
    /// How long a request waits for an answer: 1 to 60 minutes (`5m`, `90s`, `1h`);
    /// 5 minutes when not given.
    #[arg(long, value_name = "DURATION")]
    pub expires: Option<String>,
}

#[derive(Debug, Args)]
pub struct ApproverArgs {
    /// The channel's user id (for Telegram, the number `openmoat approvals listen`
    /// prints when you message the bot).
    pub user_id: String,
}

#[derive(Debug, Args)]
pub struct ApprovalsStatusArgs {
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
}
