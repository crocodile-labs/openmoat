//! `openmoat watch` and `openmoat why` grammar (ADR-059).

use clap::{Args, ValueEnum};
use openmoat_hosts::Host;

use super::{Format, parse_host};

#[derive(Debug, Args)]
pub struct WatchArgs {
    /// Only this agent's calls.
    #[arg(long, value_parser = parse_host())]
    pub host: Option<Host>,

    /// Only the calls OpenMoat denied, or only those it held for review.
    #[arg(long, value_enum, value_name = "VERDICT")]
    pub only: Option<Only>,

    /// Only one session's calls, by the id `openmoat show` prints.
    #[arg(long)]
    pub session: Option<String>,

    /// How many earlier calls to show first.
    #[arg(long, value_name = "N", default_value_t = 10)]
    pub recent: usize,

    /// Show the earlier calls and stop, instead of following new ones.
    #[arg(long)]
    pub no_follow: bool,
}

/// `openmoat watch --only`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Only {
    Deny,
    Review,
}

#[derive(Debug, Args)]
pub struct WhyArgs {
    /// The decision to explain: an event id as `openmoat show` and `openmoat watch`
    /// print it (hex), or a time today (UTC) as `openmoat watch` shows it, `HH:MM`
    /// or `HH:MM:SS`. Without one, the newest deny or review.
    #[arg(conflicts_with = "last")]
    pub event: Option<String>,

    /// The newest deny or review (the default).
    #[arg(long)]
    pub last: bool,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
}
