//! `moat audit` grammar.

use std::path::PathBuf;

use clap::{Args, Subcommand};
use openmoat_hosts::Host;

use super::{Format, parse_host};

#[derive(Debug, Subcommand)]
pub enum AuditCommand {
    /// Write events to stdout as JSON Lines, oldest first, each with its chain hashes.
    Export(ExportArgs),
    /// Check an export's hash chain without the database and print its head hash;
    /// or, with --against, check the log against the anchors recorded earlier.
    Verify(VerifyArgs),
    /// Report over exports from several machines: per host, per rule, top asks and
    /// denies, false-positive candidates. Every file must verify first.
    Report(TeamReportArgs),
    /// Record the log's current head (event, hash, time) outside the log: as a commit
    /// on `refs/moat/anchors` in a git repository you name, or as a line appended to a
    /// file. Nothing is sent anywhere; push the ref yourself. Refused unless run from an
    /// interactive terminal.
    Anchor(AnchorArgs),
}

#[derive(Debug, Args)]
pub struct TeamReportArgs {
    /// Files `openmoat audit export` wrote; events present in several are counted once.
    #[arg(required = true)]
    pub files: Vec<PathBuf>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// The file `openmoat audit export` wrote.
    #[arg(required_unless_present = "against")]
    pub file: Option<PathBuf>,

    /// A head hash recorded earlier (`openmoat audit verify` or `openmoat doctor` printed it);
    /// fail unless a verified event carries it.
    #[arg(long, conflicts_with = "against")]
    pub anchor: Option<String>,

    /// Fail when no `--anchor` is given: without one, an export whose newest
    /// events were dropped still verifies.
    #[arg(long, conflicts_with = "against")]
    pub require_anchor: bool,

    /// Check this machine's audit log against every anchor `openmoat audit anchor`
    /// recorded in this git repository or file: each must still be in the log
    /// with the same hash, or the newest events were deleted or rewritten.
    #[arg(long, value_name = "GIT_REPO_OR_FILE", conflicts_with = "file")]
    pub against: Option<PathBuf>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
}

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
pub struct AnchorArgs {
    /// A local git repository: the anchor becomes a commit on `refs/moat/anchors`
    /// there. The working tree, index and branches are not touched.
    #[arg(long, value_name = "REPO")]
    pub git: Option<PathBuf>,

    /// A file you keep: the anchor is appended to it as one line.
    #[arg(long, value_name = "PATH")]
    pub file: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ExportArgs {
    /// Window start: all, today, yesterday, 12h, 7d, 2w or YYYY-MM-DD (UTC).
    #[arg(long, default_value = "all")]
    pub since: String,

    /// Only this host.
    #[arg(long, value_parser = parse_host)]
    pub host: Option<Host>,

    /// Only this session id.
    #[arg(long)]
    pub session: Option<String>,
}
