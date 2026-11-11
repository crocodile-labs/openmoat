//! `openmoat snapshot` and `openmoat restore` (ADR-085).

use std::path::PathBuf;

use clap::Args;

use super::Format;

#[derive(Debug, Args)]
pub struct SnapshotArgs {
    /// List this project's snapshots, newest last, with what each left out.
    #[arg(long, conflicts_with = "prune")]
    pub list: bool,

    /// Remove snapshots past the retention (50 per project, 14 days; the newest stays).
    #[arg(long)]
    pub prune: bool,

    /// Output format of `--list`.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
}

#[derive(Debug, Args)]
pub struct RestoreArgs {
    /// The snapshot to put back (an id from `openmoat snapshot --list`); by
    /// default the newest one `openmoat run` took before its agent started.
    pub snapshot: Option<String>,

    /// Also print each changed file's differences.
    #[arg(long)]
    pub patch: bool,

    /// Only these files or folders of the project, after `--`.
    #[arg(last = true, value_name = "PATH")]
    pub paths: Vec<PathBuf>,
}
