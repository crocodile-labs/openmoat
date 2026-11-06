//! `openmoat provenance` grammar, and check-diff's `--provenance` (ADR-056).

use clap::{Args, ValueEnum};

use super::Format;

#[derive(Debug, Args)]
pub struct ProvenanceArgs {
    /// The commits: `A..B` as `git rev-list` reads it, or one revision. Defaults to the
    /// commits on HEAD that its upstream lacks, or HEAD alone without an upstream.
    #[arg(long, value_name = "REV-RANGE")]
    pub range: Option<String>,

    /// Store a record per commit in git notes (`refs/notes/openmoat`), replacing any there.
    /// Refused unless run by a person from an interactive terminal.
    #[arg(long, conflicts_with = "verify")]
    pub write_notes: bool,

    /// Check each commit's note against this machine's audit log; exits 64 when one does
    /// not match.
    #[arg(long)]
    pub verify: bool,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub format: Format,
}

/// `policy check-diff`'s provenance flags.
#[derive(Debug, Args)]
pub struct DiffProvenanceArgs {
    /// How to show what provenance notes (`openmoat provenance --write-notes`) say agent
    /// sessions wrote in the change: as review-level lines (`::warning` on GitHub), as
    /// information (`::notice`), or not at all. Never changes the exit code.
    #[arg(long = "provenance", value_enum, default_value_t = ProvenanceLevel::Review)]
    pub level: ProvenanceLevel,
}

/// `policy check-diff --provenance`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ProvenanceLevel {
    /// Review-level lines (`::warning` on GitHub).
    Review,
    /// Information (`::notice` on GitHub).
    Info,
    /// Not shown.
    Off,
}
