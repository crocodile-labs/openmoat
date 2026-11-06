//! Agent provenance for commits (ADR-056): which files and lines of a commit
//! an agent session wrote, from the local audit log's record of each
//! session's writes (ADR-039) and file provenance (ADR-029), kept per commit
//! in git notes on [`NOTES_REF`].
//!
//! - [`collect`]: the audit log's writes as the core's `AgentWrite`s, with
//!   the untrusted content each session had read before it wrote.
//! - [`git`]: the commits, their changed files and the notes, read with git.
//! - [`notes`]: a note built from the log, encoded, and verified against it.
//! - [`review`]: what `openmoat policy check-diff` shows from the notes.

pub mod collect;
pub mod git;
pub mod notes;
pub mod review;

/// The git notes ref provenance notes are kept on.
pub const NOTES_REF: &str = "refs/notes/openmoat";

#[cfg(test)]
mod tests;
