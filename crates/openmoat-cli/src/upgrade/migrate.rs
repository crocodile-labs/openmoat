//! `openmoat policy migrate` (ADR-103): a policy rewritten in the current
//! policy schema, on the text, so comments, order and every rule stay as the
//! person wrote them. A migration changes how the policy is written, never
//! what it decides; new default rules are `openmoat policy upgrade`'s.
//!
//! Schema version 1 is the only one, so the ladder has no version step yet:
//! a later schema adds one per version, oldest first, each rewriting version
//! N as N + 1. What it has are the two rewrites within version 1: a file
//! without `version:` gets it, and `ask`, the name schema 1 still reads for
//! `review` (ADR-053), becomes `review`.

use anyhow::{Result, bail};
use openmoat_core::{DeclaredVersion, Policy, SUPPORTED_VERSION, declared_version};

use super::rename;

/// One rewrite a migration makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// `version:` added to a file that had none.
    AddVersion,
    /// `ask` renamed `review`.
    RenameAsk,
}

impl Step {
    /// The rewrite in a line, for the command's summary.
    pub fn describe(self) -> String {
        match self {
            Self::AddVersion => format!(
                "add `version: {SUPPORTED_VERSION}`: the file names no policy schema version"
            ),
            Self::RenameAsk => {
                "rename `ask` to `review` (the name since 0.14.0, ADR-053)".to_owned()
            }
        }
    }
}

/// A policy's text in the current schema, and the rewrites that made it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Migration {
    /// The migrated text: the input when there is nothing to do.
    pub text: String,
    /// The rewrites, in the order made; empty when the file is current.
    pub steps: Vec<Step>,
}

/// `text` migrated to [`SUPPORTED_VERSION`]. An error when the file is for a
/// newer schema, names one that never existed, or would not load once
/// migrated: nothing is rewritten then.
pub fn migrate(text: &str) -> Result<Migration> {
    let mut steps = Vec::new();
    let mut text = text.to_owned();
    match declared_version(&text) {
        DeclaredVersion::Missing => {
            text = with_version(&text);
            steps.push(Step::AddVersion);
        }
        DeclaredVersion::Version(found) if found > SUPPORTED_VERSION => bail!(
            "the policy is written for policy schema version {found}, newer than this build \
             reads ({SUPPORTED_VERSION}): upgrade OpenMoat instead"
        ),
        DeclaredVersion::Version(found) if found < SUPPORTED_VERSION => bail!(
            "policy schema version {found} never existed: version {SUPPORTED_VERSION} is the \
             first; set `version: {SUPPORTED_VERSION}` if the file was written for it"
        ),
        DeclaredVersion::Version(_) | DeclaredVersion::Unreadable => {}
    }
    let (renamed, changed) = rename::old_names(&text);
    if changed {
        text = renamed;
        steps.push(Step::RenameAsk);
    }
    if let Err(e) = Policy::parse(&text) {
        bail!("the policy does not load once migrated, so nothing is rewritten: {e}");
    }
    Ok(Migration { text, steps })
}

/// `text` with `version:` as its first key: after the comments and blank
/// lines it starts with, and after a `---` that opens the document.
fn with_version(text: &str) -> String {
    let line_end = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let version = format!("version: {SUPPORTED_VERSION}{line_end}");
    let mut out = String::with_capacity(text.len() + version.len());
    let mut placed = false;
    for line in text.split_inclusive('\n') {
        let bare = line.trim_end();
        let header = bare.is_empty() || bare.starts_with('#');
        if !placed && !header {
            placed = true;
            if bare == "---" {
                out.push_str(line);
                out.push_str(&version);
                continue;
            }
            out.push_str(&version);
        }
        out.push_str(line);
    }
    if !placed {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push_str(line_end);
        }
        out.push_str(&version);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const OLD: &str = "# my policy\n\ndefaults:\n  \"*\": ask   # hold it\n  net: deny\n\
                       ask:\n  - id: deploy\n    shell: [\"make deploy\"]\n";

    #[test]
    fn a_current_policy_has_nothing_to_migrate() {
        let current = openmoat_core::DEFAULT_POLICY;
        let migration = migrate(current).unwrap();
        assert_eq!(migration.text, current);
        assert_eq!(migration.steps, []);
    }

    #[test]
    fn a_file_without_a_version_gets_it_after_its_comments_and_keeps_every_rule() {
        let migration = migrate(OLD).unwrap();
        assert_eq!(migration.steps, [Step::AddVersion, Step::RenameAsk]);
        assert!(
            migration
                .text
                .starts_with("# my policy\n\nversion: 1\ndefaults:\n"),
            "{}",
            migration.text
        );
        assert!(migration.text.contains("\"*\": review   # hold it"));
        assert!(migration.text.contains("review:\n  - id: deploy\n"));
        // It means what the file meant with `version: 1` written by hand.
        let by_hand = Policy::parse(&OLD.replace("defaults:", "version: 1\ndefaults:")).unwrap();
        let mut migrated = Policy::parse(&migration.text).unwrap();
        migrated.old_names = by_hand.old_names;
        assert_eq!(migrated, by_hand);
        // Migrating again changes nothing.
        assert_eq!(migrate(&migration.text).unwrap().steps, []);
    }

    #[test]
    fn the_version_goes_after_a_document_start_and_keeps_crlf() {
        let text = "---\r\ndefaults: deny\r\n";
        let migration = migrate(text).unwrap();
        assert_eq!(migration.text, "---\r\nversion: 1\r\ndefaults: deny\r\n");
        assert_eq!(
            with_version("# only a comment"),
            "# only a comment\nversion: 1\n"
        );
    }

    #[test]
    fn a_newer_or_impossible_schema_or_a_broken_file_is_not_rewritten() {
        for (text, says) in [
            ("version: 2\n", "upgrade OpenMoat"),
            ("version: 0\n", "never existed"),
            ("defaults: deny\ndenny: []\n", "unknown field `denny`"),
            ("ask: []\nreview: []\n", "both `ask:` and `review:`"),
        ] {
            let error = format!("{:#}", migrate(text).unwrap_err());
            assert!(error.contains(says), "{text:?}: {error}");
        }
    }
}
