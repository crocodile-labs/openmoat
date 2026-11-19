//! Why a policy file cannot be used.

use thiserror::Error;

use super::{SUPPORTED_VERSION, schema};

/// Why a policy file cannot be used. Any of these keeps `guard` from deciding.
///
/// Messages include their cause, so no variant also exposes it as `source`:
/// a chained report (`{:#}`) would print it twice.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PolicyError {
    /// The file is not valid YAML or does not fit the schema (of
    /// [`SUPPORTED_VERSION`], the one it declares: another is
    /// [`PolicyError::Version`]). The message names the field.
    #[error("policy parse error (policy schema version {SUPPORTED_VERSION}): {0}")]
    Parse(crate::yaml::Error),
    /// The `version` key names a schema this build does not know (ADR-103).
    #[error("{}", schema::unsupported(*found, *supported))]
    Version {
        /// The version in the file.
        found: u32,
        /// The version this build supports.
        supported: u32,
    },
    /// The document has no `version` key (ADR-103).
    #[error(
        "the policy has no `version:`; add `version: {supported}` as its first key, the policy \
         schema version this build reads (`openmoat policy migrate` adds it)"
    )]
    MissingVersion {
        /// The version this build supports.
        supported: u32,
    },
    /// Two rule groups share an id.
    #[error("duplicate rule id `{0}`")]
    DuplicateId(String),
    /// A rule group lists no patterns.
    #[error("rule `{0}` has no patterns")]
    EmptyRule(String),
    /// A pattern is empty (or only `!`/`$`).
    #[error("empty pattern")]
    EmptyPattern,
    /// A glob does not compile.
    #[error("bad glob `{pattern}`: {error}")]
    BadGlob {
        /// The pattern as written.
        pattern: String,
        /// The glob compiler's explanation.
        error: globset::Error,
    },
    /// A shell pattern does not tokenise (unbalanced quotes, a here-document).
    #[error("bad shell pattern `{pattern}` (unbalanced quotes?)")]
    BadShellPattern {
        /// The pattern as written.
        pattern: String,
    },
    /// The file has both `ask:` and `review:` (ADR-053): `ask` is the old name
    /// of `review`, and which list was meant cannot be told.
    #[error(
        "the policy has both `{old}:` and `{new}:`; `{old}` is the old name of `{new}`: \
         move the `{old}:` rules into `{new}:` (`openmoat policy upgrade` renames a policy \
         that has only `{old}:`)"
    )]
    OldAndNewName {
        /// The old key.
        old: &'static str,
        /// The current key.
        new: &'static str,
    },
    /// A rule group or `executables` entry is invalid; `problem` says why.
    #[error("rule `{rule}`: {problem}")]
    Rule {
        /// Rule id, or `executables.<name>`.
        rule: String,
        /// What is wrong.
        problem: String,
    },
}
