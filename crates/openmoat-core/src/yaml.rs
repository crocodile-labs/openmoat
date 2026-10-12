//! The one place OpenMoat reads and writes YAML (ADR-024).
//!
//! Every policy, repository policy, overlay and fixture goes through these two
//! functions, so the parser behind them can change without touching a caller.
//! The parser is `serde-saphyr`, a pure-Rust YAML 1.2 parser, set up to stay
//! as strict as the policy needs:
//!
//! - only `true` and `false` are booleans: YAML 1.1's `yes`, `no`, `on` and
//!   `off` are not read as booleans, so a value never changes type unseen;
//! - a key that appears twice in one mapping is an error, not "last one wins";
//! - merge keys (`<<`) are an error rather than a silent copy of another rule;
//! - a tag the parser does not know (`!env TOKEN`) is an error, and `!!binary`
//!   is not decoded: the text a reviewer sees is the text the policy holds.
//!
//! Anchors and aliases (`&secret-paths`, `*secret-paths`) work as before, with
//! the parser's limits on alias expansion.

use std::fmt;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_saphyr::options::MergeKeyPolicy;

/// YAML that does not parse, does not fit the target type, or cannot be written.
/// Its message names the line and column where the parser stopped.
#[derive(Debug)]
pub struct Error(Inner);

#[derive(Debug)]
enum Inner {
    Read(serde_saphyr::Error),
    Write(serde_saphyr::ser::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Inner::Read(e) => e.fmt(f),
            Inner::Write(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {}

/// Parse one YAML document into `T`.
///
/// # Errors
/// The text is not one well-formed YAML document, repeats a key, uses a merge
/// key, an unknown tag or a YAML 1.1 boolean, or does not fit `T`.
pub fn from_str<T: DeserializeOwned>(yaml: &str) -> Result<T, Error> {
    let options = serde_saphyr::options! {
        strict_booleans: true,
        merge_keys: MergeKeyPolicy::Error,
        reject_unsupported_tags: true,
        ignore_binary_tag_for_string: true,
        // One line per error: it ends up in a hook's deny reason.
        with_snippet: false,
    };
    serde_saphyr::from_str_with_options(yaml, options).map_err(|e| Error(Inner::Read(e)))
}

/// Write `value` as a YAML document.
///
/// # Errors
/// `value` has a shape YAML cannot hold (a map with non-scalar keys, say).
pub fn to_string<T: Serialize>(value: &T) -> Result<String, Error> {
    serde_saphyr::to_string(value).map_err(|e| Error(Inner::Write(e)))
}

#[cfg(test)]
mod tests;
