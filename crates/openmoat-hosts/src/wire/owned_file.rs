//! Files OpenMoat owns whole: pi's extension, OpenClaw's plugin. Each is a
//! script in the host's `integration/` folder with one line,
//! `const MOAT = __MOAT_BINARY__;`, that `moat init` fills in with the
//! binary's path as a JSON string; the CLI writes the result whole, pins it
//! whole and deletes it on `moat uninstall`.

use std::fmt;

use thiserror::Error;

/// The line `init` fills in with the binary's path.
const BINARY_LINE: &str = "const MOAT = __MOAT_BINARY__;";
const FILLED: &str = "const MOAT = ";

/// A file OpenMoat writes whole for a host, from its source.
pub struct OwnedFile {
    /// What the file is, as errors name it (`pi extension`).
    pub name: &'static str,
    /// The source, with the `const MOAT = __MOAT_BINARY__;` line once.
    pub source: &'static str,
    /// How every copy `init` writes begins, whichever binary it names.
    pub first_line: &'static str,
}

impl fmt::Debug for OwnedFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OwnedFile({})", self.name)
    }
}

/// A source without exactly one `const MOAT = __MOAT_BINARY__;` line.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("the {0} source has no single `{BINARY_LINE}` line")]
pub struct OwnedFileError(pub &'static str);

impl OwnedFile {
    /// The file as `init` writes it for `binary`.
    ///
    /// # Errors
    /// When the source does not hold the binary line exactly once.
    pub fn text(&self, binary: &str) -> Result<String, OwnedFileError> {
        if self.source.matches(BINARY_LINE).count() != 1 {
            return Err(OwnedFileError(self.name));
        }
        let quoted = serde_json::Value::from(binary).to_string();
        Ok(self
            .source
            .replacen(BINARY_LINE, &format!("{FILLED}{quoted};"), 1))
    }

    /// Whether `text` is a copy `init` wrote, for this binary or another.
    #[must_use]
    pub fn is_ours(&self, text: &str) -> bool {
        text.starts_with(self.first_line)
    }

    /// The binary a copy `init` wrote runs, for "points at another binary".
    #[must_use]
    pub fn binary(&self, text: &str) -> Option<String> {
        let line = text.lines().find(|l| l.starts_with(FILLED))?;
        let literal = line.strip_prefix(FILLED)?.strip_suffix(';')?;
        serde_json::from_str(literal).ok()
    }
}
