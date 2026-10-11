//! The kinds of atomic action a rule can name.
//!
//! The same names appear in policy files (`fs.read:`), in `defaults`
//! (`net: deny`), in synthetic rule ids (`default.net`) and in user output, so
//! they are defined once here.

use std::fmt;
use std::str::FromStr;

/// One kind of atomic action. Ordered as policy files list them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Kind {
    /// A command or a whole pipeline.
    Shell,
    /// A file read.
    FsRead,
    /// A file write, create, delete or move.
    FsWrite,
    /// A network host.
    Net,
    /// A host a read-only fetch tool (`WebFetch`) requests a URL from: a
    /// narrower kind of `net`, so `net` rules apply to it as well (ADR-017).
    Fetch,
    /// A query a host's own web search tool (`WebSearch`) sends to its search
    /// provider. The agent chooses the words, not the host, so only `defaults`
    /// decide it; no rule list names it.
    WebSearch,
    /// An environment variable read.
    EnvRead,
    /// An environment variable set.
    EnvSet,
    /// An MCP tool name.
    Mcp,
}

impl Kind {
    /// Every kind, in policy-file order.
    pub const ALL: [Self; 9] = [
        Self::Shell,
        Self::FsRead,
        Self::FsWrite,
        Self::Net,
        Self::Fetch,
        Self::WebSearch,
        Self::EnvRead,
        Self::EnvSet,
        Self::Mcp,
    ];

    /// The name used in policy files and rule ids (`fs.read`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shell => "shell",
            Self::FsRead => "fs.read",
            Self::FsWrite => "fs.write",
            Self::Net => "net",
            Self::Fetch => "fetch",
            Self::WebSearch => "web.search",
            Self::EnvRead => "env.read",
            Self::EnvSet => "env.set",
            Self::Mcp => "mcp",
        }
    }

    /// The rule-list and `defaults` keys that apply to an atom of this kind,
    /// most specific first: a fetch is also network access, so `net` lists
    /// match it and `defaults.net` is its fallback when `defaults.fetch` is unset.
    #[must_use]
    pub fn rule_kinds(self) -> &'static [Self] {
        match self {
            Self::Fetch => &[Self::Fetch, Self::Net],
            Self::Shell => &[Self::Shell],
            Self::FsRead => &[Self::FsRead],
            Self::FsWrite => &[Self::FsWrite],
            Self::Net => &[Self::Net],
            Self::WebSearch => &[Self::WebSearch],
            Self::EnvRead => &[Self::EnvRead],
            Self::EnvSet => &[Self::EnvSet],
            Self::Mcp => &[Self::Mcp],
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Serialised as its policy-file name (`fs.read`), as in the compiled IR.
impl serde::Serialize for Kind {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// A name that is not one of [`Kind::ALL`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown action kind `{0}`")]
pub struct UnknownKind(pub String);

impl FromStr for Kind {
    type Err = UnknownKind;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|k| k.as_str() == s)
            .ok_or_else(|| UnknownKind(s.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for kind in Kind::ALL {
            assert_eq!(kind.as_str().parse::<Kind>(), Ok(kind));
        }
        assert_eq!(
            "network".parse::<Kind>(),
            Err(UnknownKind("network".into()))
        );
    }

    #[test]
    fn only_fetch_borrows_another_kinds_rules() {
        assert_eq!(Kind::Fetch.rule_kinds(), &[Kind::Fetch, Kind::Net]);
        for kind in Kind::ALL.into_iter().filter(|k| *k != Kind::Fetch) {
            assert_eq!(kind.rule_kinds(), &[kind]);
        }
    }
}
