//! What the caller observed on its filesystem, for the checks that need it.
//!
//! The engine never looks at a disk. Three of its checks need facts that live
//! there; the caller observes them and passes them in, so the decision is made
//! on exactly the state the caller saw (ADR-046, TOCTOU):
//!
//! - **programs**: where each program name resolves on the search path the
//!   call will use, and where it was when the caller set up (`pinned`). A pinned
//!   program that now resolves elsewhere is a deny (rule `executables`).
//! - **links**: where a symlinked path really points. Every read and write is
//!   also checked at its target; the strictest verdict wins. [`crate::Engine::paths`]
//!   lists the paths a call names, to resolve.
//! - **files**: the files that exist, so an unquoted glob operand (`cat .en*`)
//!   is checked as the files it names.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use openmoat_core::{MapPathResolver, MapResolver};

/// Filesystem facts for one decision. Empty by default: nothing resolves,
/// nothing is a link, no glob operand names a file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(from = "Wire", into = "Wire")]
pub struct Facts {
    programs: MapResolver,
    paths: MapPathResolver,
}

/// The JSON form: `{programs, pinned, links, files}`, each optional.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct Wire {
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    programs: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pinned: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    links: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    files: Vec<String>,
}

impl From<Wire> for Facts {
    fn from(wire: Wire) -> Self {
        Self {
            programs: MapResolver {
                resolved: wire.programs,
                pins: wire.pinned,
            },
            paths: MapPathResolver {
                links: wire.links,
                files: wire.files,
            },
        }
    }
}

impl From<Facts> for Wire {
    fn from(facts: Facts) -> Self {
        Self {
            programs: facts.programs.resolved,
            pinned: facts.programs.pins,
            links: facts.paths.links,
            files: facts.paths.files,
        }
    }
}

impl Facts {
    /// No facts.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `name` resolves to the absolute path `path` on the search path the call
    /// will run with.
    #[must_use]
    pub fn program(mut self, name: impl Into<String>, path: impl Into<String>) -> Self {
        self.programs.resolved.insert(name.into(), path.into());
        self
    }

    /// `name` was at `path` when the caller set up; running it from anywhere
    /// else is a deny. A policy's `executables:` pins apply as well.
    #[must_use]
    pub fn pinned(mut self, name: impl Into<String>, path: impl Into<String>) -> Self {
        self.programs.pins.insert(name.into(), path.into());
        self
    }

    /// The path `link` is a symlink to `target` (both absolute). A path below
    /// `link` resolves below `target`.
    #[must_use]
    pub fn link(mut self, link: impl Into<String>, target: impl Into<String>) -> Self {
        self.paths.links.insert(link.into(), target.into());
        self
    }

    /// The absolute path of a file that exists, for glob operands.
    #[must_use]
    pub fn file(mut self, path: impl Into<String>) -> Self {
        self.paths.files.push(path.into());
        self
    }

    pub(crate) fn programs(&self) -> &MapResolver {
        &self.programs
    }

    pub(crate) fn paths(&self) -> &MapPathResolver {
        &self.paths
    }
}

#[cfg(test)]
mod tests {
    use super::Facts;

    #[test]
    fn json_form_round_trips_and_rejects_unknown_keys() {
        let facts = Facts::new()
            .program("git", "/usr/bin/git")
            .pinned("git", "/usr/bin/git")
            .link("/p/s", "/h/.ssh")
            .file("/p/.env");
        let text = serde_json::to_string(&facts).unwrap();
        assert_eq!(
            text,
            r#"{"programs":{"git":"/usr/bin/git"},"pinned":{"git":"/usr/bin/git"},"links":{"/p/s":"/h/.ssh"},"files":["/p/.env"]}"#
        );
        let back: Facts = serde_json::from_str(&text).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), text);
        assert_eq!(serde_json::to_string(&Facts::new()).unwrap(), "{}");
        assert!(serde_json::from_str::<Facts>(r#"{"link":{}}"#).is_err());
    }
}
