//! The policy schema version (`version:`, ADR-103): read before the rest of
//! the document, so a file for another schema is reported as that, with what
//! to do, instead of by the first key this build does not know.

use serde::Deserialize;

use super::{PolicyError, SUPPORTED_VERSION};

/// The `version:` a document declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Declared {
    /// The document has no `version:` key.
    Missing,
    /// The document's schema version.
    Version(u32),
    /// The document does not parse far enough to tell, or `version:` is not a
    /// number: the full parse reports why.
    Unreadable,
}

/// Just `version:`; every other key is ignored, so this reads any document a
/// policy, a repository policy or a pack may be.
#[derive(Deserialize)]
struct Probe {
    #[serde(default)]
    version: Option<u32>,
}

/// The schema version `yaml` declares.
#[must_use]
pub fn declared(yaml: &str) -> Declared {
    match crate::yaml::from_str::<Probe>(yaml) {
        Ok(Probe { version: Some(v) }) => Declared::Version(v),
        Ok(Probe { version: None }) => Declared::Missing,
        Err(_) => Declared::Unreadable,
    }
}

/// Refuse a document for a schema other than [`SUPPORTED_VERSION`], or one
/// without `version:`, naming the version and what to do.
pub(crate) fn check(yaml: &str) -> Result<(), PolicyError> {
    match declared(yaml) {
        Declared::Missing => Err(PolicyError::MissingVersion {
            supported: SUPPORTED_VERSION,
        }),
        Declared::Version(found) => check_parsed(found),
        Declared::Unreadable => Ok(()),
    }
}

/// [`check`] for a document that deserialized in full as a policy, whose
/// `version:` is `found`: the policy's `version` is a required number, so the
/// probe would have read the same `Declared::Version(found)` from it, and no
/// second deserialize is needed to read it.
pub(crate) fn check_parsed(found: u32) -> Result<(), PolicyError> {
    if found == SUPPORTED_VERSION {
        return Ok(());
    }
    Err(PolicyError::Version {
        found,
        supported: SUPPORTED_VERSION,
    })
}

/// What [`PolicyError::Version`] says: a newer schema needs a newer OpenMoat;
/// an older one, `openmoat policy migrate`.
pub(super) fn unsupported(found: u32, supported: u32) -> String {
    if found > supported {
        format!(
            "unsupported policy version {found}: the policy is written for policy schema version \
             {found}, which a newer OpenMoat reads; this build reads schema version {supported}: \
             upgrade OpenMoat"
        )
    } else {
        format!(
            "unsupported policy version {found}: this build reads policy schema version \
             {supported}; `openmoat policy migrate` rewrites an older schema"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_version_is_read_before_any_other_key() {
        assert_eq!(
            declared("version: 1\ndefaults: deny\n"),
            Declared::Version(1)
        );
        assert_eq!(declared("defaults: deny\n"), Declared::Missing);
        assert_eq!(declared("version: one\n"), Declared::Unreadable);
        assert_eq!(declared("- not a mapping\n"), Declared::Unreadable);
        // A key of a later schema does not hide the version it was written for.
        let later = "version: 2\nnew_key: true\n";
        let message = crate::Policy::parse(later).unwrap_err().to_string();
        assert!(message.contains("schema version 2"), "{message}");
        assert!(message.contains("upgrade OpenMoat"), "{message}");
    }

    #[test]
    fn a_missing_or_older_version_points_at_migrate() {
        for (yaml, says) in [
            ("defaults: deny\n", "has no `version:`"),
            ("version: 0\n", "unsupported policy version 0"),
        ] {
            let message = crate::Policy::parse(yaml).unwrap_err().to_string();
            assert!(message.contains(says), "{message}");
            assert!(message.contains("openmoat policy migrate"), "{message}");
        }
        let repo = crate::RepoPolicy::parse("deny: []\n").unwrap_err();
        assert!(
            matches!(repo, PolicyError::MissingVersion { supported: 1 }),
            "{repo}"
        );
    }

    /// `Policy::parse` reads `version:` from its one deserialize when the
    /// document parses, and probes for it only when it does not: either way a
    /// wrong or missing version gives the error the probe alone gave.
    #[test]
    fn a_wrong_or_missing_version_gives_the_same_error_with_one_deserialize() {
        for yaml in [
            // Parses in full: the version comes from the parsed policy.
            "version: 0\n",
            "version: 2\n",
            "version: 7\ndefaults: deny\n",
            // Does not parse in full: the probe reads it.
            "defaults: deny\n",
            "version: 2\nnew_key: true\n",
            "version: 0\ndenny: []\n",
            "version: ~\n",
        ] {
            let probed = check(yaml).unwrap_err().to_string();
            let parsed = crate::Policy::parse(yaml).unwrap_err().to_string();
            assert_eq!(parsed, probed, "{yaml}");
        }
        assert!(matches!(
            crate::Policy::parse("version: 3\n"),
            Err(PolicyError::Version {
                found: 3,
                supported: SUPPORTED_VERSION
            })
        ));
        assert!(matches!(
            crate::Policy::parse("defaults: deny\n"),
            Err(PolicyError::MissingVersion {
                supported: SUPPORTED_VERSION
            })
        ));
        // A readable version 1 with a bad key is the parse's own error.
        assert!(matches!(
            crate::Policy::parse("version: 1\ndenny: []\n"),
            Err(PolicyError::Parse(_))
        ));
    }

    #[test]
    fn a_field_error_names_the_schema_version() {
        let message = crate::Policy::parse("version: 1\ndenny: []\n")
            .unwrap_err()
            .to_string();
        assert!(message.contains("policy schema version 1"), "{message}");
        assert!(message.contains("unknown field `denny`"), "{message}");
    }
}
