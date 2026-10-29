//! A parsed, linted policy (docs/POLICY.md), ready to compile.

use openmoat_core::{Policy as CorePolicy, RepoPolicy};

use crate::error::Error;

/// A policy document that parsed and passed the lint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    inner: CorePolicy,
}

impl Policy {
    /// Parse and lint a policy from its YAML text. The SDK reads no file: pass
    /// the text (or, with the `fs` feature, use `Policy::read`).
    pub fn parse(yaml: &str) -> Result<Self, Error> {
        CorePolicy::parse(yaml)
            .map(|inner| Self { inner })
            .map_err(|e| Error::Policy {
                message: e.to_string(),
            })
    }

    /// This policy with a repository policy (`.moat/policy.yaml`, ADR-022)
    /// merged in. A repository policy can only add restrictions: its deny and
    /// ask rules always apply, prefixed `repo:`; its allow rules only when the
    /// person `trusted` this exact file.
    pub fn with_repository(&self, yaml: &str, trusted: bool) -> Result<Self, Error> {
        RepoPolicy::parse(yaml)
            .and_then(|repo| repo.merge(&self.inner, trusted))
            .map(|inner| Self { inner })
            .map_err(|e| Error::RepositoryPolicy {
                message: e.to_string(),
            })
    }

    /// The schema version the policy declares (always
    /// [`crate::POLICY_SCHEMA_VERSION`] once parsed).
    #[must_use]
    pub fn schema_version(&self) -> u32 {
        self.inner.version
    }

    pub(crate) fn into_core(self) -> CorePolicy {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::Policy;
    use crate::{DEFAULT_POLICY, Error, POLICY_SCHEMA_VERSION};

    #[test]
    fn the_default_policy_parses_at_the_supported_schema() {
        let p = Policy::parse(DEFAULT_POLICY).unwrap();
        assert_eq!(p.schema_version(), POLICY_SCHEMA_VERSION);
    }

    #[test]
    fn invalid_policies_are_errors_with_their_cause() {
        let err = Policy::parse("version: 2\n").unwrap_err();
        assert!(matches!(err, Error::Policy { .. }));
        assert!(err.to_string().contains("version 2"), "{err}");
        assert!(Policy::parse("version: 1\ndeny:\n  - id: a\n").is_err());
        assert!(Policy::parse("version: 1\nversion: 1\n").is_err());
        let p = Policy::parse(DEFAULT_POLICY).unwrap();
        let err = p.with_repository("deny: [", false).unwrap_err();
        assert!(matches!(err, Error::RepositoryPolicy { .. }), "{err}");
    }
}
