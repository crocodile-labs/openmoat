//! The one I/O helper (`fs` feature): read a policy file. Everything else in
//! the SDK takes text and values.

use std::path::Path;

use crate::error::Error;
use crate::policy::Policy;

impl Policy {
    /// Read the policy file at `path` and [`Policy::parse`] it.
    pub fn read(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| Error::Read {
            path: path.to_owned(),
            source,
        })?;
        Self::parse(&text)
    }
}

#[cfg(test)]
mod tests {
    use crate::{DEFAULT_POLICY, Error, Policy};

    #[test]
    fn reads_a_policy_file_and_names_a_missing_one() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("policy.yaml");
        std::fs::write(&file, DEFAULT_POLICY).unwrap();
        assert_eq!(
            Policy::read(&file).unwrap(),
            Policy::parse(DEFAULT_POLICY).unwrap()
        );
        let missing = dir.path().join("absent.yaml");
        assert!(matches!(Policy::read(&missing), Err(Error::Read { .. })));
    }
}
