//! Why a policy or an engine could not be built. A decision itself never fails:
//! what the engine cannot understand is decided `ask` or `defer`, never `allow`.

/// An input the SDK cannot use. Whatever the variant, decide nothing with it:
/// a caller without an engine must not run the call.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The policy is not valid YAML, does not fit schema version
    /// [`crate::POLICY_SCHEMA_VERSION`], or fails the lint.
    #[error("invalid policy: {message}")]
    Policy {
        /// What is wrong, with the line and column where the parser stopped.
        message: String,
    },
    /// A repository policy (`.moat/policy.yaml`) is invalid or tries to loosen
    /// the policy it is merged into.
    #[error("invalid repository policy: {message}")]
    RepositoryPolicy {
        /// What is wrong.
        message: String,
    },
    /// A [`crate::Context`] root is not an absolute, slash-separated path, or
    /// a policy pattern does not compile for it.
    #[error("invalid context: {message}")]
    Context {
        /// What is wrong.
        message: String,
    },
    /// A policy file could not be read (`fs` feature).
    #[cfg(feature = "fs")]
    #[error("cannot read {}: {source}", path.display())]
    Read {
        /// The file.
        path: std::path::PathBuf,
        /// The operating system's error.
        source: std::io::Error,
    },
}
