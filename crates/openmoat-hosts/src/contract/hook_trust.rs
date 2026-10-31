//! Read-only, advisory inspection of a host's hook approval record.

use serde_json::Value;

/// A host's own hook trust state, persisted in a TOML configuration file.
/// The CLI supplies parsed documents and hashing; this reader performs no I/O.
pub trait HookTrust: Sync + std::fmt::Debug {
    /// The TOML file beside the hook file that contains the trust record.
    fn toml_file(&self) -> &'static str;

    /// An advisory warning, or `None` when the stored approval matches.
    /// This mirrors host internals and must never gate calls or commands.
    fn warning(
        &self,
        hooks: &Value,
        config: &Value,
        source: &str,
        sha256: fn(&[u8]) -> String,
    ) -> Option<String>;
}
