//! Every approval channel this build knows: one folder each under
//! `remote/channels/`, and one row each in [`REGISTRY`]. Adding a channel
//! adds a folder and a row here, and changes nothing in the core
//! (`docs/APPROVALS.md`, "Adding a channel"; the CLI's
//! `tests/architecture.rs` holds it).

use super::channel::Registry;

mod telegram;

/// The channels, in the order `openmoat approvals connect --help` lists them.
pub const REGISTRY: Registry = Registry(&[&telegram::SPEC]);

#[cfg(test)]
mod tests {
    use super::REGISTRY;

    #[test]
    fn every_channel_meets_the_registry_rules() {
        REGISTRY.check().unwrap();
        assert!(!REGISTRY.0.is_empty());
    }
}
