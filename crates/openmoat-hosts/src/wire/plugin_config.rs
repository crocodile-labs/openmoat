//! A host's configuration file that loads a plugin OpenMoat owns whole
//! ([`crate::HookLayout::Plugin`]).
//!
//! Pure document work: the CLI reads the file, backs it up and writes it, and
//! writes the plugin; the code here only edits and inspects the parsed
//! configuration.

use serde_json::Value;

use crate::HookSpec;
use crate::wire::hook_file::HookOutcome;
use crate::wire::owned_file::OwnedFile;

/// How one host's configuration file loads OpenMoat's plugin.
pub trait PluginConfig: Sync + std::fmt::Debug {
    /// The plugin file the configuration loads.
    fn plugin(&self) -> &'static OwnedFile;

    /// Where the plugin is written, relative to the host's configuration
    /// directory, one part per path component.
    fn plugin_path(&self) -> &'static [&'static str];

    /// Add OpenMoat's plugin at `plugin_path` (the path as the configuration
    /// spells it) to the parsed configuration `root`, with `hooks`. `file`
    /// names the configuration in the message of an error.
    ///
    /// # Errors
    ///
    /// When `root` cannot hold the plugin, the reason to show the person.
    fn upsert(
        &self,
        root: &mut Value,
        file: &str,
        plugin_path: &str,
        hooks: &[HookSpec],
    ) -> Result<HookOutcome, String>;

    /// Whether the parsed configuration `root` names OpenMoat's plugin at all,
    /// however out of date.
    fn lists_ours(&self, root: &Value) -> bool;

    /// The inverse of [`Self::upsert`] on a parsed configuration. Returns
    /// whether anything was removed.
    fn remove(&self, root: &mut Value) -> bool;
}
