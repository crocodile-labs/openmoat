//! Where a host loads hook commands and plugins besides OpenMoat's own, so the
//! CLI can keep a ledger of them in the policy lock (ADR-109).
//!
//! A plugin update or a settings edit that adds a hook runs that hook's
//! command with the person's permissions, at an event OpenMoat may never see
//! (in the `HookPry` study 77% of such installs ran and none was blocked).
//! The ledger records every such command with its digest; a new or changed
//! one holds the host's
//! calls until a person accepts it. These are the facts the CLI reads them
//! from, beside the ones other specs already give: the hook file
//! ([`super::InstallSpec`]), the project's settings, hook and plugin
//! directories ([`super::ProjectSettingsSpec`]), the other hook files
//! ([`super::OtherHooks`]) and the helper commands a settings file names
//! ([`super::SettingsReader::programs`]).

/// What the ledger reads for one host beyond the other specs.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Ledger {
    /// Files of a project's settings directory
    /// ([`super::ProjectSettingsSpec::dir`]) that hold hooks laid out as the
    /// host's hook file is ([`super::HookLayout`]): Claude Code's
    /// `settings.json` and `settings.local.json`. Empty for most hosts.
    pub project_hook_files: &'static [&'static str],
    /// Where the host keeps the plugins the person installed, each of which
    /// may bring hooks of its own.
    pub plugin_hooks: &'static [PluginHooks],
}

impl Ledger {
    /// No further place: the other specs say it all.
    pub const BASE: Self = Self {
        project_hook_files: &[],
        plugin_hooks: &[],
    };
}

/// A folder of installed plugins, each a directory whose hooks are in
/// [`Self::file`], laid out as the host's hook file is, and in the hooks its
/// manifest names ([`Self::manifest`]).
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct PluginHooks {
    /// The plugin directories under the configuration directory, one name per
    /// level; [`super::Activity::ANY`] stands for every directory at its level
    /// (Claude Code's `plugins/cache/<marketplace>/<plugin>/<version>`).
    pub dirs: &'static [&'static str],
    /// A plugin's hook file, relative to its directory, one name per level.
    pub file: &'static [&'static str],
    /// A plugin's manifest and its key that names more hooks: a path or
    /// paths of hook files relative to the plugin's directory, or the event
    /// map itself (Claude Code's `.claude-plugin/plugin.json` `hooks`);
    /// `None` when the host reads no such key.
    pub manifest: Option<(&'static [&'static str], &'static str)>,
}

impl PluginHooks {
    /// Plugins in `dirs` whose hooks are in `file`.
    #[must_use]
    pub const fn new(dirs: &'static [&'static str], file: &'static [&'static str]) -> Self {
        Self {
            dirs,
            file,
            manifest: None,
        }
    }

    /// These plugins, with more hooks named by `key` of the manifest `file`.
    #[must_use]
    pub const fn manifest(self, file: &'static [&'static str], key: &'static str) -> Self {
        Self {
            manifest: Some((file, key)),
            ..self
        }
    }
}
