//! How a host's settings files are read for what turns OpenMoat's hook off,
//! runs a program or redirects the agent. Each host with project settings has
//! one [`SettingsReader`] in its folder (`host/<id>/project_settings.rs`). The
//! CLI finds, reads and parses the files and hands each one over as a
//! [`SettingsFile`]; a reader does no I/O.

use std::fmt;
use std::path::Path;

use serde_json::{Map, Value};

/// One parsed settings file and where it sits.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct SettingsFile<'a> {
    /// The file's top-level object (a TOML file as JSON).
    pub root: &'a Map<String, Value>,
    /// The directory its relative entries resolve from: the file's own
    /// directory, or the configuration directory for the person's own file.
    pub base: &'a Path,
    /// OpenMoat's hook file, which an entry may name to turn it off (pi).
    pub hook_file: &'a Path,
    /// The home directory `~` names in an entry; `None` when it is unknown.
    pub user_home: Option<&'a Path>,
}

impl<'a> SettingsFile<'a> {
    /// A file whose object is `root`, based at `base`.
    #[must_use]
    pub fn new(
        root: &'a Map<String, Value>,
        base: &'a Path,
        hook_file: &'a Path,
        user_home: Option<&'a Path>,
    ) -> Self {
        Self {
            root,
            base,
            hook_file,
            user_home,
        }
    }
}

/// Which keys of a host's settings files turn OpenMoat's hook off, run a
/// program or redirect the agent. Each finding is one sentence naming the key.
pub trait SettingsReader: Sync + fmt::Debug {
    /// What a project's file sets that could switch OpenMoat off, run a
    /// program or redirect the agent; empty when it sets none of that.
    fn findings(&self, file: &SettingsFile<'_>) -> Vec<String>;

    /// What the person's own file sets that turns OpenMoat's hook off.
    fn switched_off(&self, file: &SettingsFile<'_>) -> Vec<String>;

    /// What a file in the project's hook directory
    /// ([`crate::ProjectSettingsSpec::hook_dir`]) does, for its warning.
    fn hook_dir_effect(&self) -> &'static str {
        "adds hooks that run commands"
    }

    /// Whether the host reads these files as JSON with comments and trailing
    /// commas (OpenCode), so the CLI parses them that way.
    fn reads_comments(&self) -> bool {
        false
    }
}

/// A value that sets something: not `null`, `false`, `""`, `{}` or `[]`.
pub(crate) fn set(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null | Value::Bool(false)) => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(_) => true,
    }
}
