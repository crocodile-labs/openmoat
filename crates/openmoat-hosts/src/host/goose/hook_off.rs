//! What a project does to OpenMoat's goose plugin at start (ADR-095). goose
//! has no administrator's location for plugins.

use crate::contract::{HookOff, Managed, ProjectFile, ProjectOff};

pub(super) const HOOK_OFF: HookOff = HookOff {
    // `disabledPlugins` in the starting directory's `.config/goose/settings.json`
    // is read over the person's, and a plugin of that directory's
    // `.agents/plugins` named `openmoat` replaces OpenMoat's
    // (`plugins/discovery.rs`).
    project: ProjectOff::Files {
        example: ProjectFile::new(
            ".config/goose/settings.json",
            "{\"disabledPlugins\": [\"openmoat\"]}\n",
        ),
        source: "https://github.com/aaif-goose/goose (crates/goose/src/plugins/discovery.rs)",
    },
    session_override: None,
    managed: Managed::None {
        why: "goose's documentation names no administrator location for plugins or hooks",
        source: "https://goose-docs.ai/",
    },
};
