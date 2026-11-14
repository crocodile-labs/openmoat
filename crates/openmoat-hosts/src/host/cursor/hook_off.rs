//! What a project does to Cursor's hooks, and the enterprise `hooks.json`
//! `openmoat init --managed` writes (ADR-098).

use crate::contract::{
    HookOff, Managed, ManagedHooks, ManagedShape, Platform, ProjectOff, SystemFile,
};

/// The hooks documentation, "Configuration".
const SOURCE: &str = "https://cursor.com/docs/agent/hooks";

pub(super) const HOOK_OFF: HookOff = HookOff {
    project: ProjectOff::Nothing {
        why: "a project's `.cursor/hooks.json` adds hooks beside the person's and every matching \
              hook runs, a deny winning; Cursor documents no key that turns another tier's \
              hooks off",
        source: SOURCE,
    },
    session_override: None,
    // Enterprise (device-managed) `hooks.json`, first in "Enterprise → Team →
    // Project → User", same format as the person's. The documentation does
    // not say whether a project can turn it off, so it is not counted on to
    // outlast one.
    managed: Managed::Written(ManagedHooks {
        files: &[
            SystemFile::at(
                "/Library/Application Support/Cursor/hooks.json",
                &[Platform::MacOs],
            ),
            SystemFile::at("/etc/cursor/hooks.json", &[Platform::Linux, Platform::Wsl]),
            SystemFile::at("C:/ProgramData/Cursor/hooks.json", &[Platform::Windows]),
        ],
        shape: ManagedShape::WholeFile,
        root_owned: false,
        outlasts_project: false,
        shadowed_by: &[],
        unseen_shadows: "",
        source: SOURCE,
    }),
};
