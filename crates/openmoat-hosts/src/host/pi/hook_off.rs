//! What a trusted project's settings do to OpenMoat's pi extension
//! (ADR-098). pi has no administrator's settings.

use crate::contract::{HookOff, Managed, ProjectFile, ProjectOff};

/// pi's settings documentation, "Resources" (`docs/settings.md`).
const SOURCE: &str = "https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/docs/settings.md";

pub(super) const HOOK_OFF: HookOff = HookOff {
    // A project's `extensions` entries are resolved before the person's: a
    // `!` glob naming OpenMoat's extension turns it off.
    project: ProjectOff::Files {
        example: ProjectFile::new(".pi/settings.json", "{\"extensions\": [\"!**\"]}\n"),
        source: SOURCE,
    },
    session_override: None,
    managed: Managed::None {
        why: "pi reads the person's `settings.json` and a project's `.pi/settings.json`; it \
              names no settings an administrator deploys",
        source: SOURCE,
    },
};
