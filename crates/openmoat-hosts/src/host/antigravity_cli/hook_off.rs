//! What a workspace's `.agents/` does to OpenMoat's Antigravity CLI hook
//! (ADR-098). Antigravity documents no administrator-enforced hooks.

use crate::contract::{HookOff, Managed, ProjectFile, ProjectOff};

pub(super) const HOOK_OFF: HookOff = HookOff {
    // A workspace's `.agents/hooks.json` naming OpenMoat's hook with
    // `enabled: false` turns it off, and a plugin of `.agents/plugins` named
    // as OpenMoat's replaces it.
    project: ProjectOff::Files {
        example: ProjectFile::new(".agents/hooks.json", "{\"openmoat\": {\"enabled\": false}}\n"),
        source: "https://antigravity.google/docs/hooks.md",
    },
    session_override: None,
    managed: Managed::None {
        why: "no administrator-enforced hooks are documented",
        source: "https://antigravity.google/docs/enterprise.md",
    },
};
