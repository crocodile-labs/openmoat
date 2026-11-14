//! The released Continue CLI runs no hook, so a project has none to turn off
//! (ADR-095).

use crate::contract::{HookOff, Managed, ProjectOff};

const SOURCE: &str = "crates/openmoat-hosts/src/host/continue_cli/HOST.md";

pub(super) const HOOK_OFF: HookOff = HookOff {
    project: ProjectOff::Nothing {
        why: "the released `cn` fires no hook, so there is none for a project to turn off",
        source: SOURCE,
    },
    session_override: None,
    managed: Managed::None {
        why: "with no hook there is nothing for an administrator to enforce",
        source: SOURCE,
    },
};
