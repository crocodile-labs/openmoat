//! What a project's files can do to Crush's hooks, and its system
//! configuration, which OpenMoat does not write (ADR-098).

use crate::contract::{HookOff, Managed, ProjectOff};

const LOAD: &str = "https://github.com/charmbracelet/crush/blob/main/internal/config/load.go";

pub(super) const HOOK_OFF: HookOff = HookOff {
    project: ProjectOff::Nothing {
        why: "the hooks of every configuration file Crush loads are appended to one another \
              and no setting turns hooks off: a project can add hooks, not remove the \
              person's",
        source: LOAD,
    },
    session_override: None,
    managed: Managed::Manual {
        locations: super::protect::SYSTEM_FILES,
        why: "Crush loads `/etc/crush/crush.json` first and appends every later file's hooks \
              to its own, so a hook there runs whatever a project sets; OpenMoat does not write \
              it: the file is an administrator's",
        source: LOAD,
    },
};
