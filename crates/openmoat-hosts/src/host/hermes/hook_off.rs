//! Hermes Agent reads its hooks from the person's own home and profiles; a
//! project holds nothing that turns OpenMoat's off (ADR-095).

use crate::contract::{HookOff, Managed, ProjectOff};

const SOURCE: &str = "https://hermes-agent.nousresearch.com/docs/user-guide/features/hooks";

pub(super) const HOOK_OFF: HookOff = HookOff {
    project: ProjectOff::Nothing {
        why: "shell hooks come from `config.yaml` of the person's Hermes home and its profiles, \
              not from a project",
        source: SOURCE,
    },
    session_override: None,
    managed: Managed::None {
        why: "Hermes Agent documents no administrator location for hooks",
        source: SOURCE,
    },
};
