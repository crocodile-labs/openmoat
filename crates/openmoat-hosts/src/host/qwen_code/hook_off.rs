//! What a project's settings may do to Qwen Code's hooks, and its system
//! settings, which OpenMoat does not write (ADR-098).

use crate::contract::{HookOff, Managed, ProjectFile, ProjectOff};

pub(super) const HOOK_OFF: HookOff = HookOff {
    // `disableAllHooks: true` loads no hook (the hooks page), and a project's
    // `.qwen/settings.json` is merged over the person's (the settings
    // reference). Whether a project's turns the person's hooks off was not
    // verified; OpenMoat assumes it does, the reading that keeps the hook.
    project: ProjectOff::Files {
        example: ProjectFile::new(".qwen/settings.json", "{\"disableAllHooks\": true}\n"),
        source: "https://qwenlm.github.io/qwen-code-docs/en/users/features/hooks/",
    },
    session_override: None,
    managed: Managed::Manual {
        locations: super::protect::SYSTEM_FILES,
        why: "system settings outrank the person's and a project's, so a hook there holds over \
              a project's settings; OpenMoat does not write them: the file is an \
              administrator's, and how Qwen Code merges hook lists across files was not \
              verified",
        source: "https://qwenlm.github.io/qwen-code-docs/en/users/configuration/settings/",
    },
};
