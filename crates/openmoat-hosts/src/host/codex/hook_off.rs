//! What a trusted project's `.codex/` layer does to Codex's hooks, and its
//! managed hooks, which OpenMoat does not write (ADR-095).

use crate::contract::{HookOff, Managed, Platform, ProjectFile, ProjectOff, SystemFile};

/// The hooks documentation, "Disabling hooks" and "Managed hooks".
const SOURCE: &str = "https://learn.chatgpt.com/docs/hooks";

pub(super) const HOOK_OFF: HookOff = HookOff {
    // A trusted project's `.codex/config.toml` is a configuration layer:
    // `[features] hooks = false` in it turns every hook off, OpenMoat's
    // included (project-local hooks load only once that layer is trusted).
    project: ProjectOff::Files {
        example: ProjectFile::new(".codex/config.toml", "[features]\nhooks = false\n"),
        source: SOURCE,
    },
    session_override: None,
    managed: Managed::Manual {
        locations: &[
            SystemFile::at(
                "/etc/codex/requirements.toml",
                &[Platform::MacOs, Platform::Linux, Platform::Wsl],
            ),
            SystemFile::at(
                "C:/ProgramData/OpenAI/Codex/requirements.toml",
                &[Platform::Windows],
            ),
        ],
        why: "managed hooks go under `[hooks]` in the administrator's one `requirements.toml`, \
              with `[features] hooks = true` pinned beside them, and their commands must be \
              scripts under its `managed_dir`, which Codex does not install; OpenMoat edits \
              neither, so an administrator adds OpenMoat's `PreToolUse` entry there",
        source: SOURCE,
    },
};
