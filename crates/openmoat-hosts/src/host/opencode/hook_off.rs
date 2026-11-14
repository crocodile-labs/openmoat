//! What a project's configuration does to OpenMoat's OpenCode plugin, and
//! OpenCode's system directory, which OpenMoat does not write (ADR-098).

use crate::contract::{HookOff, Managed, Platform, ProjectFile, ProjectOff, SystemFile};

pub(super) const HOOK_OFF: HookOff = HookOff {
    // OpenCode 2: a `-openmoat` entry in a project's `plugins` drops the
    // plugin of that id (`project_settings.rs`).
    project: ProjectOff::Files {
        example: ProjectFile::new("opencode.json", "{\"plugins\": [\"-openmoat\"]}\n"),
        source: "https://opencode.ai/docs/plugins/",
    },
    session_override: None,
    // The system directory's `opencode.json` outranks a project's and its
    // `plugins/` load for every user; managed preferences outrank both.
    managed: Managed::Manual {
        locations: &[
            SystemFile::at(
                "/Library/Application Support/opencode/opencode.json",
                &[Platform::MacOs],
            ),
            SystemFile::at("/etc/opencode/opencode.json", &[Platform::Linux, Platform::Wsl]),
            SystemFile::at("C:/ProgramData/opencode/opencode.json", &[Platform::Windows]),
        ],
        why: "the system directory's `plugins/` load for every user, but OpenCode's \
              documentation does not say whether a project's `-openmoat` entry removes a plugin \
              there; OpenMoat does not write it until that is known (an administrator's \
              `plugin.use` policy is the documented way to keep a plugin on)",
        source: "https://opencode.ai/docs/config/",
    },
};
