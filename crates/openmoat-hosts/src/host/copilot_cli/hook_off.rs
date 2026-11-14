//! What a repository's settings do to GitHub Copilot CLI's hooks at start,
//! and the policy hook file `openmoat init --managed` writes (ADR-098).

use crate::contract::{
    HookOff, Managed, ManagedHooks, ManagedShape, Platform, ProjectFile, ProjectOff, SystemFile,
};

/// The hooks configuration reference: hooks load from policy, user,
/// repository, then plugins.
const SOURCE: &str = "https://docs.github.com/en/copilot/reference/hooks-configuration";

pub(super) const HOOK_OFF: HookOff = HookOff {
    // `disableAllHooks` at the top of a repository's `settings.json` skips
    // "every hook from every source (repository files, user files, plugins,
    // and inline hook blocks)" for sessions in that repository.
    project: ProjectOff::Files {
        example: ProjectFile::new(".github/copilot/settings.json", "{\"disableAllHooks\": true}\n"),
        source: SOURCE,
    },
    session_override: None,
    // Policy hooks: `policy.d/*.json`, loaded in name order, in the same
    // format as the person's hook files; they "cannot be disabled by
    // `disableAllHooks`", and on POSIX systems a file must be owned by root
    // and not group- or world-writable.
    managed: Managed::Written(ManagedHooks {
        files: &[
            SystemFile::at(
                "/etc/github-copilot/policy.d/openmoat.json",
                &[Platform::MacOs, Platform::Linux, Platform::Wsl],
            ),
            SystemFile::at(
                "C:/ProgramData/GitHub/Copilot/policy.d/openmoat.json",
                &[Platform::Windows],
            ),
        ],
        shape: ManagedShape::DropIn,
        root_owned: true,
        outlasts_project: true,
        shadowed_by: &[],
        unseen_shadows: "",
        source: SOURCE,
    }),
};
