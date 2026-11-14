//! What a trusted folder's settings do to Gemini CLI's hooks, and its system
//! settings, which OpenMoat does not write (ADR-098).

use crate::contract::{HookOff, Managed, Platform, ProjectFile, ProjectOff, SystemFile};

pub(super) const HOOK_OFF: HookOff = HookOff {
    // A trusted folder's `.gemini/settings.json` is merged over the person's:
    // `hooksConfig.enabled: false` there turns every hook off
    // (`packages/cli/src/config/settingsSchema.ts`).
    project: ProjectOff::Files {
        example: ProjectFile::new(
            ".gemini/settings.json",
            "{\"hooksConfig\": {\"enabled\": false}}\n",
        ),
        source: "https://geminicli.com/docs/hooks/",
    },
    session_override: None,
    managed: Managed::Manual {
        locations: &[
            SystemFile::at(
                "/Library/Application Support/GeminiCli/settings.json",
                &[Platform::MacOs],
            ),
            SystemFile::at(
                "/etc/gemini-cli/settings.json",
                &[Platform::Linux, Platform::Wsl],
            ),
            SystemFile::at("C:/ProgramData/gemini-cli/settings.json", &[Platform::Windows]),
        ],
        why: "system settings outrank every other file, so a hook there with \
              `hooksConfig.enabled: true` holds over a project's; OpenMoat does not write them: \
              the file is an administrator's one file, and Gemini CLI loads no settings hooks \
              in a folder it does not trust",
        source: "https://geminicli.com/docs/cli/enterprise/",
    },
};
