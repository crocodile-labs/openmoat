//! What a project's settings do to Claude Code's hooks at start, the option
//! that keeps them on for one session, and the managed settings drop-in
//! `openmoat init --managed` writes (ADR-098).

use crate::contract::{
    HookOff, Managed, ManagedHooks, ManagedShape, Platform, ProjectFile, ProjectOff,
    SessionOverride, SystemFile,
};

pub(super) const HOOK_OFF: HookOff = HookOff {
    // "Disable or remove hooks": Claude Code reads the `disableAllHooks` left
    // after settings precedence, so a project's `.claude/settings.json` or
    // `settings.local.json` setting it wins over the person's file.
    project: ProjectOff::Files {
        example: ProjectFile::new(".claude/settings.json", "{\"disableAllHooks\": true}\n"),
        source: "https://code.claude.com/docs/en/hooks#disable-or-remove-hooks",
    },
    // The same section: `--settings` "takes precedence over project and local
    // settings"; the CLI reference: its values "override the same keys in
    // your settings.json files for this session". `false` keeps every hook on.
    // `openmoat run` adds it to every session: one managed source applies
    // (a server-managed policy, a device profile or the `HKLM` value comes
    // before the files), and Claude Code reloads a project's settings while a
    // session runs, which the check before the start cannot see.
    session_override: Some(SessionOverride {
        args: &["--settings", "{\"disableAllHooks\":false}"],
        keys: &["disableAllHooks"],
        clashes: &["--settings"],
        source: "https://code.claude.com/docs/en/cli-reference",
    }),
    // Managed settings: the `*.json` files of `managed-settings.d` beside
    // `managed-settings.json` are merged in name order (`50-` comes after an
    // administrator's `10-`/`20-` files); `disableAllHooks` set in user,
    // project or local settings "can't disable those managed hooks" (hooks
    // reference). Claude Code applies one managed source by default
    // ("first-wins"): a device-management profile is used before the files.
    managed: Managed::Written(ManagedHooks {
        files: &[
            SystemFile::at(
                "/Library/Application Support/ClaudeCode/managed-settings.d/50-openmoat.json",
                &[Platform::MacOs],
            ),
            SystemFile::at(
                "/etc/claude-code/managed-settings.d/50-openmoat.json",
                &[Platform::Linux, Platform::Wsl],
            ),
            SystemFile::at(
                "C:/Program Files/ClaudeCode/managed-settings.d/50-openmoat.json",
                &[Platform::Windows],
            ),
        ],
        shape: ManagedShape::DropIn,
        root_owned: false,
        outlasts_project: true,
        shadowed_by: &[SystemFile::at(
            "/Library/Managed Preferences/com.anthropic.claudecode.plist",
            &[Platform::MacOs],
        )],
        // Ranked above the files ("How Claude Code combines managed
        // sources"): remote settings from the claude.ai console or a gateway,
        // and on Windows the `HKLM\SOFTWARE\Policies\ClaudeCode` value.
        unseen_shadows: "server-managed settings from the claude.ai console or a Claude apps \
                         gateway, and on Windows the `HKLM\\SOFTWARE\\Policies\\ClaudeCode` \
                         registry value",
        source: "https://code.claude.com/docs/en/managed-settings",
    }),
};
