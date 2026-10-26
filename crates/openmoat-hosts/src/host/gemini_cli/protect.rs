//! Gemini CLI's files the default policy and the taint list protect, and its
//! processes.

use crate::contract::{Paths, ProcessSpec, Protect};

pub(super) const PROTECT: Protect = Protect {
    self_paths: &[Paths::new(
        "Gemini CLI: its directory, the settings that hold OpenMoat's hook (a\n\
         project's are merged over them and can turn hooks off) and the folder\n\
         trust list, which decides whether settings hooks run at all",
        &[
            "~/.gemini",
            "**/.gemini",
            "~/.gemini/settings.json",
            "~/.gemini/trustedFolders.json",
            "**/.gemini/settings.json",
        ],
    )],
    taint: &[Paths::new(
        "Gemini CLI: its settings, extensions and the memory file it loads into\n\
         every session",
        &["**/GEMINI.md", "**/.gemini", "**/.gemini/**"],
    )],
    credentials: &[Paths::new(
        "Gemini CLI: its Google sign-in, the MCP and A2A OAuth tokens (in\n\
         `~/.cache/.gemini` under the macOS Seatbelt sandbox) and the file its\n\
         keychain falls back to, whose key the agent could derive\n\
         (`core/src/config/storage.ts`, `services/fileKeychain.ts`)",
        &[
            "~/.gemini/oauth_creds.json",
            "~/.gemini/mcp-oauth-tokens.json",
            "~/.gemini/a2a-oauth-tokens.json",
            "~/.gemini/gemini-credentials.json",
            "~/.cache/.gemini/mcp-oauth-tokens.json",
            "~/.cache/.gemini/a2a-oauth-tokens.json",
        ],
    )],
};

pub(super) const PROCESS: ProcessSpec = ProcessSpec {
    names: &["gemini"],
    package_dirs: &[&["@google", "gemini-cli"]],
    helper: None,
};
