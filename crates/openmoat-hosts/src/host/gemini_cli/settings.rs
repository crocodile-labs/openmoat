//! The keys of Gemini CLI's `settings.json` it rewrites itself for a person's
//! choice and that change no OpenMoat decision ([`InstallSpec::relaxed_keys`]).
//!
//! Checked against `packages/cli/src/config/settingsSchema.ts` and the
//! commands that save settings (`/model`, `/theme`, `/auth`, `/settings`) in
//! `@google/gemini-cli` 0.65.0, 2026-10-20. Each key below changes which model
//! answers, how Gemini CLI looks, or which of its own sign-in methods it uses.
//! None runs a program, loads code, changes a hook (`hooks`, `hooksConfig`),
//! the sandbox or tools (`tools.*`, `security.toolSandboxing`), MCP servers
//! (`mcpServers`, `mcp.*`), extensions, folder trust, the files Gemini CLI
//! reads into a session (`context.*`, `ui.escapePastedAtSymbols`), the
//! environment, telemetry, updates or the network the agent's tools reach, and
//! `BeforeTool` still decides every call. Keys that name a program
//! (`general.preferredEditor`) or start one (`ui.renderProcess`,
//! `general.enableAutoUpdate`, notification methods) are left out, as is every
//! key not listed: a change to one denies every call until a person re-pins.
//!
//! [`InstallSpec::relaxed_keys`]: crate::InstallSpec::relaxed_keys

use crate::contract::RelaxedKey;

pub(super) const RELAXED_KEYS: &[RelaxedKey] = &[
    // `/model`: the name of the Gemini model that answers. The endpoint and
    // the key come from the sign-in method and the environment, not from it.
    RelaxedKey::string("model.name"),
    // `/auth`, `/auth signout`: which of Gemini CLI's own sign-in methods it
    // uses (`oauth-personal`, `gemini-api-key`, `vertex-ai`, …), never a
    // credential; `security.auth.enforcedType` and `useExternal` stay pinned.
    RelaxedKey::string("security.auth.selectedType"),
    // `/theme`: colours. A theme that is a path is read as a JSON colour file
    // inside the home directory; nothing in it runs.
    RelaxedKey::string("ui.theme"),
    RelaxedKey::flag("ui.autoThemeSwitching"),
    // `/settings` display toggles: what the window title, banner, tips,
    // spinner, footer and chat show.
    RelaxedKey::flag("ui.hideWindowTitle"),
    RelaxedKey::flag("ui.showStatusInTitle"),
    RelaxedKey::flag("ui.dynamicWindowTitle"),
    RelaxedKey::flag("ui.hideTips"),
    RelaxedKey::flag("ui.showShortcutsHint"),
    RelaxedKey::flag("ui.hideBanner"),
    RelaxedKey::flag("ui.hideFooter"),
    RelaxedKey::flag("ui.footer.hideCWD"),
    RelaxedKey::flag("ui.footer.hideModelInfo"),
    RelaxedKey::flag("ui.footer.hideContextPercentage"),
    RelaxedKey::flag("ui.showMemoryUsage"),
    RelaxedKey::flag("ui.showLineNumbers"),
    RelaxedKey::flag("ui.showCitations"),
    RelaxedKey::flag("ui.showModelInfoInChat"),
    RelaxedKey::flag("ui.showUserIdentity"),
    RelaxedKey::flag("ui.showSpinner"),
    RelaxedKey::flag("ui.useBackgroundColor"),
    // `tips`, `witty`, `all`, `off`; `off`, `full`: wording on screen only.
    RelaxedKey::string("ui.loadingPhrases"),
    RelaxedKey::string("ui.inlineThinkingMode"),
    // Plain-text output for screen readers.
    RelaxedKey::flag("ui.accessibility.screenReader"),
    // Vim keybindings in the input box.
    RelaxedKey::flag("general.vimMode"),
    // Set once Gemini CLI has shown its IDE integration hint; `ide.enabled`,
    // which connects to the editor, stays pinned.
    RelaxedKey::flag("ide.hasSeenNudge"),
];
