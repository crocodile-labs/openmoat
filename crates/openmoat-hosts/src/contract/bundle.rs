//! Copies of a host's program that an editor extension ships inside itself,
//! where the search path does not find them: the Claude Code extension for
//! VS Code and its forks bundles its own Claude Code for its chat panel and
//! puts no `claude` on the search path (<https://code.claude.com/docs/en/vs-code>).
//! Such a copy reads the same hook file, so whether a hook entry may use a
//! key that only newer versions know (`onFailure`), and which published
//! advisories apply, depends on its version too.

/// One editor's extension folder and the extension in it that bundles the
/// host's program ([`crate::HostSpec::bundled`]).
#[derive(Debug)]
#[non_exhaustive]
pub struct Bundle {
    /// The editor, as `openmoat status` and `openmoat doctor` name it.
    pub editor: &'static str,
    /// The editor's extensions folder, from the home folder, one name per
    /// part (`[".vscode", "extensions"]`). Its `extensions.json` lists the
    /// installed extensions with their versions.
    pub extensions_dir: &'static [&'static str],
    /// The extension's identifier, as `extensions.json` names it
    /// (`anthropic.claude-code`). The extension's version is the version of
    /// the program it bundles.
    pub extension_id: &'static str,
}

impl Bundle {
    /// The extension `extension_id` in `editor`'s extensions folder
    /// `extensions_dir`.
    #[must_use]
    pub const fn new(
        editor: &'static str,
        extensions_dir: &'static [&'static str],
        extension_id: &'static str,
    ) -> Self {
        Self {
            editor,
            extensions_dir,
            extension_id,
        }
    }
}
