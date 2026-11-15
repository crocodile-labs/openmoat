//! GitHub Copilot CLI's plugin (ADR-099): `plugin.json` at the plugin's root
//! naming its hooks file (`"hooks": "hooks.json"`, a legacy-layout plugin),
//! whose shape is `~/.copilot/hooks/*.json`'s: `version: 1` and a `hooks` map
//! of `preToolUse` and other entries with `bash`, `powershell` and
//! `timeoutSec` (the plugin and hooks references). Copilot CLI 1.0.111
//! expands `${COPILOT_PLUGIN_ROOT}` in a plugin hook's working directory
//! (`cwd`), so each entry runs there and names the guard script by a relative
//! path. `copilot plugin install OWNER/REPO:PATH` installs a repository's
//! subdirectory, so no marketplace is needed.

use serde_json::json;

use crate::Host;
use crate::contract::{Meta, Paths, PluginFile, PluginSpec, StandAside};
use crate::wire::plugin_package::{hook_plugin, json_file};

/// The guard script, and how the hook file names it from the plugin's root.
const SCRIPT: &str = "openmoat-guard";
const COMMAND: &str = "./openmoat-guard";

pub(super) static SPEC: PluginSpec = PluginSpec {
    channel: "GitHub Copilot CLI plugins",
    install: "copilot plugin install crocodile-labs/openmoat:plugins/copilot-cli",
    publish: &[
        "Nothing to publish for the install command: it reads `plugins/copilot-cli` of this \
         repository's default branch. Test it with `copilot plugin install ./plugins/copilot-cli` \
         with `COPILOT_HOME` set to a throwaway directory (Copilot CLI 1.0.111 or later).",
        "To be listed, open a pull request adding it to the `github/awesome-copilot` \
         marketplace, or give `crocodile-labs/openmoat-plugins` a `.github/plugin/marketplace.json` \
         (Copilot CLI also reads `.claude-plugin/marketplace.json`, which lists the Claude Code \
         plugin, so the Copilot marketplace must be its own file in `.github/plugin/`).",
    ],
    sources: &[
        "https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-plugin-reference",
        "https://docs.github.com/en/copilot/reference/hooks-configuration",
        "https://github.com/github/copilot-cli/blob/main/changelog.md",
    ],
    // Every hook of every source runs and any `deny` blocks; no output is no
    // decision.
    stand_aside: StandAside::NoDecision,
    // `~/.copilot/installed-plugins/MARKETPLACE/PLUGIN-NAME` from a
    // marketplace, `~/.copilot/installed-plugins/_direct/SOURCE-ID/` from a
    // repository (the plugin reference); the source id's form is not
    // documented, so one naming `openmoat` is covered.
    installed: Paths::new(
        "GitHub Copilot CLI: OpenMoat's plugin, from a marketplace or straight from\n\
         its repository",
        &[
            "~/.copilot/installed-plugins/*/openmoat",
            "~/.copilot/installed-plugins/*/openmoat/**",
            "~/.copilot/installed-plugins/_direct/*openmoat*",
            "~/.copilot/installed-plugins/_direct/*openmoat*/**",
        ],
    ),
    marketplace: None,
    files,
};

fn files(host: Host, meta: &Meta) -> Vec<PluginFile> {
    let manifest = json!({
        "name": meta.name,
        "description": meta.description,
        "version": meta.version,
        "author": { "name": meta.author },
        "license": meta.license,
        "repository": meta.repository,
        "keywords": ["security", "hooks", "policy"],
        "hooks": "hooks.json",
    });
    let mut files = vec![PluginFile::data("plugin.json", json_file(&manifest))];
    files.extend(hook_plugin(
        host,
        "hooks.json",
        SCRIPT,
        COMMAND,
        &[("cwd", "${COPILOT_PLUGIN_ROOT}")],
    ));
    files
}
